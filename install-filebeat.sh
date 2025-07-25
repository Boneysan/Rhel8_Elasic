#!/bin/bash
#
# install-filebeat.sh
#
# Installs and configures Filebeat to ship logs to a secure Elasticsearch cluster.
# This script expects a Filebeat RPM to be present in the current directory.
#

# --- Instructions for Remote Installation ---
# To run this script on a remote machine that ships logs TO your cluster:
# 1. Update the 'hosts' setting in the local 'filebeat.yml' to point to
#    your Elasticsearch server's IP address.
# 2. Securely copy the 'credentials.txt' file from your Elasticsearch
#    server (located at /etc/elasticsearch/credentials.txt) to this
#    directory. This is needed to get the 'elastic' user password.
# 3. Securely copy the 'elastic-stack-ca.pem' file from your Elasticsearch
#    server (located at /etc/elasticsearch/elastic-stack-ca.pem) to this directory.
# 4. Ensure the 'filebeat-*.rpm' package is in this directory.
# ------------------------------------------

set -e

echo "🚀 Starting Filebeat installation..."

# 1. Find the local Filebeat RPM file.
FILEBEAT_RPM=$(find . -name "filebeat-*.rpm" | head -n 1)
if [[ -z "$FILEBEAT_RPM" ]]; then
  echo "❌ ERROR: Filebeat RPM file (filebeat-*.rpm) not found in the current directory."
  echo "Please download the correct RPM and place it here before running this script."
  exit 1
fi
echo "📦 Found Filebeat RPM: $FILEBEAT_RPM"

# 2. Install Filebeat from the local RPM.
if rpm -q filebeat > /dev/null 2>&1; then
  echo "✅ Filebeat is already installed. Skipping RPM step."
else
  sudo rpm -ivh "$FILEBEAT_RPM"
fi

# 3. Create necessary directories.
echo "📁 Creating Filebeat directories..."
sudo mkdir -p /etc/filebeat/certs
sudo mkdir -p /var/log/filebeat
sudo mkdir -p /var/lib/filebeat/data

# 4. Copy the main configuration file.
echo "📄 Copying filebeat.yml configuration..."
sudo cp filebeat.yml /etc/filebeat/

# 5. Copy the shared CA certificate from the Elasticsearch installation.
echo "🔐 Setting up SSL certificate for secure connection..."
if [[ -f ./elastic-stack-ca.pem ]]; then
    sudo cp ./elastic-stack-ca.pem /etc/filebeat/certs/elastic-stack-ca.pem
    echo "✅ CA certificate copied to /etc/filebeat/certs/"
elif [[ -f /etc/elasticsearch/elastic-stack-ca.pem ]]; then
    # This path is for local installation on the same machine as Elasticsearch
    sudo cp /etc/elasticsearch/elastic-stack-ca.pem /etc/filebeat/certs/elastic-stack-ca.pem
    echo "✅ CA certificate copied to /etc/filebeat/certs/"
else
  echo "❌ ERROR: CA certificate (elastic-stack-ca.pem) not found."
  echo "For a remote install, please copy it from your Elasticsearch server to this directory."
  exit 1
fi

# 6. Securely provide the elastic password to the Filebeat service.
echo "🔑 Setting up password environment for Filebeat service..."
CRED_FILE="./credentials.txt"
if [[ ! -f "$CRED_FILE" ]]; then
    # Fallback for local install
    if [[ -f /etc/elasticsearch/credentials.txt ]]; then
        CRED_FILE="/etc/elasticsearch/credentials.txt"
    else
        echo "❌ Credentials file (credentials.txt) not found! Cannot continue."
        echo "For a remote install, please copy it from your Elasticsearch server to this directory."
        exit 1
    fi
fi

ELASTIC_PASSWORD=$(sudo grep "elastic:" "$CRED_FILE" | cut -d':' -f2- | sed 's/^ *//;s/ *$//')

if [[ -z "$ELASTIC_PASSWORD" ]]; then
  echo "❌ ERROR: Could not retrieve elastic password from credentials file."
  exit 1
fi

# Create an environment file that systemd can use to pass the password securely.
echo "ELASTIC_PASSWORD=$ELASTIC_PASSWORD" | sudo tee /etc/filebeat/filebeat.env > /dev/null
sudo chmod 640 /etc/filebeat/filebeat.env
sudo chown root:root /etc/filebeat/filebeat.env
echo "✅ Created secure environment file at /etc/filebeat/filebeat.env"

# 7. Create a systemd override file to load the new environment file.
echo "⚙️ Configuring systemd service to use the environment file..."
sudo mkdir -p /etc/systemd/system/filebeat.service.d
cat <<EOF | sudo tee /etc/systemd/system/filebeat.service.d/override.conf
[Service]
EnvironmentFile=/etc/filebeat/filebeat.env
EOF
echo "✅ Created systemd override file."

# 8. Set final ownership and permissions.
echo "🔧 Setting final file permissions..."
sudo chown -R root:root /etc/filebeat

# 9. NEW: Verify network connectivity to Elasticsearch before starting the service.
echo "🌐 Verifying network connectivity to Elasticsearch..."
# Parse the host and port from the filebeat.yml configuration
# This extracts the part between "https://" and the closing quote/bracket.
ES_FULL_HOST=$(grep 'hosts:' filebeat.yml | sed -e 's,.*https://,,' -e 's/["].*//')
ES_HOST=$(echo "$ES_FULL_HOST" | cut -d':' -f1)
ES_PORT=$(echo "$ES_FULL_HOST" | cut -d':' -f2)

if [[ -z "$ES_HOST" || -z "$ES_PORT" ]]; then
    echo "❌ ERROR: Could not parse Elasticsearch host and port from filebeat.yml."
    exit 1
fi

echo "   Attempting to connect to $ES_HOST on port $ES_PORT..."
# Use nc (netcat) to check if the port is open. Timeout after 10 seconds.
if nc -zv -w 10 "$ES_HOST" "$ES_PORT" >/dev/null 2>&1; then
    echo "✅ Successfully connected to Elasticsearch on port $ES_PORT."
else
    echo "❌ ERROR: Could not connect to Elasticsearch at $ES_HOST:$ES_PORT."
    echo "   Please check the following:"
    echo "   1. The 'hosts' setting in filebeat.yml is correct."
    echo "   2. The Elasticsearch service is running on the target server."
    echo "   3. There are no firewalls blocking port $ES_PORT between this machine and the server."
    exit 1
fi

# 10. Enable and start the Filebeat service.
echo "🔁 Enabling and starting Filebeat service..."
sudo systemctl daemon-reload
sudo systemctl enable filebeat.service
sudo systemctl start filebeat.service

echo "📊 Verifying Filebeat status..."
sleep 5
sudo systemctl is-active --quiet filebeat.service && echo "✅ Filebeat is running." || (echo "⚠️ Filebeat service check failed. Check logs with 'journalctl -u filebeat'" && exit 1)

echo "🎉 Filebeat installation completed successfully!"
