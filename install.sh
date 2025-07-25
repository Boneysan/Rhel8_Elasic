#!/bin/bash
#
# install.sh
# This script automates the full installation and initial configuration of a secure,
# single-node Elasticsearch cluster on a RHEL 8 system.
#

# Exit immediately if any command fails, ensuring the script doesn't continue in a broken state.
set -e

echo "🚀 Starting Elasticsearch installation..."

# --- 1. Install Elasticsearch Package ---
# First, check if Elasticsearch is already installed using the rpm package manager.
# This makes the script 'idempotent', meaning it can be run multiple times without causing errors.
if rpm -q elasticsearch > /dev/null 2>&1; then
  echo "✅ Elasticsearch is already installed. Skipping RPM installation."
else
  # If not installed, check for a local RPM file first. This is useful for offline installations.
  ES_RPM=$(find . -name "elasticsearch-*.rpm" | head -n 1)

  if [[ -f "$ES_RPM" ]]; then
    echo "📦 Found local Elasticsearch RPM: $ES_RPM. Installing from local file..."
    sudo rpm -ivh "$ES_RPM"
  else
    # If no local RPM is found, download the official package from the web.
    echo "📥 No local RPM found. Downloading Elasticsearch from the web..."
    curl -O https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-x86_64.rpm
    sudo rpm -ivh elasticsearch-8.11.0-x86_64.rpm
  fi
fi


# --- 2. System Prerequisites ---
# Run the system-setup.sh script if it exists. This script handles all OS-level
# prerequisites like creating users, setting kernel parameters, and configuring the firewall.
if [[ -f ./system-setup.sh ]]; then
  echo "🔧 Running system setup..."
  sudo ./system-setup.sh
fi

# --- 3. Deploy Configuration Files ---
echo "📁 Copying Elasticsearch configs..."
# Copy the main configuration file, the Java Virtual Machine (JVM) options, and the logging configuration
# from the local directory to the system configuration path for Elasticsearch.
sudo cp elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
sudo cp jvm.options /etc/elasticsearch/jvm.options
sudo cp log4j2.properties /etc/elasticsearch/log4j2.properties

# --- 4. Initialize Keystore ---
# The Elasticsearch keystore is used to securely store sensitive settings like passwords.
# We remove any old keystore to ensure a clean start and then create a new, empty one.
echo "🔐 Resetting keystore..."
sudo rm -f /etc/elasticsearch/elasticsearch.keystore
sudo /usr/share/elasticsearch/bin/elasticsearch-keystore create

# --- 5. Set File Permissions ---
# For security, Elasticsearch runs as a dedicated, unprivileged user ('elasticsearch').
# This command ensures that this user owns all of its configuration files.
echo "🔒 Setting file ownerships..."
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch

# --- 6. Generate SSL/TLS Certificates ---
# This section creates the certificates needed to encrypt all network communication.
SSL_DIR="/etc/elasticsearch/certs"
CA_ZIP_PATH="/tmp/elastic-stack-ca.zip"
CA_DIR="/tmp/elastic-stack-ca"
CERT_ZIP_PATH="/tmp/elastic-node-cert.zip"
CERT_DIR="/tmp/elastic-node-cert"
CERT_CONFIG="/tmp/cert-config.yml"
# Automatically detect the server's primary IP address.
IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo "🔑 Generating fresh CA and self-signed PEM certificates with SAN for $IP_ADDRESS..."

# Clean up any old certificates or temporary files from previous runs.
sudo rm -rf "$SSL_DIR" "$CA_ZIP_PATH" "$CA_DIR" "$CERT_ZIP_PATH" "$CERT_DIR"
sudo mkdir -p "$SSL_DIR"

# 6a. Generate the Certificate Authority (CA)
# The CA is the root of trust. It will be used to sign the node certificate.
echo "📄 Generating new Certificate Authority..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent --pem --out "$CA_ZIP_PATH"
sudo unzip -o "$CA_ZIP_PATH" -d "$CA_DIR"

# 6b. Create a configuration file for the node certificate
# This config specifies the details for the certificate, including a Subject Alternative Name (SAN).
# The SAN is critical because it allows clients to connect securely using the server's IP address.
cat <<EOF | sudo tee "$CERT_CONFIG" > /dev/null
instances:
  - name: instance
    dns:
      - localhost
    ip:
      - 127.0.0.1
      - $IP_ADDRESS
EOF

# 6c. Generate the node certificate, signed by our new CA
echo "📄 Generating new node certificate signed by the CA..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert \
  --silent \
  --pem \
  --in "$CERT_CONFIG" \
  --out "$CERT_ZIP_PATH" \
  --ca-cert "$CA_DIR/ca/ca.crt" \
  --ca-key "$CA_DIR/ca/ca.key"

# 6d. Unzip and install the node certificate
sudo unzip -o "$CERT_ZIP_PATH" -d "$CERT_DIR"
sudo cp "$CERT_DIR"/instance/instance.crt "$SSL_DIR"/elasticsearch.crt
sudo cp "$CERT_DIR"/instance/instance.key "$SSL_DIR"/elasticsearch.key

# 6e. Copy the CA certificate for client trust
# Other services like Kibana and Filebeat will need this CA certificate to verify
# the identity of the Elasticsearch server and establish a trusted connection.
CA_DST=/etc/elasticsearch/elastic-stack-ca.pem
sudo cp "$CA_DIR/ca/ca.crt" "$CA_DST"
sudo chmod 644 "$CA_DST"
echo "📄 Copied CA cert for client trust to $CA_DST"

# 6f. Set final, secure permissions on the certificates and keys.
sudo chown -R elasticsearch:elasticsearch "$SSL_DIR"
sudo chmod 600 "$SSL_DIR"/*

# 6g. Clean up all temporary files used during certificate generation.
sudo rm -rf "$CA_ZIP_PATH" "$CA_DIR" "$CERT_ZIP_PATH" "$CERT_DIR" "$CERT_CONFIG"

echo "✅ SSL certs (CA and Node Cert with SAN) generated and installed."

# --- 7. Start the Elasticsearch Service ---
echo "🔁 Enabling and starting Elasticsearch..."
# Use systemd to manage the service. These commands ensure the service is
# enabled to start on boot and is started immediately.
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service

# --- 8. Apply SELinux Context ---
# On RHEL systems with SELinux enabled, it's critical to apply the correct
# security context to the configuration files to prevent permission errors.
echo "🔐 Restoring SELinux contexts..."
sudo restorecon -Rv /etc/elasticsearch

echo "✅ Elasticsearch installation complete."

# --- 9. Set Initial Passwords ---
# Wait for the Elasticsearch API to become responsive before trying to set passwords.
# The service can take a minute to fully initialize.
echo "⏳ Waiting for Elasticsearch API to be ready..."
until curl -s -k "https://localhost:9200" -o /dev/null; do
    sleep 5
    echo "Retrying... waiting for Elasticsearch API to respond."
done
echo "✅ Elasticsearch API is ready."

# Since security is enabled by default, we must reset the passwords for the built-in
# 'elastic' (superuser) and 'kibana_system' (for Kibana to connect) users.
echo "🔐 Resetting and capturing passwords for 'elastic' and 'kibana_system' users..."
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b > /tmp/elastic_password.tmp
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b > /tmp/kibana_password.tmp

ELASTIC_PASSWORD=$(cat /tmp/elastic_password.tmp)
KIBANA_PASSWORD=$(cat /tmp/kibana_password.tmp)

# Store the new passwords in a secure file for other scripts (like the Kibana installer) to use.
if [[ -n "$ELASTIC_PASSWORD" && -n "$KIBANA_PASSWORD" ]]; then
  # Create a single credentials file
  echo "elastic:$ELASTIC_PASSWORD" | sudo tee /etc/elasticsearch/credentials.txt > /dev/null
  echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /etc/elasticsearch/credentials.txt > /dev/null
  
  sudo chown root:elasticsearch /etc/elasticsearch/credentials.txt
  sudo chmod 640 /etc/elasticsearch/credentials.txt
  
  # Clean up temp files
  rm /tmp/elastic_password.tmp /tmp/kibana_password.tmp

  echo "✅ Stored passwords for elastic and kibana_system at /etc/elasticsearch/credentials.txt"
else
  echo "❌ Failed to retrieve passwords. Check logs manually."
  # Clean up temp files
  rm -f /tmp/elastic_password.tmp /tmp/kibana_password.tmp
  exit 1
fi

# --- 10. NEW: Create a package for remote Filebeat installations ---
echo "📦 Creating package for remote Filebeat agents..."
REMOTE_PACKAGE_DIR="remote_filebeat_package"
mkdir -p "$REMOTE_PACKAGE_DIR"

# Copy the necessary scripts and configs
cp install-filebeat.sh "$REMOTE_PACKAGE_DIR/"
cp filebeat.yml "$REMOTE_PACKAGE_DIR/"

# Copy the security files from the system
sudo cp /etc/elasticsearch/credentials.txt "$REMOTE_PACKAGE_DIR/"
sudo cp /etc/elasticsearch/elastic-stack-ca.pem "$REMOTE_PACKAGE_DIR/"

# Copy the Filebeat RPM if it exists locally
FILEBEAT_RPM=$(find . -name "filebeat-*.rpm" | head -n 1)
if [[ -f "$FILEBEAT_RPM" ]]; then
    cp "$FILEBEAT_RPM" "$REMOTE_PACKAGE_DIR/"
    echo "  -> Copied $FILEBEAT_RPM"
fi

echo "✅ Remote Filebeat package created at: ./$REMOTE_PACKAGE_DIR"
echo "   You can now copy this entire folder to a remote machine to install Filebeat."
