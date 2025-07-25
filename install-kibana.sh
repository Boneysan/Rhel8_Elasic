#!/bin/bash
# Kibana Installation Script for RHEL 8
# Updated: 2025-07-24

set -e

echo "🚀 Starting Kibana installation..."

# 1. Create kibana user and group
sudo useradd -r -s /bin/false kibana 2>/dev/null || echo "👤 User kibana already exists."

# 2. Install Kibana Package
# First, check if Kibana is already installed.
if rpm -q kibana > /dev/null 2>&1; then
  echo "✅ Kibana is already installed. Skipping RPM installation."
else
  # If not installed, check for a local RPM file first.
  KIBANA_RPM=$(find . -name "kibana-*.rpm" | head -n 1)

  if [[ -f "$KIBANA_RPM" ]]; then
    echo "📦 Found local Kibana RPM: $KIBANA_RPM. Installing from local file..."
    sudo rpm -ivh "$KIBANA_RPM"
  else
    # If no local RPM is found, download it from the web.
    echo "📥 No local RPM found. Downloading Kibana 8.11.0 from the web..."
    wget -q https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-x86_64.rpm
    sudo rpm -i kibana-8.11.0-x86_64.rpm
  fi
fi

# 3. Create directories
echo "📁 Creating Kibana directories..."
sudo mkdir -p /var/lib/kibana /var/log/kibana /var/run/kibana /etc/kibana/certs

# 4. Copy shared CA certificate from Elasticsearch
echo "🔐 Setting up SSL certificates for Kibana..."
if [[ -f /etc/elasticsearch/elastic-stack-ca.pem ]]; then
  sudo cp /etc/elasticsearch/elastic-stack-ca.pem /etc/kibana/certs/elastic-stack-ca.pem
  echo "✅ CA certificate copied."
else
  echo "❌ CA certificate not found at /etc/elasticsearch/elastic-stack-ca.pem"
  exit 1
fi

# 5. Copy configuration file
echo "📄 Copying Kibana config..."
# Overwrite the config file to ensure a clean state
sudo cp -f kibana.yml /etc/kibana/

# 6. Set ownership and permissions BEFORE generating keys
echo "🔧 Setting file permissions..."
sudo chown -R kibana:kibana /var/lib/kibana /var/log/kibana /var/run/kibana /etc/kibana
sudo chmod 660 /etc/kibana/certs/*

# 7. Generate and inject encryption keys
echo "🔑 Generating and injecting Kibana encryption keys..."
KEY_OUTPUT=$(sudo KBN_PATH_CONF=/etc/kibana /usr/share/kibana/bin/kibana-encryption-keys generate)
ENCRYPTION_KEY=$(echo "$KEY_OUTPUT" | grep "xpack.encryptedSavedObjects.encryptionKey" | awk '{print $2}')

# Add validation to ensure a key was generated successfully.
if [[ -z "$ENCRYPTION_KEY" || ${#ENCRYPTION_KEY} -lt 32 ]]; then
    echo "❌ ERROR: Failed to generate a valid encryption key."
    echo "   Dumping full output from key generation tool for debugging:"
    echo "$KEY_OUTPUT"
    exit 1
fi

# Add the key to the kibana.yml file for all required settings
cat <<EOF | sudo tee -a /etc/kibana/kibana.yml > /dev/null

# Added by installation script to enable full functionality
xpack.encryptedSavedObjects.encryptionKey: "$ENCRYPTION_KEY"
xpack.reporting.encryptionKey: "$ENCRYPTION_KEY"
xpack.security.encryptionKey: "$ENCRYPTION_KEY"
EOF
echo "✅ Encryption keys injected into kibana.yml"

# 8. Inject kibana_system password
echo "🔑 Setting Kibana system user password..."
CRED_FILE="/etc/elasticsearch/credentials.txt"
if [[ ! -f "$CRED_FILE" ]]; then
  echo "❌ Credentials file not found at $CRED_FILE! Cannot continue."
  exit 1
fi

KIBANA_PASSWORD=$(sudo grep "kibana_system:" "$CRED_FILE" | cut -d':' -f2 | sed 's/ //g')
if [[ -z "$KIBANA_PASSWORD" ]]; then
  echo "❌ kibana_system password not found in $CRED_FILE"
  exit 1
fi

sudo sed -i "s|changeme|$KIBANA_PASSWORD|" /etc/kibana/kibana.yml
echo "✅ kibana_system password injected into kibana.yml"

# 9. Copy systemd service file and configure firewall
sudo cp kibana.service /etc/systemd/system/
echo "🌐 Configuring firewall for Kibana..."
sudo firewall-cmd --permanent --add-port=5601/tcp || echo "Firewall port 5601 already configured"
sudo firewall-cmd --reload

# 10. Restart the Kibana service to apply all changes
echo "🔁 Restarting Kibana service..."
sudo systemctl daemon-reload
sudo systemctl restart kibana.service

# 11. Wait for Kibana to initialize with a robust timeout loop
TIMEOUT=90  # seconds
INTERVAL=5 # seconds
ELAPSED=0

echo "⏳ Waiting up to $TIMEOUT seconds for Kibana to initialize..."

while true; do
    # Check if Kibana has logged the success message
    if sudo journalctl -u kibana.service --since "5 minutes ago" | grep -q "Kibana is now available"; then
        echo "✅ Kibana has successfully started."
        break
    fi

    # Check if the service has failed
    if ! sudo systemctl is-active --quiet kibana.service; then
        echo "❌ Kibana service has failed to start. Please check the logs:"
        sudo journalctl -u kibana.service -n 50 --no-pager -l
        exit 1
    fi

    # Check for timeout
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "⌛️ Timed out waiting for Kibana to start. Please check the logs:"
        sudo journalctl -u kibana.service -n 50 --no-pager -l
        exit 1
    fi

    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
    echo "   ... still waiting ($ELAPSED/$TIMEOUT seconds)"
done


echo "🎉 Kibana installation and configuration completed successfully!"
echo "➡️  Access Kibana at: http://<your-server-ip>:5601"
