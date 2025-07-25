#!/bin/bash

set -e

echo "🔧 [1/7] Running system-setup.sh..."
sudo ./system-setup.sh

echo "📦 [2/7] Running install.sh for Elasticsearch..."
echo "📄 This step includes JVM option sanitation and SSL certificate handling."
sudo ./install.sh

echo "🧪 [3/7] Validating Elasticsearch service..."
sudo systemctl is-active --quiet elasticsearch && echo "✅ Elasticsearch is running." || (echo "❌ Elasticsearch failed to start." && exit 1)

echo "⚙️ [4/7] Applying cluster configurations (ILM, Template)..."

# Retrieve the elastic password securely from the file created by install.sh
echo "🔐 Retrieving elastic password for setup..."
ELASTIC_PASSWORD=$(sudo grep "elastic:" /etc/elasticsearch/credentials.txt | cut -d':' -f2)
if [[ -z "$ELASTIC_PASSWORD" ]]; then
  echo "❌ Could not retrieve elastic password. Aborting configuration."
  exit 1
fi

# Wait for the Elasticsearch API to be responsive before continuing
echo "⏳ Waiting for Elasticsearch to be ready..."
until curl -s -k -u "elastic:$ELASTIC_PASSWORD" "https://localhost:9200/" > /dev/null; do
    sleep 5
    echo "Retrying connection to Elasticsearch..."
done
echo "✅ Elasticsearch API is ready."

# Upload ILM Policy
echo "📄 Uploading ILM policy..."
curl -X PUT "https://localhost:9200/_ilm/policy/filebeat-policy" \
-u "elastic:$ELASTIC_PASSWORD" -k -H 'Content-Type: application/json' -d @ilm-policy.json

# Upload Index Template
echo "📄 Uploading Index Template..."
curl -X PUT "https://localhost:9200/_index_template/filebeat" \
-u "elastic:$ELASTIC_PASSWORD" -k -H 'Content-Type: application/json' -d @index-template.json

# Create the first index and rollover alias
echo "📄 Creating initial index and rollover alias..."
curl -X PUT "https://localhost:9200/%3Cfilebeat-%7Bnow%2Fd%7D-000001%3E" \
-u "elastic:$ELASTIC_PASSWORD" -k -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "filebeat": {
      "is_write_index": true
    }
  }
}
'
echo "✅ Cluster configurations applied."

echo "🚀 [5/7] Running install-kibana.sh for Kibana..."
sudo ./install-kibana.sh

echo "📊 [6/7] Validating Kibana service..."
sudo systemctl is-active --quiet kibana && echo "✅ Kibana is running." || echo "⚠️ Kibana service check failed. It may still be starting."

echo "🎉 [7/7] Master installation script completed."
echo "➡️  Access Kibana at: http://<your-server-ip>:5601"
