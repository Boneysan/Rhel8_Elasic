#!/bin/bash

set -e

echo "💣 Starting full uninstallation of Elastic Stack (Elasticsearch, Kibana, and Filebeat)..."

#---------------------------------
# Uninstall Kibana
#---------------------------------
echo "🔻 Stopping and disabling Kibana service..."
sudo systemctl stop kibana || true
sudo systemctl disable kibana || true

echo "📦 Removing Kibana RPM package..."
sudo rpm -e kibana || echo "⚠️ Kibana not installed or already removed."

echo "🧹 Removing Kibana directories and files..."
sudo rm -rf /etc/kibana
sudo rm -rf /var/lib/kibana
sudo rm -rf /var/log/kibana
sudo rm -rf /var/run/kibana
sudo rm -f /etc/systemd/system/kibana.service

echo "👤 Removing kibana user and group..."
sudo userdel kibana || true
sudo groupdel kibana || true

#---------------------------------
# Uninstall Filebeat
#---------------------------------
echo "🔻 Stopping and disabling Filebeat service..."
sudo systemctl stop filebeat || true
sudo systemctl disable filebeat || true

echo "📦 Removing Filebeat RPM package..."
sudo rpm -e filebeat || echo "⚠️ Filebeat not installed or already removed."

echo "🧹 Removing Filebeat directories and files..."
sudo rm -rf /etc/filebeat
sudo rm -rf /var/lib/filebeat
sudo rm -rf /var/log/filebeat
sudo rm -f /etc/systemd/system/filebeat.service.d/override.conf

#---------------------------------
# Uninstall Elasticsearch
#---------------------------------
echo "🔻 Stopping and disabling Elasticsearch service..."
sudo systemctl stop elasticsearch || true
sudo systemctl disable elasticsearch || true

echo "📦 Removing Elasticsearch RPM package..."
sudo rpm -e elasticsearch || echo "⚠️ Elasticsearch not installed or already removed."

echo "🧹 Removing Elasticsearch directories and files..."
sudo rm -rf /etc/elasticsearch
sudo rm -rf /var/lib/elasticsearch
sudo rm -rf /var/log/elasticsearch
sudo rm -f /etc/systemd/system/elasticsearch.service

echo "👤 Removing elasticsearch user and group..."
sudo userdel elasticsearch || true
sudo groupdel elasticsearch || true

#---------------------------------
# Revert System Settings
#---------------------------------
echo "🔥 Reverting firewall ports..."
sudo firewall-cmd --permanent --remove-port=9200/tcp || true
sudo firewall-cmd --permanent --remove-port=9300/tcp || true
sudo firewall-cmd --permanent --remove-port=5601/tcp || true
sudo firewall-cmd --reload || true

echo "📉 Reverting sysctl vm.max_map_count..."
if grep -q "vm.max_map_count" /etc/sysctl.conf; then
    sudo sed -i '/vm.max_map_count/d' /etc/sysctl.conf
    sudo sysctl -p
fi

echo "🔐 Reverting SELinux port contexts..."
sudo semanage port -d -t http_port_t -p tcp 9200 || true

echo "🔄 Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "✅ Full system uninstallation completed."
