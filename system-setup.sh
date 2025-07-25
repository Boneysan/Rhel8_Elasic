#!/bin/bash
# Elasticsearch System Setup Script for RHEL 8
# Generated on: 2025-07-20T15:11:31.759Z

set -e

echo "Starting system setup for RHEL 8..."

# Create elasticsearch user and group (ignore if already exists)
sudo useradd -r -s /bin/false elasticsearch || echo "User elasticsearch already exists"

# Create required directories
echo "Creating directories..."
sudo mkdir -p /var/lib/elasticsearch
sudo mkdir -p /var/log/elasticsearch
sudo mkdir -p /etc/elasticsearch
sudo mkdir -p /var/run/elasticsearch

# Set ownership for all directories
echo "Setting directory ownership..."
sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
sudo chown -R elasticsearch:elasticsearch /var/log/elasticsearch
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch
sudo chown -R elasticsearch:elasticsearch /var/run/elasticsearch


# Configure firewall for RHEL 8
echo "Configuring firewall ports..."
sudo firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || echo "Port 9200/tcp already configured"
sudo firewall-cmd --permanent --add-port=9300/tcp 2>/dev/null || echo "Port 9300/tcp already configured"
sudo firewall-cmd --reload
echo "Firewall configured successfully"


# Set system limits for Elasticsearch
echo "Configuring system limits..."
echo "elasticsearch soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "elasticsearch hard nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "elasticsearch soft memlock unlimited" | sudo tee -a /etc/security/limits.conf
echo "elasticsearch hard memlock unlimited" | sudo tee -a /etc/security/limits.conf

# Configure virtual memory for Elasticsearch
echo "Configuring virtual memory settings..."
if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    echo "Added vm.max_map_count to /etc/sysctl.conf"
else
    echo "vm.max_map_count already configured in /etc/sysctl.conf"
fi
sudo sysctl -p


# Configure SELinux for RHEL 8
echo "Configuring SELinux policies..."
# Check if SELinux is enforcing
if getenforce | grep -q "Enforcing"; then
    echo "SELinux is enforcing, configuring policies..."
    sudo setsebool -P httpd_can_network_connect 1
    
    # Add port to SELinux policy (ignore if already exists)
    sudo semanage port -a -t http_port_t -p tcp 9200 2>/dev/null || echo "Port 9200 already configured in SELinux"
    
    # Allow Elasticsearch to bind to network ports
    sudo setsebool -P nis_enabled 1
    echo "SELinux configured for Elasticsearch"
else
    echo "SELinux is not enforcing, skipping SELinux configuration"
fi


# Verify Java 8 installation (required for Elasticsearch compatibility)
echo "Checking Java installation..."
if command -v java >/dev/null 2>&1; then
    JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2)
    echo "Java version found: $JAVA_VERSION"
    if [[ "$JAVA_VERSION" =~ ^1.8. ]]; then
        echo "Java 8 detected - compatible with Elasticsearch"
    else
        echo "WARNING: Java 8 is recommended for Elasticsearch compatibility"
    fi
else
    echo "WARNING: Java not found. Please install Java 8 before starting Elasticsearch"
fi

echo "System setup completed successfully!"
echo "Next steps:"
echo "1. Install Elasticsearch RPM package"
echo "2. Copy configuration files"
echo "3. Start Elasticsearch service"