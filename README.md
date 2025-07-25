Elastic Stack Configuration Package
Version: 1.0.0
Generated on: 2025-07-24

Overview
This package contains all necessary configuration files and automation scripts for setting up a complete, single-node Elastic Stack (Elasticsearch, Kibana, and Filebeat) version 8.11.0 on a RHEL 8 server.

The installation is fully automated, secure by default (with SSL/TLS encryption), and configured with best practices for logging and data management.

Files Included
Automation Scripts:

master-install.sh: The main script that orchestrates the entire installation of Elasticsearch and Kibana on the central server.

system-setup.sh: Prepares the RHEL 8 system with necessary dependencies and settings.

install.sh: Installs and configures Elasticsearch. It also creates a deployment package for remote Filebeat agents.

install-kibana.sh: Installs and configures Kibana.

install-filebeat.sh: Installs and configures Filebeat (can be used on the central server or remote systems).

full-uninstall.sh: A single script to completely remove all components.

Configuration Files:

elasticsearch.yml, kibana.yml, filebeat.yml

jvm.options, log4j2.properties

index-template.json, ilm-policy.json

Service Files:

elasticsearch.service, kibana.service

Java Prerequisites
For Elasticsearch 8.x, a separate installation of Java is not required. The Elasticsearch RPM package includes its own bundled Java Development Kit (JDK) and is configured to use it automatically.

The system-setup.sh script includes a diagnostic check to verify if Java 8 is present on the system. This is for informational purposes and does not block the installation. The cluster will run correctly using its bundled JDK regardless of whether system-wide Java is installed.

Air-Gapped Environment Preparation
For offline or "air-gapped" installations, you must first download the required RPM packages on a machine with internet access.

Run the following commands to download the necessary files:

# Download Elasticsearch 8.11.0
wget [https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-x86_64.rpm](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-x86_64.rpm)

# Download Kibana 8.11.0
wget [https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-x86_64.rpm](https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-x86_64.rpm)

# Download Filebeat 8.11.0
wget [https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-x86_64.rpm](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-x86_64.rpm)

After downloading, transfer these RPM files along with all the scripts and configuration files in this package to the target server. The installation scripts are designed to automatically use these local RPMs if they are present in the same directory.

Installation Instructions
A. Installing the Central Elasticsearch & Kibana Server
The entire installation on your main server is handled by the master-install.sh script.

Prepare Files:
Place all scripts, configuration files, and the elasticsearch-*.rpm and kibana-*.rpm packages into a single directory on the target server.

Make Scripts Executable:

chmod +x *.sh

Run the Master Installation Script:

sudo ./master-install.sh

The script will handle all dependencies, configurations, and service startups. Upon completion, Kibana will be available at http://<your-server-ip>:5601.

B. Installing Filebeat on Remote Systems
After the master-install.sh script completes, it will create a new folder named remote_filebeat_package. This folder contains everything you need to install Filebeat on a remote machine.

1. Copy the Package to the Remote Machine:

Securely copy the entire remote_filebeat_package folder from your main Elasticsearch server to the remote machine where you want to install Filebeat. You can use scp for this.

2. Configure filebeat.yml for Remote Connection:

Before running the install script, you must edit the filebeat.yml file inside the remote_filebeat_package folder on the remote machine. Change the hosts setting from localhost to the IP address of your Elasticsearch server.

Change this line:
hosts: ["https://localhost:9200"]

To this (example):
hosts: ["https://192.168.1.100:9200"]

3. Run the Filebeat Installation Script:

Once the package is copied and the configuration is updated, run the installation script from inside the remote_filebeat_package folder on the remote machine.

Navigate into the directory:

cd remote_filebeat_package

Make the script executable:

chmod +x install-filebeat.sh

Run the installer:

sudo ./install-filebeat.sh

The script will install Filebeat, configure it with the correct credentials and certificate, and start the service to begin shipping logs.