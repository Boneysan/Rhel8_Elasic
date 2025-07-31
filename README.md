Elastic Stack Configuration Package
Version: 1.0.0
Generated on: 2025-07-28

Overview
This package contains all necessary configuration files and automation scripts for setting up a complete, single-node Elastic Stack (Elasticsearch, Kibana, and Filebeat) version 9.0.4 on a RHEL 8 server.

The installation is fully automated, secure by default (with SSL/TLS encryption), and configured with best practices for logging and data management.

Files Included
Automation Scripts:

install.sh: The main, all-in-one script that installs and configures Elasticsearch and Kibana. It also creates a deployment package for remote Filebeat agents.

system-setup.sh: Prepares the RHEL 8 system with necessary dependencies and settings.

full-uninstall.sh: A single script to completely remove all components.

Configuration Files:

elasticsearch.yml, filebeat.yml

jvm.options, log4j2.properties

Service Files:

elasticsearch.service, kibana.service

Java Prerequisites
For Elasticsearch 9.x, a separate installation of Java is not required. The Elasticsearch RPM package includes its own bundled Java Development Kit (JDK) and is configured to use it automatically.

Air-Gapped Environment Preparation
For offline or "air-gapped" installations, you must first download the required RPM packages on a machine with internet access. The install.sh script is configured for version 9.0.4.

Run the following commands to download the necessary files:

# Download Elasticsearch 9.0.4
wget [https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.0.4-x86_64.rpm](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.0.4-x86_64.rpm)

# Download Kibana 9.0.4
wget [https://artifacts.elastic.co/downloads/kibana/kibana-9.0.4-x86_64.rpm](https://artifacts.elastic.co/downloads/kibana/kibana-9.0.4-x86_64.rpm)

# Download Filebeat 9.0.4
wget [https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.0.4-x86_64.rpm](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.0.4-x86_64.rpm)

After downloading, transfer these RPM files along with all the scripts and configuration files in this package to the target server. The installation scripts are designed to automatically use these local RPMs if they are present in the same directory.

Installation Instructions
A. Installing the Central Elasticsearch & Kibana Server
The entire installation on your main server is handled by the install.sh script.

Prepare Files:
Place all scripts, configuration files, and the elasticsearch-*.rpm and kibana-*.rpm packages into a single directory on the target server.

Make Scripts Executable:

chmod +x *.sh

Run the Installation Script:

sudo ./install.sh

The script will handle all dependencies, configurations, and service startups. Upon completion, Kibana will be available at http://<your-server-ip>:5601.

B. Installing Filebeat on Remote Systems
After the install.sh script completes on your central server, it will create a new compressed archive named remote_filebeat_package.tar.gz. This single file contains everything you need to install Filebeat on a remote machine.

1. Copy the Package to the Remote Machine:

Securely copy the remote_filebeat_package.tar.gz file from your main Elasticsearch server to the remote machine where you want to install Filebeat. You can use scp for this.

2. Unpack and Run the Installation Script:

Once the package is copied, log into the remote machine and run the following commands.

Unpack the archive:

tar -xzvf remote_filebeat_package.tar.gz

Navigate into the new directory:
The files will be unpacked into the current directory.

Make the script executable:

chmod +x install-filebeat.sh

Run the installer:

sudo ./install-filebeat.sh

The script will install Filebeat and start the service to begin shipping logs. The filebeat.yml inside the package has already been automatically configured with the correct IP address for your Elasticsearch server.