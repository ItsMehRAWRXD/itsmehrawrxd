#!/bin/bash
# One-liner Docker run for 1GB RAM
docker run -d --name rawrz-app --memory=1g --cpus=1 -p 8080:8080 -v $(pwd)/uploads:/app/uploads -v $(pwd)/downloads:/app/downloads -v $(pwd)/generated-stubs:/app/generated-stubs -e NODE_ENV=production -e PORT=8080 -e MAX_FILE_SIZE=500MB -e NODE_OPTIONS="--max-old-space-size=768" rawrz-1gb
