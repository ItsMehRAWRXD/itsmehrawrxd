DigitalOcean Droplet Deployment

This guide deploys the stack on a DigitalOcean Droplet using Docker and docker compose.

Prerequisites
- Ubuntu 22.04+ Droplet with sudo access
- A domain (optional) pointing at the Droplet public IP for nginx/HTTPS

Files
- deploy/digitalocean/deploy.sh: Installs Docker, clones or uses the repo, and runs docker compose

Usage
SSH into your Droplet and run one of the following:

1) Use current directory (if repo is already present on Droplet):
```bash
sudo bash deploy/digitalocean/deploy.sh
```

2) Clone and deploy from a repository:
```bash
sudo bash deploy/digitalocean/deploy.sh --repo https://github.com/your-org/your-repo.git --branch main --dir /opt/your-app
```

What the script does
- Installs Docker Engine and Docker Compose plugin
- Optionally clones the provided repo into the target directory
- Ensures bind-mount directories exist for volumes in docker-compose.yml
- Builds images and starts services in detached mode

Ports
- Exposes the ports as defined in docker-compose.yml (80, 443, 3000, 3001, 3002, etc.)

Updating
To pull latest changes and restart:
```bash
cd /opt/your-app
git pull --rebase
docker compose build
docker compose up -d
```

Logs and status
```bash
docker compose ps
docker compose logs -f rawrz-app
```

Security notes
- Consider placing secrets in an .env file and reference with env_file in docker-compose.yml
- Configure ufw if desired, or a cloud firewall, to restrict access
- For HTTPS, populate nginx/ssl with certificates or use a reverse proxy with automated TLS

