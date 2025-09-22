#!/usr/bin/env bash
set -euo pipefail

# DigitalOcean Droplet Deployment Script
# - Installs Docker Engine and Docker Compose plugin
# - Optionally clones your repo
# - Builds and runs the stack via docker compose

SCRIPT_NAME="$(basename "$0")"

COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[0;31m"
COLOR_RESET="\033[0m"

log() { echo -e "${COLOR_GREEN}[deploy]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[deploy] WARN:${COLOR_RESET} $*"; }
err() { echo -e "${COLOR_RED}[deploy] ERROR:${COLOR_RESET} $*" >&2; }

require_cmd() { command -v "$1" >/dev/null 2>&1; }

# Defaults (can be overridden via env or flags)
GIT_REPO_URL="${GIT_REPO_URL:-}"
GIT_BRANCH="${GIT_BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/rawrz-security-platform}"
PUBLISH_PORTS=(80 443 3000 3001 3002 6379 5432)

usage() {
  cat <<EOF
Usage: sudo ./${SCRIPT_NAME} [--repo <git_url>] [--branch <branch>] [--dir <path>]

Options:
  --repo <url>      Optional: Git repository URL to clone
  --branch <name>   Optional: Branch to checkout (default: ${GIT_BRANCH})
  --dir <path>      Optional: Target directory (default: ${APP_DIR})

Environment variables:
  GIT_REPO_URL, GIT_BRANCH, APP_DIR can be used instead of flags.

This script is intended to run on a fresh Ubuntu 22.04+ Droplet.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo)
        GIT_REPO_URL="$2"; shift 2 ;;
      --branch)
        GIT_BRANCH="$2"; shift 2 ;;
      --dir)
        APP_DIR="$2"; shift 2 ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        err "Unknown argument: $1"; usage; exit 1 ;;
    esac
  done
}

ensure_root() {
  if [[ $(id -u) -ne 0 ]]; then
    err "Please run as root (e.g., sudo bash ${SCRIPT_NAME})."
    exit 1
  fi
}

detect_ubuntu() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "Non-Ubuntu detected (${ID:-unknown}). Proceeding, but only Ubuntu is tested."
    fi
  fi
}

install_docker() {
  if require_cmd docker && docker --version >/dev/null 2>&1; then
    log "Docker already installed."
    return
  fi

  log "Installing Docker Engine and Compose plugin..."
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list >/dev/null

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git

  systemctl enable docker
  systemctl start docker

  log "Docker installation complete: $(docker --version)"
  log "Docker Compose plugin: $(docker compose version)"
}

configure_ufw() {
  if ! require_cmd ufw; then
    warn "ufw not found; skipping firewall configuration."
    return
  fi

  if ufw status | grep -q inactive; then
    warn "ufw is installed but inactive. Skipping changes."
    return
  fi

  log "Configuring ufw rules..."
  ufw allow OpenSSH || true
  for p in "${PUBLISH_PORTS[@]}"; do
    ufw allow "$p" || true
  done
}

clone_or_prepare_repo() {
  if [[ -n "${GIT_REPO_URL}" ]]; then
    log "Cloning repository ${GIT_REPO_URL} (branch: ${GIT_BRANCH}) to ${APP_DIR}..."
    if [[ -d "${APP_DIR}" ]]; then
      warn "Target directory ${APP_DIR} exists. Updating..."
      if [[ -d "${APP_DIR}/.git" ]]; then
        git -C "${APP_DIR}" fetch --all --prune
        git -C "${APP_DIR}" checkout "${GIT_BRANCH}"
        git -C "${APP_DIR}" reset --hard "origin/${GIT_BRANCH}"
      else
        warn "${APP_DIR} is not a git repo. Removing and recloning."
        rm -rf "${APP_DIR}"
        git clone --branch "${GIT_BRANCH}" "${GIT_REPO_URL}" "${APP_DIR}"
      fi
    else
      git clone --branch "${GIT_BRANCH}" "${GIT_REPO_URL}" "${APP_DIR}"
    fi
  else
    # No repo URL provided; assume script is run from project root with compose files present.
    APP_DIR="$(pwd)"
    log "No --repo provided. Using current directory: ${APP_DIR}"
  fi
}

ensure_compose_files() {
  if [[ ! -f "${APP_DIR}/docker-compose.yml" ]]; then
    err "docker-compose.yml not found in ${APP_DIR}. Aborting."
    exit 1
  fi
}

prepare_bind_dirs() {
  # Create common bind-mount directories from docker-compose.yml
  local dirs=(uploads downloads temp logs data keys stubs payloads bots cve engines backups public)
  for d in "${dirs[@]}"; do
    mkdir -p "${APP_DIR}/${d}"
  done
}

bring_up_stack() {
  log "Building containers..."
  (cd "${APP_DIR}" && docker compose build)

  log "Starting stack in detached mode..."
  (cd "${APP_DIR}" && docker compose up -d)

  log "Stack status:"
  (cd "${APP_DIR}" && docker compose ps)
}

main() {
  parse_args "$@"
  ensure_root
  detect_ubuntu
  install_docker
  configure_ufw || true
  clone_or_prepare_repo
  ensure_compose_files
  prepare_bind_dirs
  bring_up_stack

  log "Deployment complete. Services should be reachable on published ports (e.g., 80/443/3000)."
}

main "$@"

