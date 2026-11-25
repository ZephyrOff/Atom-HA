#!/usr/bin/with-contenv bashio
# shellcheck shell=bash

export ATOM_DATA_DIR=/data
export ATOM_DNS_LISTEN=0.0.0.0:53
export ATOM_HTTP_LISTEN=0.0.0.0:3000
# Le proxy ingress de Home Assistant est déjà authentifié par Home Assistant.
export ATOM_TRUSTED_IP=172.30.32.2

export ATOM_PASSWORD="$(bashio::config 'password')"
export ATOM_NODE_NAME="$(bashio::config 'node_name')"
export ATOM_ADVERTISE_URL="$(bashio::config 'advertise_url')"
export ATOM_ALLOWED_ORIGINS="$(bashio::config 'allowed_origins')"
export ATOM_LOG_RETENTION="$(bashio::config 'log_retention')"
export RUST_LOG="atom=info"

bashio::log.info "Démarrage d'Atom..."
exec /usr/local/bin/atom
