#!/bin/bash

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo " ==> Build plugin"
GOOS=$OS GOARCH="amd64" go build -ldflags="-s -w" \
  -o vault/plugins/haproxy-secrets-plugin cmd/haproxy-secrets-plugin/main.go || exit 1

echo "==> Start Vault"
vault server -log-level=debug -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins & sleep 2
VAULT_PID=$!

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_DEV_ROOT_TOKEN_ID='root'

function cleanup {
  echo ""
  echo " ==> Cleaning up"
  kill -INT "$VAULT_PID"
}
trap cleanup EXIT

echo " ==> Enable plugin"
vault secrets enable -path=haproxy haproxy-secrets-plugin

wait $VAULT_PID