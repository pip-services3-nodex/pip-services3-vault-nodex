#!/usr/bin/env bash

# Start server
vault server -config ./data/vault-config.hcl -dev -dev-root-token-id="vault-plaintext-root-token" &

export VAULT_ADDR='http://0.0.0.0:8201'
export VAULT_SKIP_VERIFY='true'

sleep 10

# Login
vault login token=vault-plaintext-root-token

# Enable auth
vault auth enable userpass

# Add policy
vault policy write users ./data/test-policy.hcl

# Add user and associate policy with user
vault write auth/userpass/users/user password=pass policies=users

sleep 1000000