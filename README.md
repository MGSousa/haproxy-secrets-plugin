# HAProxy Plugin for Vault

[![Go Report Card](https://goreportcard.com/badge/github.com/MGSousa/haproxy-secrets-plugin)](https://goreportcard.com/report/github.com/MGSousa/haproxy-secrets-plugin)
![Actions Status](https://github.com/MGSousa/haproxy-secrets-plugin/workflows/plugin-release/badge.svg)

Vault plugin for generate hashed HAProxy userlist password

## Build && Run Vault
```shell
./make-dev.sh
```

## Configuration
 - **output** - Defines if secret hashed will be returned, ignores userlist options
 - **remote_path** - Remote userlist file to parse from, if set ignores 'source_path
 - **source_path**  - Userlist local file to parse from, use this if 'remote_path' not set
 - **target_path**  - Target file path where userlist will be saved
 - **crypter** - Algorithm to generate hashes (sha256, sha512)
```shell
vault write haproxy/options options...
```

## Secret encryption
```shell
vault write haproxy/password username=password
```

## TODO
 - Synchronize modified userlist to a remote API
 - Add tests coverage