# Needroleshere - Yet Another AWS IAM Roles Anywhere helper

This tool is a helper program for AWS IAM Roles Anywhere to obtain credentials using a X.509 ceritificate and corresponding private key. It works well as a drop-in replacement of the official [rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper) with some advantages including:

- Support loading a fullchain certificate PEM file that contains both an end entity certificate and its intermediate CA certificates.
- Support ECS container credentials provider for SDKs and libraries without process credentials provider support.

## Install

- Cargo: `cargo install needroleshere`
- Arch: `yay -Sy needroleshere` <sup>[[AUR](https://aur.archlinux.org/packages/needroleshere)]</sup>
- Debian/Ubuntu: https://github.com/nkmideb/needroleshere/releases ([nekomit-originals repo](https://sorah.jp/packaging/debian/))

## Usage

Needroleshere offers the following modes:

- `process-credentials`: Process credentials provider mode
- `server` + `ecs-full`: Container credentials provider mode using `AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN`
- `server` + `ecs-full-query`: Container credentials provider mode using `AWS_CONTAINER_CREDENTIALS_FULL_URI`
- `server` + `ecs-relative`: Container credentials provider mode using `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN`
- `server` + `ecs-relative-query`: Container credentials provider mode using `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

Comparisons explained later.

### Process credentials provider mode (`process-credentials`)

Needroleshere acts as a credentials helper program for [process credentials provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html) defined in AWS SDK.

This can be used a drop-in replacement for the official and original [rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper) because this supports [the same parameters and usage](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html):

https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html

```
[profile myrole]
    credential_process = needroleshere credential-process --certificate /path/to/certificate.pem --private-key /path/to/private-key.pem --trust-anchor-arn arn:aws:rolesanywhere:region:account:trust-anchor/TA_ID --profile-arn arn:aws:rolesanywhere:region:account:profile/PROFILE_ID --role-arn arn:aws:iam::account:role/role-name-with-path
```

The advantage of Needroleshere than the original is a certificate PEM file passed to `--certificate` can contain multiple certificates so you don't have to use `--intermediates` if you have intermediate CAs and put such certificates in a single file (`fullchain.pem`).

### Server mode (`serve`)

Server mode runs a HTTP server to act as other AWS SDK credential providers to enable using IAM Roles Anywhere for SDKs and libraries don't support process credentials provider. Currently ECS container credentials provider is implemented.

#### Run a server

Needroleshere supports (only) launching through systemd socket activation. Configure systemd units like as follows:

```systemd
# /etc/systemd/system/needroleshere.service
[Unit]
Wants=needroleshere.socket

[Service]
Type=simple
ExecStart=/usr/bin/needroleshere serve --region AWS_REGION
RuntimeDirectory=needroleshere
```

```systemd
# /etc/systemd/system/needroleshere.socket
[Socket]
ListenStream=127.0.0.1:7224
FreeBind=yes
IPAddressAllow=localhost
IPAddressDeny=any

[Install]
WantedBy=sockets.target
```

Specify `User=`, `Group=` as needed. The example unit files in full (which listens on `196.254.170.2:80`) is available under [./contrib/systemd](./contrib/systemd).

#### Use as ECS container credentials provider

Server mode supports [ECS container credentials provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html). To use this provider, you first need to generate a binding configuration and environment variables file using a helper command.

This provider supports using multiple roles on a single server process.

##### Generate binding

```
needroleshere bind myrole \
  --mode ecs-full \
  --url http://127.0.0.1:7224 \
  --certificate /path/to/certificate.pem \
  --private-key /path/to/private-key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:region:account:trust-anchor/TA_ID \
  --profile-arn arn:aws:rolesanywhere:region:account:profile/PROFILE_ID \
  --role-arn arn:aws:iam::account:role/myrole \
  --configuration-directory /path/to/etc/needroleshere
```

This will generate a configuration at `/path/to/etc/needroleshere/bindings/myrole` and a environment file at `/path/to/etc/needroleshere/env/myrole`. Treat a environment file as a secret as it includes a shared secret between Needroleshere and credentials consumer.

- `--configuration-directory` is default to `$RUNTIME_DIRECTORY` if not specified.
- Mode variants can be specified by `--mode`. For instance specify `--mode ecs-relative-query` to activate a mode uses `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` only.

Running this through systemd unit is a recommended way:

```systemd
# /etc/systemd/system/needroleshere-bind-somethingawesome.service
[Unit]
Before=somethingawesome.service
After=needroleshere.socket
PartOf=somethingawesome.service
Wants=needroleshere.socket needroleshere.service

[Service]
Type=oneshot
RemainAfterExit=yes
# use of --no-validate is recommended if you run `bind` in a systemd unit
ExecStart=/usr/bin/needroleshere bind somethingawesome --no-validate ...
ExecStop=/usr/bin/needroleshere unbind somethingawesome
RuntimeDirectory=needroleshere

[Install]
WantedBy=somethingawesome.service

# and run systemctl enable needroleshere-bind-somethingawesome.service, or specify Wants= in somethingawesome.service
```

##### Load environment file and use

```systemd
# /etc/systemd/system/somethingawesome.service

[Unit]
# You can specify Wants= here instead of systemctl enable:
# Wants=needroleshere-bind-somethingawesome.service

[Service]
Type=simple
EnvironmentFile=/run/needroleshere/env/somethingawesome
ExecStart=...

DynamicUser=yes
```

`needroleshere-bind-somethingawesome.service` and `needroleshere.socket` will be started before `somethingawesome.service` automatically. If you restart `somethingawesome.service`, `needroleshere bind` will automatically re-run to rotate a shared shared secret (thanks to `PartOf=`).

## Comparison between modes

Compatibility matrix:

  | process-credentials | ecs-full | ecs-full-query | ecs-relative | ecs-relative-query
-- | -- | -- | -- | -- | --
AWS CLI v2 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for C++ | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Go V2 (1.x) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Go 1.x (V1) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Java 2.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Java 1.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for JavaScript 3.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for JavaScript 2.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for .NET 3.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for PHP 3.x | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Python (Boto3) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
AWS SDK for Ruby 3.x | :white_check_mark: |   |   |   | :white_check_mark:
AWS SDK for Rust (preview) | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
Rusoto | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
minio-go |   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:
fog-aws |   |   |   |   | :white_check_mark:

`process-credentials` is most preferred and easy way, and use `ecs-relative-query` as a last resort option.

- `ecs-*` type has `-query` variants to prevent using `AWS_CONTAINER_AUTHORIZATION_TOKEN` as some SDKs don't support. Note that -query variants don't provide SSRF protection.
- `ecs-relative*` mode requires a special server process setup to listen on `169.254.170.2:80`.

## Security Model

- In the server mode, the server process has to be able to read private keys on behalf of credentials consumers. Plus, `needroleshere bind` command also needs to be able to read keys unless `--no-validate` is used.
  - To allow a certificate renewal with key rotation, the server process reads and parses certificates and key files in every request.
- In the ECS container credentials provider mode, an endpoint uses an access token to distinguish a role binding and authenticates its consumer. Access tokens are based on shared secret generated during `needroleshere bind`.
  - a SHA-384 digest of secret is stored to a role binding data file and read from the server process, and a secret in cleartext is stored to a environment file.
  - So consider an environment file as a secret and protect it accordingly. `needroleshere bind` preserves file mode and owner of a environment file in subsequent runs for a existing role binding.
  - `-query` mode variants use HTTP URL query string to pass an access token instead of using `AWS_CONTAINER_AUTHORIZATION_TOKEN` where turns into HTTP `Authorization` header. As `AWS_CONTAINER_CREDENTIALS_*_URI` is not considered a secret, it might have leaked into logs in case of request failure. And as the endpoint works on HTTP GET method, it is exploitable through SSRF attacks.
  - As a protection measure, for role bindings using `AWS_CONTAINER_AUTHORIZATION_TOKEN`, the endpoint rejects requests with an access token in HTTP query string.


## Caveats

- Only keys in RSA, P-256, P-384 are supported.
- Signer implementation of AWS4-X509-*-SHA256 algorithm uses crates from [RustCrypto](https://github.com/RustCrypto). Refer to their [security warning](https://github.com/RustCrypto/signatures/tree/master/ecdsa#%EF%B8%8F-security-warning) if you use EC keys with this tool.
  - For EC keys of curves other than P-256, its primitive implementation gated behind `hazmat` feature will be used; because AWS4-X509-ECDSA-SHA256 requires SHA-256 hash function to be used in ECDSA regardless of a curve's fields size, but `ecdsa` crate restricts hash function to use with ECDSA to match the same length of curve, so we have to use primitives to force using SHA-256 for curves other than P-256...
- Server mode is designed and intended to be primarily used on servers and with systemd. Supporting this mode for non-server usage is out of scope for this project.
  - Especially, ECS relative URI mode requires a privilege to listen :80. We don't have a plan to implement easy-to-use implicit helper to support launching from non-root user like in [aws-vault](https://github.com/99designs/aws-vault). 
- Server mode can use a single AWS region per process. `needroleshere bind` does take `--region` argument, but it is only used for configuration validation happens on it.
- Server mode reads certificates and a key per request. This allows certificate renewal without reloading/restarting the server process.
- Note that [systemd.exec](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#EnvironmentFile=) states that using EnvironmentFile= for credentials is discouraged.

## Configuration Examples

### Setup for `ecs-relative` mode variants

Reconfigure your socket unit like the following. You need to update `--url` if you're also using `ecs-full` mode variants.

```systemd
# /etc/systemd/system/needroleshere.socket
[Socket]
ListenStream=169.254.170.2:80
FreeBind=yes

ExecStartPre=-/bin/ip address add 169.254.170.2/32 dev lo

IPAddressAllow=localhost
IPAddressAllow=169.254.170.2/32
IPAddressDeny=any
```

### Utilizing systemd unit template

It is possible to use systemd unit template for the `needroleshere bind` service unit explained above:

```systemd
# /etc/systemd/system/needroleshere-bind@.service
[Unit]
Before=%i.service
After=needroleshere.socket
PartOf=%i.service
Wants=needroleshere.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/home/sorah/git/github.com/sorah/needroleshere/target/debug/needroleshere bind %i ... --role-arn arn:aws:iam::...:role/%i
ExecStop=/home/sorah/git/github.com/sorah/needroleshere/target/debug/needroleshere unbind %i
RuntimeDirectory=needroleshere

[Install]
WantedBy=%i.service
```

then `systemctl enable needroleshere-bind@somethingawesome.service` to pair with `somethingawesome.service`. 

## Development

### Server

run with systemfd and cargo-watch. the following is a shorthand to start on 127.0.0.1:3000:

```
./dev/serve.sh
```

To test credentials provider is working, use the following script; it run `needroleshere bind` with the given argument and pass to `aws sts get-caller-identity`.

```
./dev/roundtrip-gci.sh --region ap-northeast-1 \
  --trust-anchor-arn TA_ARN \
  --profile-arn PROFILE_ARN \
  --role-arn ROLE_ARN \
  --private-key path/to/key.pem \
  --certificate path/to/fullchain.pem \
  --no-validate \
  --mode ecs-full
```

## License

This project is licensed under the Apache-2.0 License.

Copyright 2022 Sorah Fukumori

## Copyright Notice

- [src/sign.rs](./src/sign.rs) contains a source code originally from [aws-sigv4 crate](https://github.com/awslabs/aws-sdk-rust/blob/main/sdk/aws-sigv4), which is also available under Apache License 2.0.
  - Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
- [src/ecdsa_sha256.rs](./src/ecdsa_sha256.rs) contains a source code originally from [ecdsa crate](https://github.com/RustCrypto/signatures/blob/master/ecdsa/src/hazmat.rs), which is also available under Apache License 2.0.
  - Copyright 2018-2022 RustCrypto Developers
