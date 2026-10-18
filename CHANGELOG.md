# Changelog

All notable changes to `dskripchenko/php-pdf-cloud-kms` are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-10-18

### Added
- `AwsKmsSigner` — a php-pdf `Signer` for an asymmetric AWS KMS key (RSA,
  ECC NIST) through the AWS SDK; `MessageType: DIGEST`, or `RAW` with
  `sendDigest: false`.
- `GoogleKmsSigner` — Google Cloud KMS / Cloud HSM key versions through the
  REST API, the digest sent with its CRC32C; `GoogleToken` from the metadata
  server or a service account key.
- `AzureKeyVaultSigner` — Azure Key Vault and Managed HSM keys through the
  REST API, `fromCertificate()` for a Key Vault certificate; `AzureToken`
  from a managed identity or client credentials.
- `CallbackToken` for tokens from any other source.
- Every signature is verified against the certificate before it is
  embedded; `KmsException` carries the HTTP status and the service's error
  code, with plain explanations of the common failures.
- `docker/` — a live check of `AwsKmsSigner` against moto; run in CI.
