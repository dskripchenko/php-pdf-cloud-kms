# dskripchenko/php-pdf-cloud-kms

Sign PDFs with [`dskripchenko/php-pdf`](https://github.com/dskripchenko/php-pdf)
using a key held by a **cloud KMS**: AWS KMS, Google Cloud KMS (and Cloud
HSM), Azure Key Vault (and Managed HSM). php-pdf computes the digest, the
service signs it; the key never leaves the cloud and the document never
leaves your process. The result is a PAdES signature with RSA or ECDSA.

> 🌐 **English** · [Deutsch](docs/de/README.md) · [Русский](docs/ru/README.md) · [中文](docs/zh/README.md)

[![Tests](https://img.shields.io/github/actions/workflow/status/dskripchenko/php-pdf-cloud-kms/tests.yml?branch=main&label=tests&logo=github)](https://github.com/dskripchenko/php-pdf-cloud-kms/actions/workflows/tests.yml)
[![Packagist](https://img.shields.io/packagist/v/dskripchenko/php-pdf-cloud-kms.svg)](https://packagist.org/packages/dskripchenko/php-pdf-cloud-kms)
[![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%5E8.2-blue.svg)](composer.json)

---

## The certificate

A KMS holds a key pair, not a certificate. Get one issued for the key's
public key — by your CA, or a qualified provider — and pass it as
`certificatePem`. Azure Key Vault can hold the certificate itself; then
`AzureKeyVaultSigner::fromCertificate()` reads both.

Every signer verifies the returned signature against the certificate before
handing it to php-pdf, so a key that does not belong to the certificate, or
a key whose algorithm uses another digest, fails with a clear error instead
of producing a PDF no reader accepts.

## AWS KMS

```php
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;

$signer = AwsKmsSigner::create('alias/pdf-signing', $certificatePem, region: 'eu-central-1');

$signed = PdfSigner::fromBytes($pdf)->sign(new SignatureConfig(signer: $signer, timestampAuthority: $tsa));
```

- Needs `aws/aws-sdk-php`. Credentials come from the SDK's default chain —
  environment, profile, ECS/EC2 role, IRSA — or pass `clientOptions:`, or
  build the `KmsClient` yourself and use `new AwsKmsSigner($client, …)`.
- The key: `KeyUsage: SIGN_VERIFY`, `RSA_2048/3072/4096` or
  `ECC_NIST_P256/P384/P521`. The caller needs `kms:Sign`.
- The algorithm follows the key and the digest:
  `RSASSA_PKCS1_V1_5_SHA_256`, `ECDSA_SHA_384`…
- `sendDigest: false` sends the signed attributes themselves
  (`MessageType: RAW`, up to 4 KB) instead of their digest — for emulators
  without `DIGEST`, such as moto.

## Google Cloud KMS

```php
use Dskripchenko\PhpPdfCloudKms\Google\GoogleKmsSigner;
use Dskripchenko\PhpPdfCloudKms\Google\GoogleToken;

$signer = new GoogleKmsSigner(
    'projects/my-project/locations/europe-west3/keyRings/pdf/cryptoKeys/signing/cryptoKeyVersions/1',
    $certificatePem,
    GoogleToken::fromMetadataServer(),        // GCE, GKE, Cloud Run, Cloud Functions
);
```

- REST API, no Google SDK needed. Tokens: `GoogleToken::fromMetadataServer()`,
  `GoogleToken::fromServiceAccountJson($json)`, or any source through
  `new CallbackToken(fn () => …)` (google/auth, for one).
- The key version: purpose `ASYMMETRIC_SIGN`, an `EC_SIGN_*` or
  `RSA_SIGN_PKCS1_*` algorithm. The algorithm fixes the digest: for
  `…_SHA512` keys pass `digest: DigestAlgorithm::Sha512`. RSA-PSS keys are
  not supported. The caller needs `roles/cloudkms.signer`.
- The digest is sent with its CRC32C, and the service's integrity flag is
  checked.

## Azure Key Vault

```php
use Dskripchenko\PhpPdfCloudKms\Azure\AzureKeyVaultSigner;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureToken;

// A Key Vault certificate: the certificate and its key in one place.
$signer = AzureKeyVaultSigner::fromCertificate('https://my-vault.vault.azure.net', 'pdf-signing', AzureToken::managedIdentity());

// A bare key, with the certificate kept elsewhere.
$signer = new AzureKeyVaultSigner('https://my-vault.vault.azure.net/keys/pdf/0123abcd…', $certificatePem, $token);
```

- REST API, no Azure SDK needed. Tokens: `AzureToken::managedIdentity()`
  (VMs, AKS, App Service, Container Apps; a user-assigned identity by its
  client id) or `AzureToken::clientCredentials($tenant, $clientId, $secret)`,
  or `new CallbackToken(fn () => …)`.
- Keys: `RSA`, `RSA-HSM`, `EC`, `EC-HSM` (P-256, P-384, P-521), Managed HSM
  too. The identity needs the `sign` key permission or the *Key Vault Crypto
  User* role, and `get` on certificates for `fromCertificate()`.

## Common options

| Argument | Default | Meaning |
|---|---|---|
| `certificatePem` | — | The certificate for the key: PEM or a `Certificate` |
| `chainPem` | `[]` | Intermediate certificates to embed — a PEM bundle or a list |
| `digest` | by the key | SHA-256 for RSA and P-256, SHA-384 for P-384, SHA-512 for P-521 |
| `transport` | PHP streams | Google and Azure: your HTTP client, proxy or retries through php-pdf's `HttpTransport` |

Failures are `KmsException` with the HTTP `$status` and the service's
`$errorCode` (`AccessDeniedException`, `PERMISSION_DENIED`, `Forbidden`…);
the message explains the common ones — the missing permission or role, an
unknown or disabled key, an expired token, a digest that does not match the
key.

## How it was checked

- **AWS KMS** — live against moto (an AWS emulator) in Docker: RSA-2048,
  RSA-3072, P-256 and P-384 keys created in the emulator, certificates
  issued for their public keys, PDFs signed and validated by php-pdf and
  poppler's `pdfsig`. CI runs it on every change; see
  [docker/README.md](docker/README.md). moto lacks `MessageType: DIGEST`,
  so the live run uses `sendDigest: false`; the `DIGEST` call is covered by
  unit tests against the SDK's mock handler.
- **Google Cloud KMS and Azure Key Vault** have no emulators. The signers
  are tested against fakes of their REST APIs that sign with real keys —
  the request format, the response decoding (DER for Google, `r ‖ s` for
  Azure), the errors and the tokens — not against the live services.

## License

MIT — see [LICENSE](LICENSE).
