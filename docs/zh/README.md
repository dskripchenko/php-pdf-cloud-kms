# dskripchenko/php-pdf-cloud-kms

使用 [`dskripchenko/php-pdf`](https://github.com/dskripchenko/php-pdf)
签署 PDF，密钥保存在 **云 KMS** 中：AWS KMS、Google Cloud KMS（及 Cloud
HSM）、Azure Key Vault（及 Managed HSM）。php-pdf 计算哈希，服务对其签名；
密钥从不离开云端，文档也从不离开你的进程。得到使用 RSA 或 ECDSA 的 PAdES
签名。

> 🌐 [English](../../README.md) · [Deutsch](../de/README.md) · [Русский](../ru/README.md) · **中文**

## 证书

KMS 保存的是密钥对，而不是证书。请为该密钥的公钥签发证书——由你的 CA 或
合格的服务商签发——并作为 `certificatePem` 传入。Azure Key Vault 可以自己
保存证书；此时 `AzureKeyVaultSigner::fromCertificate()` 会同时读取证书和密钥。

每个签名者在把签名交给 php-pdf 之前都会用证书验证返回的签名，因此不属于该
证书的密钥，或其算法使用另一种哈希的密钥，会得到明确的错误，而不是生成一个
任何阅读器都不接受的 PDF。

## AWS KMS

```php
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;

$signer = AwsKmsSigner::create('alias/pdf-signing', $certificatePem, region: 'eu-central-1');

$signed = PdfSigner::fromBytes($pdf)->sign(new SignatureConfig(signer: $signer, timestampAuthority: $tsa));
```

- 需要 `aws/aws-sdk-php`。凭据来自 SDK 的默认链——环境变量、profile、
  ECS/EC2 角色、IRSA——也可以传入 `clientOptions:`，或自行构建 `KmsClient`
  并使用 `new AwsKmsSigner($client, …)`。
- 密钥：`KeyUsage: SIGN_VERIFY`，`RSA_2048/3072/4096` 或
  `ECC_NIST_P256/P384/P521`。调用方需要 `kms:Sign`。
- 算法由密钥和哈希决定：`RSASSA_PKCS1_V1_5_SHA_256`、`ECDSA_SHA_384`…
- `sendDigest: false` 发送已签名属性本身（`MessageType: RAW`，最多 4 KB）
  而不是其哈希——用于不支持 `DIGEST` 的模拟器，例如 moto。

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

- 使用 REST API，无需 Google SDK。令牌：`GoogleToken::fromMetadataServer()`、
  `GoogleToken::fromServiceAccountJson($json)`，或通过
  `new CallbackToken(fn () => …)` 接入任意来源（例如 google/auth）。
- 密钥版本：用途为 `ASYMMETRIC_SIGN`，算法为 `EC_SIGN_*` 或
  `RSA_SIGN_PKCS1_*`。算法决定哈希：对于 `…_SHA512` 密钥请传入
  `digest: DigestAlgorithm::Sha512`。不支持 RSA-PSS 密钥。调用方需要
  `roles/cloudkms.signer`。
- 哈希连同其 CRC32C 一起发送，并会检查服务返回的完整性标志。

## Azure Key Vault

```php
use Dskripchenko\PhpPdfCloudKms\Azure\AzureKeyVaultSigner;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureToken;

// A Key Vault certificate: the certificate and its key in one place.
$signer = AzureKeyVaultSigner::fromCertificate('https://my-vault.vault.azure.net', 'pdf-signing', AzureToken::managedIdentity());

// A bare key, with the certificate kept elsewhere.
$signer = new AzureKeyVaultSigner('https://my-vault.vault.azure.net/keys/pdf/0123abcd…', $certificatePem, $token);
```

- 使用 REST API，无需 Azure SDK。令牌：`AzureToken::managedIdentity()`
  （VM、AKS、App Service、Container Apps；用户分配的标识通过其 client id
  指定）或 `AzureToken::clientCredentials($tenant, $clientId, $secret)`，
  也可以用 `new CallbackToken(fn () => …)`。
- 密钥：`RSA`、`RSA-HSM`、`EC`、`EC-HSM`（P-256、P-384、P-521），也支持
  Managed HSM。标识需要密钥权限 `sign` 或 *Key Vault Crypto User* 角色，
  使用 `fromCertificate()` 时还需要证书的 `get` 权限。

## 通用选项

| 参数 | 默认值 | 含义 |
|---|---|---|
| `certificatePem` | — | 密钥对应的证书：PEM 或 `Certificate` |
| `chainPem` | `[]` | 要嵌入的中间证书——PEM 证书包或列表 |
| `digest` | 随密钥 | RSA 和 P-256 用 SHA-256，P-384 用 SHA-384，P-521 用 SHA-512 |
| `transport` | PHP 流 | Google 和 Azure：通过 php-pdf 的 `HttpTransport` 接入你的 HTTP 客户端、代理或重试 |

错误以 `KmsException` 抛出，带有 HTTP 状态 `$status` 和服务的错误代码
`$errorCode`（`AccessDeniedException`、`PERMISSION_DENIED`、`Forbidden`…）；
消息会解释常见情况——缺少权限或角色、密钥未知或已禁用、令牌过期、哈希与
密钥不匹配。

## 要求

- **PHP 8.2+**，需要 `ext-openssl` 和 `ext-json`，以及 `dskripchenko/php-pdf`
  1.19 或更高版本（由 Composer 安装）。
- **`aws/aws-sdk-php`**，仅 `AwsKmsSigner` 需要。Google Cloud KMS 和 Azure
  Key Vault 无需 SDK：其 REST API 通过 php-pdf 的 HTTP 传输调用。
- 能向服务（以及令牌端点）发起出站 HTTPS 连接。

## 验证方式

- **AWS KMS**——在 Docker 中针对 moto（AWS 模拟器）实际运行：在模拟器中创建
  RSA-2048、RSA-3072、P-256 和 P-384 密钥，为其公钥签发证书，签署 PDF 并用
  php-pdf 和 poppler 的 `pdfsig` 验证。CI 在每次变更时运行它；见
  [docker/README.md](../../docker/README.md)。moto 不支持
  `MessageType: DIGEST`，因此实际运行使用 `sendDigest: false`；`DIGEST`
  调用由针对 SDK mock handler 的单元测试覆盖。
- **Google Cloud KMS 和 Azure Key Vault** 没有模拟器。签名者针对其 REST API
  的仿冒实现进行测试，这些仿冒实现使用真实密钥签名——覆盖请求格式、响应解码
  （Google 为 DER，Azure 为 `r ‖ s`）、错误和令牌——而不是针对真实服务。

## php-pdf 系列

| 包 | 提供的功能 |
|---|---|
| [php-pdf](https://github.com/dskripchenko/php-pdf) | 核心：用 HTML 加 CSS 或构建器生成 PDF，读取、合并、填写表单、签名和验证。 |
| [laravel-php-pdf](https://github.com/dskripchenko/laravel-php-pdf) | Laravel 桥接：Blade 视图直接生成 PDF、`response()->pdf()`、按配置签名。 |
| [php-pdf-fonts-liberation](https://github.com/dskripchenko/php-pdf-fonts-liberation) | Liberation Sans、Serif 和 Mono，与 Arial、Times New Roman 和 Courier New 度量兼容（OFL 许可，独立于 MIT 核心之外）。 |
| [php-pdf-cryptopro](https://github.com/dskripchenko/php-pdf-cryptopro) | 使用服务器上 CryptoPro CSP 中的密钥签名：GOST R 34.10-2012，俄罗斯合格电子签名。 |
| [php-pdf-pkcs11](https://github.com/dskripchenko/php-pdf-pkcs11) | 通过 PKCS#11 使用 HSM、智能卡或 USB 令牌上的密钥签名。 |
| **php-pdf-cloud-kms**（本包） | 使用 AWS KMS、Google Cloud KMS 或 Azure Key Vault 中的密钥签名。 |

## 许可证

MIT——见 [LICENSE](../../LICENSE)。
