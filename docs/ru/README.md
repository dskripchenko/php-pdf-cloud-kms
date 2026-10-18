# dskripchenko/php-pdf-cloud-kms

Подпись PDF библиотекой [`dskripchenko/php-pdf`](https://github.com/dskripchenko/php-pdf)
ключом, который хранит **облачный KMS**: AWS KMS, Google Cloud KMS (и Cloud
HSM), Azure Key Vault (и Managed HSM). php-pdf считает хэш, сервис его
подписывает; ключ не покидает облако, а документ — ваш процесс. Получается
подпись PAdES на RSA или ECDSA.

> 🌐 [English](../../README.md) · [Deutsch](../de/README.md) · **Русский** · [中文](../zh/README.md)

## Сертификат

KMS хранит пару ключей, а не сертификат. Получите сертификат на открытый
ключ — у своего УЦ или у квалифицированного провайдера — и передайте его
как `certificatePem`. Azure Key Vault умеет хранить и сам сертификат; тогда
`AzureKeyVaultSigner::fromCertificate()` читает и то, и другое.

Прежде чем отдать подпись в php-pdf, каждый подписант проверяет её по
сертификату, поэтому ключ, не относящийся к сертификату, или ключ, чей
алгоритм использует другой хэш, дают понятную ошибку, а не PDF, который не
примет ни одна программа просмотра.

## AWS KMS

```php
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;

$signer = AwsKmsSigner::create('alias/pdf-signing', $certificatePem, region: 'eu-central-1');

$signed = PdfSigner::fromBytes($pdf)->sign(new SignatureConfig(signer: $signer, timestampAuthority: $tsa));
```

- Нужен `aws/aws-sdk-php`. Учётные данные берутся из стандартной цепочки
  SDK — окружение, профиль, роль ECS/EC2, IRSA, — либо передайте
  `clientOptions:`, либо создайте `KmsClient` сами и используйте
  `new AwsKmsSigner($client, …)`.
- Ключ: `KeyUsage: SIGN_VERIFY`, `RSA_2048/3072/4096` или
  `ECC_NIST_P256/P384/P521`. Вызывающему нужно право `kms:Sign`.
- Алгоритм определяется ключом и хэшем:
  `RSASSA_PKCS1_V1_5_SHA_256`, `ECDSA_SHA_384`…
- `sendDigest: false` отправляет сами подписываемые атрибуты
  (`MessageType: RAW`, до 4 КБ) вместо их хэша — для эмуляторов без
  `DIGEST`, например moto.

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

- REST API, Google SDK не нужен. Токены: `GoogleToken::fromMetadataServer()`,
  `GoogleToken::fromServiceAccountJson($json)` или любой источник через
  `new CallbackToken(fn () => …)` (например, google/auth).
- Версия ключа: назначение `ASYMMETRIC_SIGN`, алгоритм `EC_SIGN_*` или
  `RSA_SIGN_PKCS1_*`. Алгоритм фиксирует хэш: для ключей `…_SHA512`
  передайте `digest: DigestAlgorithm::Sha512`. Ключи RSA-PSS не
  поддерживаются. Вызывающему нужна роль `roles/cloudkms.signer`.
- Хэш отправляется вместе с CRC32C, а флаг целостности в ответе сервиса
  проверяется.

## Azure Key Vault

```php
use Dskripchenko\PhpPdfCloudKms\Azure\AzureKeyVaultSigner;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureToken;

// A Key Vault certificate: the certificate and its key in one place.
$signer = AzureKeyVaultSigner::fromCertificate('https://my-vault.vault.azure.net', 'pdf-signing', AzureToken::managedIdentity());

// A bare key, with the certificate kept elsewhere.
$signer = new AzureKeyVaultSigner('https://my-vault.vault.azure.net/keys/pdf/0123abcd…', $certificatePem, $token);
```

- REST API, Azure SDK не нужен. Токены: `AzureToken::managedIdentity()`
  (VM, AKS, App Service, Container Apps; user-assigned identity — по её
  client id) или `AzureToken::clientCredentials($tenant, $clientId, $secret)`,
  либо `new CallbackToken(fn () => …)`.
- Ключи: `RSA`, `RSA-HSM`, `EC`, `EC-HSM` (P-256, P-384, P-521), в том числе
  Managed HSM. Identity нужно право на ключ `sign` или роль *Key Vault
  Crypto User*, а для `fromCertificate()` — ещё `get` на сертификаты.

## Общие параметры

| Аргумент | По умолчанию | Смысл |
|---|---|---|
| `certificatePem` | — | Сертификат ключа: PEM или `Certificate` |
| `chainPem` | `[]` | Промежуточные сертификаты для встраивания — PEM-бандл или список |
| `digest` | по ключу | SHA-256 для RSA и P-256, SHA-384 для P-384, SHA-512 для P-521 |
| `transport` | потоки PHP | Google и Azure: ваш HTTP-клиент, прокси или повторы через `HttpTransport` из php-pdf |

Ошибки — `KmsException` с HTTP-статусом `$status` и кодом ошибки сервиса
`$errorCode` (`AccessDeniedException`, `PERMISSION_DENIED`, `Forbidden`…);
сообщение объясняет частые случаи — недостающее право или роль, неизвестный
или отключённый ключ, истёкший токен, хэш, не подходящий к ключу.

## Требования

- **PHP 8.2+** с `ext-openssl` и `ext-json` и `dskripchenko/php-pdf`
  1.19 или новее (Composer установит его сам).
- **`aws/aws-sdk-php`** — только для `AwsKmsSigner`. Google Cloud KMS и Azure
  Key Vault SDK не нужен: их REST API вызываются через HTTP-транспорт
  php-pdf.
- Исходящий HTTPS до сервиса (и до эндпоинта токенов).

## Как это проверено

- **AWS KMS** — вживую против moto (эмулятора AWS) в Docker: ключи
  RSA-2048, RSA-3072, P-256 и P-384 создаются в эмуляторе, на их открытые
  ключи выпускаются сертификаты, PDF подписываются и проверяются php-pdf и
  `pdfsig` из poppler. CI запускает это на каждое изменение; см.
  [docker/README.md](../../docker/README.md). В moto нет
  `MessageType: DIGEST`, поэтому живой прогон использует `sendDigest: false`;
  вызов с `DIGEST` покрыт модульными тестами на mock-обработчике SDK.
- **Google Cloud KMS и Azure Key Vault** эмуляторов не имеют. Подписанты
  проверены на подделках их REST API, подписывающих настоящими ключами, —
  формат запроса, разбор ответа (DER у Google, `r ‖ s` у Azure), ошибки и
  токены, — а не на живых сервисах.

## Семейство php-pdf

| Пакет | Что добавляет |
|---|---|
| [php-pdf](https://github.com/dskripchenko/php-pdf) | Ядро: HTML с CSS или билдер в PDF, чтение, слияние, заполнение форм, подпись и проверка. |
| [laravel-php-pdf](https://github.com/dskripchenko/laravel-php-pdf) | Мост для Laravel: Blade-шаблон сразу в PDF, `response()->pdf()`, подпись из конфига. |
| [php-pdf-fonts-liberation](https://github.com/dskripchenko/php-pdf-fonts-liberation) | Liberation Sans, Serif и Mono, метрически совместимые с Arial, Times New Roman и Courier New (OFL, вынесены из MIT-ядра). |
| [php-pdf-cryptopro](https://github.com/dskripchenko/php-pdf-cryptopro) | Подпись ключом в КриптоПро CSP на сервере: ГОСТ Р 34.10-2012, российская квалифицированная подпись. |
| [php-pdf-pkcs11](https://github.com/dskripchenko/php-pdf-pkcs11) | Подпись ключом на HSM, смарт-карте или USB-токене через PKCS#11. |
| **php-pdf-cloud-kms** (этот пакет) | Подпись ключом в AWS KMS, Google Cloud KMS или Azure Key Vault. |

## Лицензия

MIT — см. [LICENSE](../../LICENSE).
