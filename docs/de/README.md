# dskripchenko/php-pdf-cloud-kms

PDFs mit [`dskripchenko/php-pdf`](https://github.com/dskripchenko/php-pdf)
signieren — mit einem Schlüssel in einem **Cloud-KMS**: AWS KMS, Google
Cloud KMS (und Cloud HSM), Azure Key Vault (und Managed HSM). php-pdf
berechnet den Hash, der Dienst signiert ihn; der Schlüssel verlässt die
Cloud nie, und das Dokument verlässt Ihren Prozess nie. Das Ergebnis ist
eine PAdES-Signatur mit RSA oder ECDSA.

> 🌐 [English](../../README.md) · **Deutsch** · [Русский](../ru/README.md) · [中文](../zh/README.md)

## Das Zertifikat

Ein KMS hält ein Schlüsselpaar, kein Zertifikat. Lassen Sie eines für den
öffentlichen Schlüssel ausstellen — von Ihrer CA oder einem qualifizierten
Anbieter — und übergeben Sie es als `certificatePem`. Azure Key Vault kann
das Zertifikat selbst halten; dann liest
`AzureKeyVaultSigner::fromCertificate()` beides.

Jeder Signierer prüft die zurückgegebene Signatur gegen das Zertifikat,
bevor er sie an php-pdf weitergibt; ein Schlüssel, der nicht zum
Zertifikat gehört, oder ein Schlüssel, dessen Algorithmus einen anderen
Hash verwendet, führt so zu einem klaren Fehler statt zu einer PDF, die
kein Reader akzeptiert.

## AWS KMS

```php
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;

$signer = AwsKmsSigner::create('alias/pdf-signing', $certificatePem, region: 'eu-central-1');

$signed = PdfSigner::fromBytes($pdf)->sign(new SignatureConfig(signer: $signer, timestampAuthority: $tsa));
```

- Benötigt `aws/aws-sdk-php`. Zugangsdaten kommen aus der Standardkette des
  SDK — Umgebung, Profil, ECS/EC2-Rolle, IRSA —, oder Sie übergeben
  `clientOptions:`, oder Sie bauen den `KmsClient` selbst und verwenden
  `new AwsKmsSigner($client, …)`.
- Der Schlüssel: `KeyUsage: SIGN_VERIFY`, `RSA_2048/3072/4096` oder
  `ECC_NIST_P256/P384/P521`. Der Aufrufer benötigt `kms:Sign`.
- Der Algorithmus ergibt sich aus Schlüssel und Hash:
  `RSASSA_PKCS1_V1_5_SHA_256`, `ECDSA_SHA_384`…
- `sendDigest: false` sendet die signierten Attribute selbst
  (`MessageType: RAW`, bis 4 KB) statt ihres Hashes — für Emulatoren ohne
  `DIGEST`, etwa moto.

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

- REST-API, kein Google SDK nötig. Tokens: `GoogleToken::fromMetadataServer()`,
  `GoogleToken::fromServiceAccountJson($json)` oder eine beliebige Quelle über
  `new CallbackToken(fn () => …)` (etwa google/auth).
- Die Schlüsselversion: Zweck `ASYMMETRIC_SIGN`, ein Algorithmus
  `EC_SIGN_*` oder `RSA_SIGN_PKCS1_*`. Der Algorithmus legt den Hash fest:
  Für `…_SHA512`-Schlüssel übergeben Sie `digest: DigestAlgorithm::Sha512`.
  RSA-PSS-Schlüssel werden nicht unterstützt. Der Aufrufer benötigt
  `roles/cloudkms.signer`.
- Der Hash wird mit seiner CRC32C gesendet, und das Integritäts-Flag des
  Dienstes wird geprüft.

## Azure Key Vault

```php
use Dskripchenko\PhpPdfCloudKms\Azure\AzureKeyVaultSigner;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureToken;

// A Key Vault certificate: the certificate and its key in one place.
$signer = AzureKeyVaultSigner::fromCertificate('https://my-vault.vault.azure.net', 'pdf-signing', AzureToken::managedIdentity());

// A bare key, with the certificate kept elsewhere.
$signer = new AzureKeyVaultSigner('https://my-vault.vault.azure.net/keys/pdf/0123abcd…', $certificatePem, $token);
```

- REST-API, kein Azure SDK nötig. Tokens: `AzureToken::managedIdentity()`
  (VMs, AKS, App Service, Container Apps; eine benutzerseitig zugewiesene
  Identität über ihre Client-ID) oder
  `AzureToken::clientCredentials($tenant, $clientId, $secret)`, oder
  `new CallbackToken(fn () => …)`.
- Schlüssel: `RSA`, `RSA-HSM`, `EC`, `EC-HSM` (P-256, P-384, P-521), auch
  Managed HSM. Die Identität benötigt die Schlüsselberechtigung `sign` oder
  die Rolle *Key Vault Crypto User*, für `fromCertificate()` zusätzlich
  `get` auf Zertifikate.

## Gemeinsame Optionen

| Argument | Standard | Bedeutung |
|---|---|---|
| `certificatePem` | — | Das Zertifikat zum Schlüssel: PEM oder ein `Certificate` |
| `chainPem` | `[]` | Einzubettende Zwischenzertifikate — ein PEM-Bundle oder eine Liste |
| `digest` | nach Schlüssel | SHA-256 für RSA und P-256, SHA-384 für P-384, SHA-512 für P-521 |
| `transport` | PHP-Streams | Google und Azure: Ihr HTTP-Client, Proxy oder Wiederholungen über `HttpTransport` von php-pdf |

Fehler sind `KmsException` mit dem HTTP-Status `$status` und dem
Fehlercode des Dienstes `$errorCode` (`AccessDeniedException`,
`PERMISSION_DENIED`, `Forbidden`…); die Meldung erklärt die häufigen
Fälle — fehlende Berechtigung oder Rolle, unbekannter oder deaktivierter
Schlüssel, abgelaufenes Token, ein Hash, der nicht zum Schlüssel passt.

## Voraussetzungen

- **PHP 8.2+** mit `ext-openssl` und `ext-json` sowie `dskripchenko/php-pdf`
  1.19 oder neuer (Composer installiert es).
- **`aws/aws-sdk-php`** nur für `AwsKmsSigner`. Google Cloud KMS und Azure
  Key Vault brauchen kein SDK: Ihre REST-APIs werden über den
  HTTP-Transport von php-pdf aufgerufen.
- Ausgehendes HTTPS zum Dienst (und zum Token-Endpunkt).

## Wie es geprüft wurde

- **AWS KMS** — live gegen moto (einen AWS-Emulator) in Docker: RSA-2048-,
  RSA-3072-, P-256- und P-384-Schlüssel werden im Emulator erzeugt,
  Zertifikate für ihre öffentlichen Schlüssel ausgestellt, PDFs signiert und
  mit php-pdf und `pdfsig` aus poppler validiert. Die CI führt das bei jeder
  Änderung aus; siehe [docker/README.md](../../docker/README.md). moto
  fehlt `MessageType: DIGEST`, daher nutzt der Live-Lauf
  `sendDigest: false`; der `DIGEST`-Aufruf ist durch Unit-Tests gegen den
  Mock-Handler des SDK abgedeckt.
- **Google Cloud KMS und Azure Key Vault** haben keine Emulatoren. Die
  Signierer sind gegen Fakes ihrer REST-APIs getestet, die mit echten
  Schlüsseln signieren — Anfrageformat, Dekodierung der Antwort (DER bei
  Google, `r ‖ s` bei Azure), Fehler und Tokens —, nicht gegen die echten
  Dienste.

## Die php-pdf-Familie

| Paket | Was es hinzufügt |
|---|---|
| [php-pdf](https://github.com/dskripchenko/php-pdf) | Der Kern: HTML mit CSS oder ein Builder zu PDF, lesen, zusammenführen, Formulare ausfüllen, signieren und validieren. |
| [laravel-php-pdf](https://github.com/dskripchenko/laravel-php-pdf) | Laravel-Brücke: eine Blade-View direkt als PDF, `response()->pdf()`, Signieren aus der Konfiguration. |
| [php-pdf-fonts-liberation](https://github.com/dskripchenko/php-pdf-fonts-liberation) | Liberation Sans, Serif und Mono, metrisch kompatibel zu Arial, Times New Roman und Courier New (OFL, aus dem MIT-Kern herausgehalten). |
| [php-pdf-cryptopro](https://github.com/dskripchenko/php-pdf-cryptopro) | Signiert mit einem Schlüssel in CryptoPro CSP auf dem Server: GOST R 34.10-2012, russische qualifizierte Signaturen. |
| [php-pdf-pkcs11](https://github.com/dskripchenko/php-pdf-pkcs11) | Signiert mit einem Schlüssel auf einem HSM, einer Smartcard oder einem USB-Token über PKCS#11. |
| **php-pdf-cloud-kms** (dieses Paket) | Signiert mit einem Schlüssel in AWS KMS, Google Cloud KMS oder Azure Key Vault. |

## Lizenz

MIT — siehe [LICENSE](../../LICENSE).
