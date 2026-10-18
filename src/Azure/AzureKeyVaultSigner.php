<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Azure;

use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Certificate;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpGetTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\StreamHttpTransport;
use Dskripchenko\PhpPdfCloudKms\EcdsaSignature;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\KmsSigner;
use Dskripchenko\PhpPdfCloudKms\Token\AccessToken;

/**
 * Signs PDFs with an Azure Key Vault or Managed HSM key (RSA, RSA-HSM, EC,
 * EC-HSM) through the REST API. php-pdf computes the digest; Key Vault
 * signs it.
 *
 * ```php
 * // A Key Vault certificate: the certificate and its key in one place.
 * $signer = AzureKeyVaultSigner::fromCertificate('https://my-vault.vault.azure.net', 'pdf-signing', AzureToken::managedIdentity());
 *
 * // A bare key, with the certificate kept elsewhere.
 * $signer = new AzureKeyVaultSigner('https://my-vault.vault.azure.net/keys/pdf/0123abcd…', $certificatePem, $token);
 * ```
 */
final class AzureKeyVaultSigner extends KmsSigner
{
    public const API_VERSION = '7.4';

    private readonly HttpTransport $transport;

    /**
     * @param  string  $keyUrl  The key identifier, `https://{vault}.vault.azure.net/keys/{name}[/{version}]`.
     * @param  list<string>|string  $chainPem
     */
    public function __construct(
        private readonly string $keyUrl,
        Certificate|string $certificatePem,
        private readonly AccessToken $token,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
        ?HttpTransport $transport = null,
        private readonly float $timeoutSeconds = 30.0,
    ) {
        parent::__construct($certificatePem, $chainPem, $digest);
        $this->transport = $transport ?? new StreamHttpTransport;
    }

    /**
     * From a Key Vault certificate: reads the certificate (its latest
     * version, or `$version`) and signs with the key behind it.
     *
     * @param  list<string>|string  $chainPem
     */
    public static function fromCertificate(
        string $vaultUrl,
        string $certificateName,
        AccessToken $token,
        ?string $version = null,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
        (HttpTransport&HttpGetTransport)|null $transport = null,
        float $timeoutSeconds = 30.0,
    ): self {
        $transport ??= new StreamHttpTransport;
        $url = rtrim($vaultUrl, '/').'/certificates/'.rawurlencode($certificateName).($version !== null ? '/'.rawurlencode($version) : '').'?api-version='.self::API_VERSION;
        $response = $transport->get($url, ['Authorization' => 'Bearer '.$token->token()], $timeoutSeconds);
        $json = self::decode($response, 'reading the certificate '.$certificateName);

        $der = base64_decode((string) ($json['cer'] ?? ''), true);
        $kid = $json['kid'] ?? null;
        if ($der === false || $der === '' || ! is_string($kid)) {
            throw new KmsException('Azure Key Vault: the certificate '.$certificateName.' has no DER or key id in the response');
        }

        return new self($kid, Certificate::fromDer($der), $token, $chainPem, $digest, $transport, $timeoutSeconds);
    }

    /** The JWS algorithm Key Vault takes: `RS256`, `ES384`… */
    public function algorithm(): string
    {
        return ($this->isEc() ? 'ES' : 'RS').$this->shaBits();
    }

    protected function signDigest(string $digest): string
    {
        $url = rtrim($this->keyUrl, '/').'/sign?api-version='.self::API_VERSION;
        $body = json_encode(['alg' => $this->algorithm(), 'value' => self::base64Url($digest)], JSON_THROW_ON_ERROR);
        $response = $this->transport->post($url, $body, [
            'Authorization' => 'Bearer '.$this->token->token(),
            'Content-Type' => 'application/json',
        ], $this->timeoutSeconds);
        $json = self::decode($response, 'signing with '.$this->keyUrl);

        $value = is_string($json['value'] ?? null) ? self::fromBase64Url($json['value']) : '';
        if ($value === '') {
            throw new KmsException('Azure Key Vault: the response has no signature');
        }

        // Key Vault returns ECDSA as JWS does, r ‖ s; CMS carries DER.
        return $this->isEc() ? EcdsaSignature::toDer($value) : $value;
    }

    /** @return array<string, mixed> */
    private static function decode(HttpResponse $response, string $action): array
    {
        $json = json_decode($response->body, true);
        if ($response->status === 200 && is_array($json)) {
            return $json;
        }
        $error = is_array($json) && is_array($json['error'] ?? null) ? $json['error'] : [];
        $code = is_string($error['code'] ?? null) ? $error['code'] : null;
        $message = is_string($error['message'] ?? null) ? $error['message'] : 'HTTP '.$response->status;
        $explained = match (true) {
            $response->status === 401 => 'the access token is missing, expired or for another resource — the scope must be https://vault.azure.net/.default ('.$message.')',
            $response->status === 403 => 'forbidden: the identity needs the "sign" key permission or the Key Vault Crypto User role (and "get" on certificates for fromCertificate) ('.$message.')',
            $response->status === 404 => 'not found — check the vault URL, the name and the version ('.$message.')',
            default => ($code !== null ? $code.': ' : '').$message,
        };

        throw new KmsException('Azure Key Vault: '.$action.' failed — '.$explained, $response->status, $code);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function fromBase64Url(string $text): string
    {
        return (string) base64_decode(strtr($text, '-_', '+/'), true);
    }
}
