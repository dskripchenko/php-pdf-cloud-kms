<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Google;

use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Certificate;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\StreamHttpTransport;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\KmsSigner;
use Dskripchenko\PhpPdfCloudKms\Token\AccessToken;

/**
 * Signs PDFs with a Google Cloud KMS (or Cloud HSM) asymmetric signing key
 * version — `EC_SIGN_P256_SHA256`, `RSA_SIGN_PKCS1_3072_SHA256` and the
 * like — through the REST API. php-pdf computes the digest; KMS signs it.
 *
 * ```php
 * $signer = new GoogleKmsSigner(
 *     'projects/p/locations/europe-west3/keyRings/r/cryptoKeys/pdf/cryptoKeyVersions/1',
 *     $certificatePem,
 *     GoogleToken::fromMetadataServer(),
 * );
 * ```
 *
 * The key version's algorithm fixes the digest: for `…_SHA512` keys pass
 * `digest: DigestAlgorithm::Sha512`. RSA-PSS keys are not supported — PDF
 * signatures here use PKCS#1 v1.5.
 */
final class GoogleKmsSigner extends KmsSigner
{
    private readonly HttpTransport $transport;

    /**
     * @param  string  $keyVersion  The full `cryptoKeyVersions/N` resource name.
     * @param  list<string>|string  $chainPem
     */
    public function __construct(
        private readonly string $keyVersion,
        Certificate|string $certificatePem,
        private readonly AccessToken $token,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
        ?HttpTransport $transport = null,
        private readonly string $endpoint = 'https://cloudkms.googleapis.com',
        private readonly float $timeoutSeconds = 30.0,
    ) {
        parent::__construct($certificatePem, $chainPem, $digest);
        $this->transport = $transport ?? new StreamHttpTransport;
    }

    protected function signDigest(string $digest): string
    {
        $url = rtrim($this->endpoint, '/').'/v1/'.$this->keyVersion.':asymmetricSign';
        $body = json_encode([
            'digest' => ['sha'.$this->shaBits() => base64_encode($digest)],
            'digestCrc32c' => (string) hexdec(hash('crc32c', $digest)),
        ], JSON_THROW_ON_ERROR);

        $response = $this->transport->post($url, $body, [
            'Authorization' => 'Bearer '.$this->token->token(),
            'Content-Type' => 'application/json',
        ], $this->timeoutSeconds);
        $json = json_decode($response->body, true);

        if ($response->status !== 200 || ! is_array($json)) {
            $error = is_array($json) && is_array($json['error'] ?? null) ? $json['error'] : [];
            $status = is_string($error['status'] ?? null) ? $error['status'] : null;
            $message = is_string($error['message'] ?? null) ? $error['message'] : 'HTTP '.$response->status;

            throw new KmsException('Google Cloud KMS: signing with '.$this->keyVersion.' failed — '.self::explain($status, $message), $response->status, $status);
        }
        if (($json['verifiedDigestCrc32c'] ?? true) !== true) {
            throw new KmsException('Google Cloud KMS: the service did not receive the digest intact (CRC32C mismatch)');
        }
        $signature = base64_decode((string) ($json['signature'] ?? ''), true);
        if ($signature === false || $signature === '') {
            throw new KmsException('Google Cloud KMS: the response has no signature');
        }

        // Cloud KMS returns ECDSA already DER-encoded, as CMS carries it.
        return $signature;
    }

    private static function explain(?string $status, string $message): string
    {
        return match ($status) {
            'PERMISSION_DENIED' => 'permission denied: the caller needs roles/cloudkms.signer on the key ('.$message.')',
            'UNAUTHENTICATED' => 'the access token is missing or expired ('.$message.')',
            'NOT_FOUND' => 'no such key version ('.$message.')',
            'FAILED_PRECONDITION' => 'the key version is not enabled, or is not an asymmetric signing key ('.$message.')',
            'INVALID_ARGUMENT' => $message.' — does the digest match the key\'s algorithm? Pass digest: for SHA-384/512 keys',
            default => ($status !== null ? $status.': ' : '').$message,
        };
    }
}
