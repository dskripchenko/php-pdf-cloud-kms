<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Google;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpGetTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\StreamHttpTransport;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\Token\CachedToken;

/**
 * Google OAuth tokens for Cloud KMS, without the Google SDK: from the
 * metadata server (GCE, GKE, Cloud Run, Cloud Functions) or from a service
 * account key file. With google/auth at hand, a `CallbackToken` works too.
 */
final class GoogleToken extends CachedToken
{
    public const SCOPE = 'https://www.googleapis.com/auth/cloudkms';

    private const METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';

    /** @param  \Closure(): HttpResponse  $fetch */
    private function __construct(private readonly \Closure $fetch) {}

    /** The workload's own service account, from the metadata server. */
    public static function fromMetadataServer(?HttpGetTransport $transport = null, float $timeoutSeconds = 5.0): self
    {
        $transport ??= new StreamHttpTransport;

        return new self(static fn (): HttpResponse => $transport->get(self::METADATA_URL, ['Metadata-Flavor' => 'Google'], $timeoutSeconds));
    }

    /**
     * A service account key (the JSON file from IAM): signs a JWT with the
     * account's private key and exchanges it for an access token.
     */
    public static function fromServiceAccountJson(
        #[\SensitiveParameter] string $json,
        ?HttpTransport $transport = null,
        float $timeoutSeconds = 10.0,
    ): self {
        $key = json_decode($json, true);
        if (! is_array($key) || ! is_string($key['client_email'] ?? null) || ! is_string($key['private_key'] ?? null)) {
            throw new KmsException('Not a Google service account key: client_email and private_key are required');
        }
        $tokenUri = is_string($key['token_uri'] ?? null) ? $key['token_uri'] : 'https://oauth2.googleapis.com/token';
        $transport ??= new StreamHttpTransport;

        return new self(static function () use ($key, $tokenUri, $transport, $timeoutSeconds): HttpResponse {
            $now = time();
            $segments = [
                self::base64Url((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT'])),
                self::base64Url((string) json_encode([
                    'iss' => $key['client_email'],
                    'scope' => self::SCOPE,
                    'aud' => $tokenUri,
                    'iat' => $now,
                    'exp' => $now + 3600,
                ])),
            ];
            if (! openssl_sign(implode('.', $segments), $signature, $key['private_key'], OPENSSL_ALGO_SHA256)) {
                throw new KmsException('Could not sign the token request with the service account key');
            }
            $segments[] = self::base64Url($signature);

            return $transport->post($tokenUri, http_build_query([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => implode('.', $segments),
            ]), ['Content-Type' => 'application/x-www-form-urlencoded'], $timeoutSeconds);
        });
    }

    protected function fetch(): HttpResponse
    {
        return ($this->fetch)();
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
