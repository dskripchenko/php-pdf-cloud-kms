<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Token;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdfCloudKms\KmsException;

/**
 * An OAuth token fetched from an endpoint and kept until a minute before
 * it expires.
 */
abstract class CachedToken implements AccessToken
{
    private ?string $token = null;

    private int $expiresAt = 0;

    /** Fetches a fresh token response (`access_token`, `expires_in`). */
    abstract protected function fetch(): HttpResponse;

    public function token(): string
    {
        if ($this->token !== null && time() < $this->expiresAt - 60) {
            return $this->token;
        }
        $response = $this->fetch();
        $json = json_decode($response->body, true);
        if ($response->status !== 200 || ! is_array($json) || ! is_string($json['access_token'] ?? null)) {
            $error = is_array($json) ? ($json['error_description'] ?? $json['error'] ?? null) : null;

            throw new KmsException(
                'Could not get an access token: HTTP '.$response->status.(is_string($error) ? ' — '.$error : ''),
                $response->status,
                is_array($json) && is_string($json['error'] ?? null) ? $json['error'] : null,
            );
        }
        $this->token = $json['access_token'];
        $this->expiresAt = time() + (int) ($json['expires_in'] ?? 300);

        return $this->token;
    }
}
