<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Azure;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpGetTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\StreamHttpTransport;
use Dskripchenko\PhpPdfCloudKms\Token\CachedToken;

/**
 * Microsoft Entra ID tokens for Key Vault: a managed identity (VMs, App
 * Service, AKS, Container Apps) or an app registration's client secret.
 */
final class AzureToken extends CachedToken
{
    public const RESOURCE = 'https://vault.azure.net';

    /** @param  \Closure(): HttpResponse  $fetch */
    private function __construct(private readonly \Closure $fetch) {}

    /**
     * The managed identity of the host, from the instance metadata service.
     *
     * @param  ?string  $clientId  For a user-assigned identity.
     */
    public static function managedIdentity(?string $clientId = null, ?HttpGetTransport $transport = null, float $timeoutSeconds = 5.0): self
    {
        $transport ??= new StreamHttpTransport;
        // App Service and Container Apps expose their own endpoint.
        $endpoint = getenv('IDENTITY_ENDPOINT') ?: null;
        $header = getenv('IDENTITY_HEADER') ?: null;

        return new self(static function () use ($transport, $timeoutSeconds, $clientId, $endpoint, $header): HttpResponse {
            $query = ['resource' => self::RESOURCE] + ($clientId !== null ? ['client_id' => $clientId] : []);
            if ($endpoint !== null && $header !== null) {
                return $transport->get($endpoint.'?'.http_build_query(['api-version' => '2019-08-01'] + $query), ['X-IDENTITY-HEADER' => $header], $timeoutSeconds);
            }

            return $transport->get(
                'http://169.254.169.254/metadata/identity/oauth2/token?'.http_build_query(['api-version' => '2018-02-01'] + $query),
                ['Metadata' => 'true'],
                $timeoutSeconds,
            );
        });
    }

    /** An app registration (service principal) with a client secret. */
    public static function clientCredentials(
        string $tenantId,
        string $clientId,
        #[\SensitiveParameter] string $clientSecret,
        ?HttpTransport $transport = null,
        float $timeoutSeconds = 10.0,
        string $authority = 'https://login.microsoftonline.com',
    ): self {
        $transport ??= new StreamHttpTransport;

        return new self(static fn (): HttpResponse => $transport->post(
            rtrim($authority, '/').'/'.rawurlencode($tenantId).'/oauth2/v2.0/token',
            http_build_query([
                'grant_type' => 'client_credentials',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'scope' => self::RESOURCE.'/.default',
            ]),
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            $timeoutSeconds,
        ));
    }

    protected function fetch(): HttpResponse
    {
        return ($this->fetch)();
    }
}
