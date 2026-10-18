<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureToken;
use Dskripchenko\PhpPdfCloudKms\EcdsaSignature;
use Dskripchenko\PhpPdfCloudKms\Google\GoogleToken;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\FakeHttp;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\Prehash;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\TestPki;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    private static function issuing(string $token = 'tok'): FakeHttp
    {
        return new FakeHttp(static fn (): HttpResponse => FakeHttp::json(['access_token' => $token, 'expires_in' => 3599, 'token_type' => 'Bearer']));
    }

    #[Test]
    public function a_google_service_account_exchanges_a_signed_jwt(): void
    {
        $pki = TestPki::get('rsa');
        $http = self::issuing();
        $token = GoogleToken::fromServiceAccountJson((string) json_encode([
            'type' => 'service_account', 'client_email' => 'pdf@p.iam.gserviceaccount.com', 'private_key' => $pki['keyPem'],
        ]), $http);

        self::assertSame('tok', $token->token());
        self::assertSame('tok', $token->token(), 'Cached');
        self::assertCount(1, $http->requests);

        $request = $http->requests[0];
        self::assertSame('https://oauth2.googleapis.com/token', $request['url']);
        parse_str((string) $request['body'], $form);
        self::assertSame('urn:ietf:params:oauth:grant-type:jwt-bearer', $form['grant_type']);
        [$header, $claims, $signature] = explode('.', (string) $form['assertion']);
        $decode = static fn (string $s): string => (string) base64_decode(strtr($s, '-_', '+/'), true);
        self::assertSame(1, openssl_verify("$header.$claims", $decode($signature), openssl_pkey_get_public($pki['certPem']) ?: '', OPENSSL_ALGO_SHA256));
        $claims = json_decode($decode($claims), true);
        self::assertSame('pdf@p.iam.gserviceaccount.com', $claims['iss']);
        self::assertSame(GoogleToken::SCOPE, $claims['scope']);
    }

    #[Test]
    public function the_google_metadata_server_is_asked_with_its_header(): void
    {
        $http = self::issuing();
        self::assertSame('tok', GoogleToken::fromMetadataServer($http)->token());
        self::assertSame('Google', $http->requests[0]['headers']['Metadata-Flavor']);
    }

    #[Test]
    public function azure_client_credentials_ask_for_the_key_vault_scope(): void
    {
        $http = self::issuing();
        self::assertSame('tok', AzureToken::clientCredentials('tenant-id', 'client-id', 'secret', $http)->token());

        self::assertSame('https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token', $http->requests[0]['url']);
        parse_str((string) $http->requests[0]['body'], $form);
        self::assertSame('https://vault.azure.net/.default', $form['scope']);
        self::assertSame('client_credentials', $form['grant_type']);
    }

    #[Test]
    public function azure_managed_identity_asks_the_instance_metadata_service(): void
    {
        $http = self::issuing();
        self::assertSame('tok', AzureToken::managedIdentity('uami-client-id', $http)->token());

        self::assertStringStartsWith('http://169.254.169.254/metadata/identity/oauth2/token?', $http->requests[0]['url']);
        self::assertStringContainsString('client_id=uami-client-id', $http->requests[0]['url']);
        self::assertSame('true', $http->requests[0]['headers']['Metadata']);
    }

    #[Test]
    public function a_refused_token_request_explains_itself(): void
    {
        $http = new FakeHttp(static fn (): HttpResponse => FakeHttp::json(['error' => 'invalid_client', 'error_description' => 'AADSTS7000215: Invalid client secret provided.'], 401));

        try {
            AzureToken::clientCredentials('t', 'c', 'wrong', $http)->token();
            self::fail('No exception');
        } catch (KmsException $e) {
            self::assertSame(401, $e->status);
            self::assertSame('invalid_client', $e->errorCode);
            self::assertStringContainsString('Invalid client secret', $e->getMessage());
        }
    }

    #[Test]
    public function r_and_s_become_der(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']) ?: throw new \RuntimeException('key');
        for ($i = 0; $i < 30; $i++) {
            openssl_sign('data '.$i, $der, $key, 'sha256');
            self::assertSame(bin2hex($der), bin2hex(EcdsaSignature::toDer(Prehash::derToRaw($der, 32))));
        }
    }
}
