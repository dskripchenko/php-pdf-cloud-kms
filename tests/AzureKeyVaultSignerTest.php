<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdfCloudKms\Azure\AzureKeyVaultSigner;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\FakeHttp;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\Prehash;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\SignsPdfs;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\TestPki;
use Dskripchenko\PhpPdfCloudKms\Token\CallbackToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class AzureKeyVaultSignerTest extends TestCase
{
    use SignsPdfs;

    private const VAULT = 'https://my-vault.vault.azure.net';

    private const KID = self::VAULT.'/keys/pdf/0123abcd';

    /** Key Vault as the REST API answers: base64url, ECDSA as r ‖ s. */
    private static function vault(string $type): FakeHttp
    {
        $pki = TestPki::get($type);

        return new FakeHttp(static function (string $method, string $url, ?string $body) use ($pki, $type): HttpResponse {
            if ($method === 'GET') {
                return FakeHttp::json(['id' => self::VAULT.'/certificates/pdf-signing/9f', 'kid' => self::KID, 'cer' => base64_encode(TestPki::der($pki['certPem']))]);
            }
            $request = json_decode((string) $body, true);
            $digest = (string) base64_decode(strtr($request['value'], '-_', '+/'), true);
            $signature = Prehash::sign($pki['keyPem'], $digest);
            if ($type === 'ec') {
                $signature = Prehash::derToRaw($signature, 32);
            }

            return FakeHttp::json(['kid' => self::KID, 'value' => rtrim(strtr(base64_encode($signature), '+/', '-_'), '=')]);
        });
    }

    #[Test]
    #[TestWith(['rsa', 'RS256'])]
    #[TestWith(['ec', 'ES256'])]
    public function signs_a_pdf_with_a_key_and_a_certificate_kept_elsewhere(string $type, string $alg): void
    {
        $http = self::vault($type);
        $signer = new AzureKeyVaultSigner(self::KID, TestPki::get($type)['certPem'], new CallbackToken(static fn (): string => 'eyJ0'), transport: $http);

        self::assertSame($alg, $signer->algorithm());
        self::assertSignsValidPdf($signer, $type);
        self::assertSame(self::KID.'/sign?api-version=7.4', $http->requests[0]['url']);
        self::assertSame('Bearer eyJ0', $http->requests[0]['headers']['Authorization']);
        self::assertSame($alg, json_decode((string) $http->requests[0]['body'], true)['alg']);
    }

    #[Test]
    public function reads_a_key_vault_certificate_and_signs_with_its_key(): void
    {
        $http = self::vault('ec');
        $signer = AzureKeyVaultSigner::fromCertificate(self::VAULT, 'pdf-signing', new CallbackToken(static fn (): string => 't'), transport: $http);

        self::assertSame('Jane Doe', $signer->certificate()->subjectCommonName());
        self::assertSignsValidPdf($signer, 'ec');
        self::assertSame(self::VAULT.'/certificates/pdf-signing?api-version=7.4', $http->requests[0]['url']);
        self::assertSame(self::KID.'/sign?api-version=7.4', $http->requests[1]['url']);
    }

    #[Test]
    public function forbidden_names_the_permission(): void
    {
        $http = new FakeHttp(static fn (): HttpResponse => FakeHttp::json(['error' => ['code' => 'Forbidden', 'message' => 'The user does not have keys sign permission']], 403));
        $signer = new AzureKeyVaultSigner(self::KID, TestPki::get('rsa')['certPem'], new CallbackToken(static fn (): string => 't'), transport: $http);

        try {
            $signer->sign('data');
            self::fail('No exception');
        } catch (KmsException $e) {
            self::assertSame(403, $e->status);
            self::assertSame('Forbidden', $e->errorCode);
            self::assertStringContainsString('Key Vault Crypto User', $e->getMessage());
        }
    }
}
