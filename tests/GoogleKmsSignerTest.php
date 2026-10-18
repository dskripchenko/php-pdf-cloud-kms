<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests;

use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdfCloudKms\Google\GoogleKmsSigner;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\FakeHttp;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\Prehash;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\SignsPdfs;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\TestPki;
use Dskripchenko\PhpPdfCloudKms\Token\CallbackToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class GoogleKmsSignerTest extends TestCase
{
    use SignsPdfs;

    private const VERSION = 'projects/p/locations/global/keyRings/r/cryptoKeys/pdf/cryptoKeyVersions/1';

    /** Cloud KMS as the REST API answers: the signature over the digest sent. */
    private static function kms(string $keyPem): FakeHttp
    {
        return new FakeHttp(static function (string $method, string $url, ?string $body) use ($keyPem): HttpResponse {
            $request = json_decode((string) $body, true);
            $digest = base64_decode((string) current($request['digest']), true);

            return FakeHttp::json([
                'signature' => base64_encode(Prehash::sign($keyPem, (string) $digest)),
                'verifiedDigestCrc32c' => $request['digestCrc32c'] === (string) hexdec(hash('crc32c', (string) $digest)),
                'name' => self::VERSION,
            ]);
        });
    }

    #[Test]
    #[TestWith(['rsa'])]
    #[TestWith(['ec'])]
    public function signs_a_pdf_with_the_key_version(string $type): void
    {
        $pki = TestPki::get($type);
        $http = self::kms($pki['keyPem']);
        $signer = new GoogleKmsSigner(self::VERSION, $pki['certPem'], new CallbackToken(static fn (): string => 'ya29.token'), transport: $http);

        self::assertSignsValidPdf($signer, $type);
        self::assertCount(1, $http->requests);
        $request = $http->requests[0];
        self::assertSame('https://cloudkms.googleapis.com/v1/'.self::VERSION.':asymmetricSign', $request['url']);
        self::assertSame('Bearer ya29.token', $request['headers']['Authorization']);
        self::assertSame(['sha256'], array_keys(json_decode((string) $request['body'], true)['digest']));
    }

    #[Test]
    public function the_digest_field_follows_the_digest(): void
    {
        $pki = TestPki::get('rsa');
        $http = self::kms($pki['keyPem']);
        $signer = new GoogleKmsSigner(self::VERSION, $pki['certPem'], new CallbackToken(static fn (): string => 't'), digest: DigestAlgorithm::Sha512, transport: $http);

        self::assertSignsValidPdf($signer, 'rsa');
        self::assertSame(['sha512'], array_keys(json_decode((string) $http->requests[0]['body'], true)['digest']));
    }

    #[Test]
    public function a_permission_error_says_which_role_is_missing(): void
    {
        $http = new FakeHttp(static fn (): HttpResponse => FakeHttp::json(['error' => [
            'code' => 403, 'status' => 'PERMISSION_DENIED', 'message' => "Permission 'cloudkms.cryptoKeyVersions.useToSign' denied",
        ]], 403));
        $signer = new GoogleKmsSigner(self::VERSION, TestPki::get('rsa')['certPem'], new CallbackToken(static fn (): string => 't'), transport: $http);

        try {
            $signer->sign('data');
            self::fail('No exception');
        } catch (KmsException $e) {
            self::assertSame(403, $e->status);
            self::assertSame('PERMISSION_DENIED', $e->errorCode);
            self::assertStringContainsString('roles/cloudkms.signer', $e->getMessage());
        }
    }

    #[Test]
    public function a_digest_damaged_on_the_way_is_refused(): void
    {
        $http = new FakeHttp(static fn (): HttpResponse => FakeHttp::json(['signature' => base64_encode('x'), 'verifiedDigestCrc32c' => false]));
        $signer = new GoogleKmsSigner(self::VERSION, TestPki::get('rsa')['certPem'], new CallbackToken(static fn (): string => 't'), transport: $http);

        $this->expectExceptionMessage('CRC32C');
        $signer->sign('data');
    }

    #[Test]
    public function a_key_that_does_not_match_the_certificate_is_caught(): void
    {
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) ?: throw new \RuntimeException('key');
        openssl_pkey_export($other, $otherPem);
        $signer = new GoogleKmsSigner(self::VERSION, TestPki::get('rsa')['certPem'], new CallbackToken(static fn (): string => 't'), transport: self::kms($otherPem));

        $this->expectException(KmsException::class);
        $this->expectExceptionMessage('does not verify against the certificate');
        $signer->sign('data');
    }
}
