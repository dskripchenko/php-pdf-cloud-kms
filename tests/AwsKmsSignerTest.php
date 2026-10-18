<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests;

use Aws\CommandInterface;
use Aws\Kms\Exception\KmsException as AwsKmsException;
use Aws\Kms\KmsClient;
use Aws\MockHandler;
use Aws\Result;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\Prehash;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\SignsPdfs;
use Dskripchenko\PhpPdfCloudKms\Tests\Support\TestPki;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

final class AwsKmsSignerTest extends TestCase
{
    use SignsPdfs;

    /** @var list<array<string, mixed>> */
    private array $calls = [];

    private function client(string $keyPem): KmsClient
    {
        $mock = new MockHandler;
        $mock->append(function (CommandInterface $command) use ($keyPem): Result {
            $this->calls[] = $command->toArray();

            return new Result(['Signature' => Prehash::sign($keyPem, $command['Message']), 'KeyId' => 'arn:aws:kms:…', 'SigningAlgorithm' => $command['SigningAlgorithm']]);
        });

        return new KmsClient(['region' => 'eu-central-1', 'version' => '2014-11-01', 'handler' => $mock, 'credentials' => ['key' => 'k', 'secret' => 's']]);
    }

    #[Test]
    #[TestWith(['rsa', 'RSASSA_PKCS1_V1_5_SHA_256'])]
    #[TestWith(['ec', 'ECDSA_SHA_256'])]
    public function signs_a_pdf_with_the_kms_key(string $type, string $algorithm): void
    {
        $pki = TestPki::get($type);
        $signer = new AwsKmsSigner($this->client($pki['keyPem']), 'alias/pdf', $pki['certPem']);

        self::assertSignsValidPdf($signer, $type);
        self::assertCount(1, $this->calls);
        self::assertSame('alias/pdf', $this->calls[0]['KeyId']);
        self::assertSame('DIGEST', $this->calls[0]['MessageType']);
        self::assertSame($algorithm, $this->calls[0]['SigningAlgorithm']);
        self::assertSame(32, strlen($this->calls[0]['Message']));
    }

    #[Test]
    public function the_algorithm_follows_the_digest(): void
    {
        $signer = new AwsKmsSigner($this->client(TestPki::get('rsa')['keyPem']), 'k', TestPki::get('rsa')['certPem'], digest: DigestAlgorithm::Sha384);

        self::assertSame('RSASSA_PKCS1_V1_5_SHA_384', $signer->signingAlgorithm());
        self::assertSignsValidPdf($signer, 'rsa');
    }

    #[Test]
    public function raw_mode_sends_the_signed_attributes_for_kms_to_hash(): void
    {
        $pki = TestPki::get('ec');
        $mock = new MockHandler;
        $mock->append(function (CommandInterface $command) use ($pki): Result {
            $this->calls[] = $command->toArray();
            openssl_sign($command['Message'], $signature, $pki['keyPem'], 'sha256');

            return new Result(['Signature' => $signature]);
        });
        $client = new KmsClient(['region' => 'eu-central-1', 'version' => '2014-11-01', 'handler' => $mock, 'credentials' => ['key' => 'k', 'secret' => 's']]);

        self::assertSignsValidPdf(new AwsKmsSigner($client, 'k', $pki['certPem'], sendDigest: false), 'ec');
        self::assertSame('RAW', $this->calls[0]['MessageType']);
        self::assertGreaterThan(32, strlen($this->calls[0]['Message']));
    }

    #[Test]
    public function access_denied_names_the_permission(): void
    {
        $mock = new MockHandler;
        $mock->append(static fn (CommandInterface $command): AwsKmsException => new AwsKmsException('denied', $command, [
            'code' => 'AccessDeniedException', 'message' => 'User is not authorized to perform: kms:Sign', 'response' => null,
        ]));
        $client = new KmsClient(['region' => 'eu-central-1', 'version' => '2014-11-01', 'handler' => $mock, 'credentials' => ['key' => 'k', 'secret' => 's']]);
        $signer = new AwsKmsSigner($client, 'alias/pdf', TestPki::get('rsa')['certPem']);

        try {
            $signer->sign('data');
            self::fail('No exception');
        } catch (KmsException $e) {
            self::assertSame('AccessDeniedException', $e->errorCode);
            self::assertStringContainsString('kms:Sign', $e->getMessage());
        }
    }
}
