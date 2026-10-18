<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Aws;

use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Certificate;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdfCloudKms\KmsException;
use Dskripchenko\PhpPdfCloudKms\KmsSigner;

/**
 * Signs PDFs with an asymmetric AWS KMS key (`SIGN_VERIFY`, RSA or ECC
 * NIST). php-pdf computes the digest; KMS signs it (`MessageType: DIGEST`),
 * so the document never leaves your process and the key never leaves KMS.
 *
 * ```php
 * $signer = AwsKmsSigner::create('alias/pdf-signing', $certificatePem, region: 'eu-central-1');
 * $pdf = PdfSigner::fromBytes($pdf)->sign(new SignatureConfig(signer: $signer));
 * ```
 *
 * Needs aws/aws-sdk-php; credentials come from the SDK's default chain
 * (environment, profile, ECS/EC2 role, IRSA) unless the client is built
 * otherwise.
 */
final class AwsKmsSigner extends KmsSigner
{
    /** The most KMS takes as a `RAW` message. */
    private const RAW_LIMIT = 4096;

    /**
     * @param  string  $keyId  Key id, ARN, alias name (`alias/…`) or alias ARN.
     * @param  list<string>|string  $chainPem
     * @param  bool  $sendDigest  True sends the digest (`MessageType: DIGEST`). False sends the
     *                            signed attributes themselves (`RAW`, up to 4 KB) for KMS to hash —
     *                            for emulators without `DIGEST`, such as moto.
     */
    public function __construct(
        private readonly KmsClient $client,
        private readonly string $keyId,
        Certificate|string $certificatePem,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
        private readonly bool $sendDigest = true,
    ) {
        parent::__construct($certificatePem, $chainPem, $digest);
    }

    /**
     * With a client for the region and the SDK's default credentials.
     *
     * @param  list<string>|string  $chainPem
     * @param  array<string, mixed>  $clientOptions  Extra `KmsClient` options: `credentials`, `endpoint`, `http`…
     */
    public static function create(
        string $keyId,
        Certificate|string $certificatePem,
        string $region,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
        array $clientOptions = [],
        bool $sendDigest = true,
    ): self {
        if (! class_exists(KmsClient::class)) {
            throw new KmsException('AwsKmsSigner needs the AWS SDK: composer require aws/aws-sdk-php');
        }

        return new self(new KmsClient(['region' => $region, 'version' => '2014-11-01'] + $clientOptions), $keyId, $certificatePem, $chainPem, $digest, $sendDigest);
    }

    /** The KMS signing algorithm for the key type and digest: `RSASSA_PKCS1_V1_5_SHA_256`, `ECDSA_SHA_384`… */
    public function signingAlgorithm(): string
    {
        return ($this->isEc() ? 'ECDSA_SHA_' : 'RSASSA_PKCS1_V1_5_SHA_').$this->shaBits();
    }

    public function sign(string $data): string
    {
        if ($this->sendDigest) {
            return parent::sign($data);
        }
        if (strlen($data) > self::RAW_LIMIT) {
            throw new KmsException('AWS KMS: the signed attributes are '.strlen($data).' bytes, over the 4096 a RAW message may have — use sendDigest: true');
        }

        return $this->verified($data, $this->call($data, 'RAW'));
    }

    protected function signDigest(string $digest): string
    {
        return $this->call($digest, 'DIGEST');
    }

    private function call(string $message, string $type): string
    {
        try {
            $result = $this->client->sign([
                'KeyId' => $this->keyId,
                'Message' => $message,
                'MessageType' => $type,
                'SigningAlgorithm' => $this->signingAlgorithm(),
            ]);
        } catch (AwsException $e) {
            throw new KmsException(
                'AWS KMS: signing with '.$this->keyId.' failed — '.self::explain($e),
                $e->getStatusCode(),
                $e->getAwsErrorCode(),
                $e,
            );
        }
        $signature = $result['Signature'] ?? null;
        if (! is_string($signature) || $signature === '') {
            throw new KmsException('AWS KMS: the response has no signature');
        }

        // KMS returns ECDSA already DER-encoded, as CMS carries it.
        return $signature;
    }

    private static function explain(AwsException $e): string
    {
        $message = (string) ($e->getAwsErrorMessage() ?: $e->getMessage());

        return match ($e->getAwsErrorCode()) {
            'AccessDeniedException' => 'access denied: the caller needs kms:Sign on the key ('.$message.')',
            'NotFoundException' => 'no such key or alias in this account and region ('.$message.')',
            'DisabledException', 'KMSInvalidStateException' => 'the key is disabled or pending deletion ('.$message.')',
            'InvalidKeyUsageException' => 'the key is not a SIGN_VERIFY key, or does not support '.$message,
            default => ($e->getAwsErrorCode() !== null ? $e->getAwsErrorCode().': ' : '').$message,
        };
    }
}
