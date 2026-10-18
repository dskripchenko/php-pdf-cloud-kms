<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms;

use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Certificate;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\DigestAlgorithm;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\KeyType;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Signer;

/**
 * What the cloud signers share: the certificate and chain, the digest, and
 * a check of the returned signature against the certificate. A subclass
 * only sends the digest to its service.
 */
abstract class KmsSigner implements Signer
{
    protected readonly Certificate $certificate;

    /** @var list<Certificate> */
    private readonly array $chain;

    protected readonly DigestAlgorithm $digest;

    /**
     * @param  string  $certificatePem  The certificate issued for the KMS key's public key.
     * @param  list<string>|string  $chainPem  Intermediate certificates — a PEM bundle or a list of them.
     */
    public function __construct(
        Certificate|string $certificatePem,
        array|string $chainPem = [],
        ?DigestAlgorithm $digest = null,
    ) {
        $this->certificate = $certificatePem instanceof Certificate ? $certificatePem : Certificate::fromPem($certificatePem);
        if (! in_array($this->certificate->keyType(), [KeyType::Rsa, KeyType::Ec], true)) {
            throw new KmsException('Cloud KMS signs with RSA and EC keys; the certificate holds a '.$this->certificate->keyType()->name.' key');
        }
        $chain = [];
        foreach (is_string($chainPem) ? [$chainPem] : $chainPem as $bundle) {
            array_push($chain, ...Certificate::allFromPem($bundle));
        }
        $this->chain = $chain;
        $this->digest = $digest ?? DigestAlgorithm::defaultFor($this->certificate);
        if ($this->digest->isGost()) {
            throw new KmsException('Cloud KMS does not support GOST digests');
        }
    }

    /**
     * Sends the digest to the service and returns the signature as CMS
     * carries it: PKCS#1 v1.5 for RSA, a DER `ECDSA-Sig-Value` for EC.
     */
    abstract protected function signDigest(string $digest): string;

    public function certificate(): Certificate
    {
        return $this->certificate;
    }

    public function chain(): array
    {
        return $this->chain;
    }

    public function digestAlgorithm(): DigestAlgorithm
    {
        return $this->digest;
    }

    public function sign(string $data): string
    {
        return $this->verified($data, $this->signDigest($this->digest->digest($data)));
    }

    /** The signature, once it verifies against the certificate. */
    protected function verified(string $data, string $signature): string
    {
        // A key that does not belong to the certificate would make a PDF
        // that no reader accepts; say so here instead.
        if (openssl_verify($data, $signature, $this->certificate->publicKey(), $this->digest->opensslName()) !== 1) {
            throw new KmsException('The signature from the KMS does not verify against the certificate — the key does not belong to it, or the key\'s algorithm uses another digest (pass digest:)');
        }

        return $signature;
    }

    protected function isEc(): bool
    {
        return $this->certificate->keyType() === KeyType::Ec;
    }

    /** "256", "384" or "512" — the SHA-2 size, as the services name algorithms. */
    protected function shaBits(): string
    {
        return substr($this->digest->value, 3);
    }
}
