<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests\Support;

/** A throwaway root and signers, made with the openssl extension once per run. */
final class TestPki
{
    /** @var array<string, array{rootPem: string, certPem: string, keyPem: string}> */
    private static array $made = [];

    /**
     * @param  'rsa'|'ec'  $type
     * @return array{rootPem: string, certPem: string, keyPem: string}
     */
    public static function get(string $type = 'rsa'): array
    {
        if (isset(self::$made[$type])) {
            return self::$made[$type];
        }
        $rootConfig = ['digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $config = $type === 'ec'
            ? ['digest_alg' => 'sha256', 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : $rootConfig;

        $rootKey = openssl_pkey_new($rootConfig) ?: throw new \RuntimeException('root key');
        $rootCsr = openssl_csr_new(['commonName' => 'Test Root'], $rootKey, $rootConfig) ?: throw new \RuntimeException('csr');
        $root = openssl_csr_sign($rootCsr, null, $rootKey, 30, $rootConfig + ['x509_extensions' => 'v3_ca'], 1) ?: throw new \RuntimeException('root');

        $key = openssl_pkey_new($config) ?: throw new \RuntimeException('key');
        $csr = openssl_csr_new(['commonName' => 'Jane Doe', 'organizationName' => 'Example Ltd'], $key, $config) ?: throw new \RuntimeException('csr');
        $cert = openssl_csr_sign($csr, $root, $rootKey, 30, $rootConfig + ['x509_extensions' => 'usr_cert'], 2) ?: throw new \RuntimeException('cert');

        openssl_x509_export($root, $rootPem);
        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem);

        return self::$made[$type] = ['rootPem' => $rootPem, 'certPem' => $certPem, 'keyPem' => $keyPem];
    }

    public static function der(string $pem): string
    {
        return (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem), true);
    }
}
