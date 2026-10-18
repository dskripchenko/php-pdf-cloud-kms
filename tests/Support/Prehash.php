<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests\Support;

/**
 * Signs a digest the way a KMS does — the caller hashed already. RSA with
 * the openssl extension, ECDSA with the openssl command (the extension
 * always hashes its input itself).
 */
final class Prehash
{
    private const DIGEST_INFO = [
        32 => '3031300d060960864801650304020105000420',
        48 => '3041300d060960864801650304020205000430',
        64 => '3051300d060960864801650304020305000440',
    ];

    /** PKCS#1 v1.5 for RSA, DER `ECDSA-Sig-Value` for EC. */
    public static function sign(string $keyPem, string $digest): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private($keyPem) ?: throw new \RuntimeException('key')) ?: [];
        if (($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
            openssl_private_encrypt((string) hex2bin(self::DIGEST_INFO[strlen($digest)]).$digest, $signature, $keyPem, OPENSSL_PKCS1_PADDING);

            return $signature;
        }

        $dir = sys_get_temp_dir().'/php-pdf-cloud-kms-'.bin2hex(random_bytes(4));
        mkdir($dir);
        try {
            file_put_contents("$dir/key.pem", $keyPem);
            file_put_contents("$dir/digest", $digest);
            exec(sprintf('openssl pkeyutl -sign -inkey %s -in %s -out %s 2>&1', escapeshellarg("$dir/key.pem"), escapeshellarg("$dir/digest"), escapeshellarg("$dir/sig")), $output, $code);
            if ($code !== 0) {
                throw new \RuntimeException('openssl pkeyutl: '.implode("\n", $output));
            }

            return (string) file_get_contents("$dir/sig");
        } finally {
            array_map('unlink', glob("$dir/*") ?: []);
            rmdir($dir);
        }
    }

    /** DER `ECDSA-Sig-Value` → fixed-width `r ‖ s`, as JWS and Key Vault carry it. */
    public static function derToRaw(string $der, int $width): string
    {
        $offset = 2;
        $raw = '';
        for ($n = 0; $n < 2; $n++) {
            $length = ord($der[$offset + 1]);
            $raw .= str_pad(ltrim(substr($der, $offset + 2, $length), "\x00"), $width, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $raw;
    }
}
