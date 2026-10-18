<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms;

/**
 * `r ‖ s` (JWS, Azure Key Vault) as the DER `ECDSA-Sig-Value` CMS carries.
 *
 * @internal
 */
final class EcdsaSignature
{
    private function __construct() {}

    public static function toDer(string $raw): string
    {
        $length = strlen($raw);
        if ($length === 0 || $length % 2 !== 0) {
            throw new KmsException('The KMS returned an ECDSA signature of odd length '.$length);
        }
        $half = intdiv($length, 2);
        $body = self::integer(substr($raw, 0, $half)).self::integer(substr($raw, $half));

        return "\x30".self::length(strlen($body)).$body;
    }

    private static function integer(string $magnitude): string
    {
        $magnitude = ltrim($magnitude, "\x00");
        if ($magnitude === '' || (ord($magnitude[0]) & 0x80) !== 0) {
            $magnitude = "\x00".$magnitude;
        }

        return "\x02".self::length(strlen($magnitude)).$magnitude;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)).$bytes;
    }
}
