<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Token;

/**
 * Where a REST signer gets its OAuth bearer token. Implementations cache
 * the token until shortly before it expires.
 */
interface AccessToken
{
    public function token(): string;
}
