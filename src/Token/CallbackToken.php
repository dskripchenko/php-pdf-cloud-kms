<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Token;

/**
 * A token from your own code — google/auth, an Azure SDK, a secret store:
 *
 * ```php
 * new CallbackToken(fn () => $credentials->fetchAuthToken()['access_token']);
 * ```
 *
 * The callback is called for every signature; cache inside it if needed.
 */
final class CallbackToken implements AccessToken
{
    /** @param  \Closure(): string  $callback */
    public function __construct(private readonly \Closure $callback) {}

    public function token(): string
    {
        return ($this->callback)();
    }
}
