<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms;

/**
 * A failure of a cloud KMS call. `$status` is the HTTP status and
 * `$errorCode` the service's own code (`AccessDeniedException`,
 * `PERMISSION_DENIED`, `Forbidden`…) when there was a response.
 */
final class KmsException extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?int $status = null,
        public readonly ?string $errorCode = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $status ?? 0, $previous);
    }
}
