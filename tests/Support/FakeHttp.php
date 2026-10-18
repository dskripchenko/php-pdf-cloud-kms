<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests\Support;

use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpGetTransport;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpResponse;
use Dskripchenko\PhpPdf\Pdf\Signature\Transport\HttpTransport;

/** Answers every request with a handler; records them. */
final class FakeHttp implements HttpGetTransport, HttpTransport
{
    /** @var list<array{method: string, url: string, body: ?string, headers: array<string, string>}> */
    public array $requests = [];

    /** @param  \Closure(string, string, ?string, array<string, string>): HttpResponse  $handler */
    public function __construct(private readonly \Closure $handler) {}

    public function get(string $url, array $headers, float $timeoutSeconds): HttpResponse
    {
        $this->requests[] = ['method' => 'GET', 'url' => $url, 'body' => null, 'headers' => $headers];

        return ($this->handler)('GET', $url, null, $headers);
    }

    public function post(string $url, string $body, array $headers, float $timeoutSeconds): HttpResponse
    {
        $this->requests[] = ['method' => 'POST', 'url' => $url, 'body' => $body, 'headers' => $headers];

        return ($this->handler)('POST', $url, $body, $headers);
    }

    /** @param  array<string, mixed>  $json */
    public static function json(array $json, int $status = 200): HttpResponse
    {
        return new HttpResponse($status, (string) json_encode($json));
    }
}
