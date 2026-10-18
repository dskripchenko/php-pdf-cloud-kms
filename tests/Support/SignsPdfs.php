<?php

declare(strict_types=1);

namespace Dskripchenko\PhpPdfCloudKms\Tests\Support;

use Dskripchenko\PhpPdf\Pdf\Document;
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\Signature\Signer\Signer;
use Dskripchenko\PhpPdf\Pdf\Signature\Validation\SignatureValidator;
use Dskripchenko\PhpPdf\Pdf\Signature\Validation\TrustStore;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;

trait SignsPdfs
{
    /** Signs a one-page PDF and asserts it validates against the test root. */
    private static function assertSignsValidPdf(Signer $signer, string $type): void
    {
        $doc = Document::new();
        $doc->addPage();
        $pdf = PdfSigner::fromBytes($doc->toBytes())->sign(new SignatureConfig(signer: $signer));

        $report = SignatureValidator::fromBytes($pdf)->validate(TrustStore::fromPem(TestPki::get($type)['rootPem']));
        self::assertTrue($report->allValid(), implode('; ', $report->signatures[0]->errors ?? []));
    }
}
