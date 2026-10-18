<?php

declare(strict_types=1);

// Creates SIGN_VERIFY keys in the KMS at $KMS_ENDPOINT, issues a
// certificate for each public key from a throwaway root, signs a PDF with
// AwsKmsSigner and validates it. moto has no MessageType DIGEST, so the
// signer sends the signed attributes (sendDigest: false).

require __DIR__.'/../../vendor/autoload.php';

use Aws\Kms\KmsClient;
use Dskripchenko\PhpPdf\Pdf\Document;
use Dskripchenko\PhpPdf\Pdf\Signature\Appearance\SignatureAppearance;
use Dskripchenko\PhpPdf\Pdf\Signature\PdfSigner;
use Dskripchenko\PhpPdf\Pdf\Signature\Validation\SignatureValidator;
use Dskripchenko\PhpPdf\Pdf\Signature\Validation\TrustStore;
use Dskripchenko\PhpPdf\Pdf\SignatureConfig;
use Dskripchenko\PhpPdfCloudKms\Aws\AwsKmsSigner;
use Dskripchenko\PhpPdfCloudKms\KmsException;

$out = (string) getenv('OUT');
$client = new KmsClient([
    'region' => 'eu-central-1',
    'version' => '2014-11-01',
    'endpoint' => (string) getenv('KMS_ENDPOINT'),
    'credentials' => ['key' => 'test', 'secret' => 'test'],
]);

$work = sys_get_temp_dir().'/kms-smoke';
@mkdir($work);
run("openssl req -x509 -newkey rsa:2048 -nodes -keyout $work/root.key -out $work/root.pem -days 30 -subj '/CN=Smoke Root'");
run("openssl req -new -newkey rsa:2048 -nodes -keyout $work/throwaway.key -out $work/req.csr -subj '/CN=Smoke'");
$trust = TrustStore::fromPem((string) file_get_contents("$work/root.pem"));

$doc = Document::new();
$doc->addPage();
$pdf = $doc->toBytes();
$failed = false;

foreach (['RSA_2048', 'RSA_3072', 'ECC_NIST_P256', 'ECC_NIST_P384'] as $spec) {
    try {
        $keyId = $client->createKey(['KeySpec' => $spec, 'KeyUsage' => 'SIGN_VERIFY'])['KeyMetadata']['KeyId'];
        $client->createAlias(['AliasName' => 'alias/pdf-'.strtolower($spec), 'TargetKeyId' => $keyId]);

        // The certificate takes the KMS public key; the CSR is only a carrier.
        $public = $client->getPublicKey(['KeyId' => $keyId])['PublicKey'];
        file_put_contents("$work/$spec.pub.pem", "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($public), 64, "\n")."-----END PUBLIC KEY-----\n");
        run("openssl x509 -req -in $work/req.csr -CA $work/root.pem -CAkey $work/root.key -CAcreateserial -days 30 -force_pubkey $work/$spec.pub.pem -subj '/CN=Smoke $spec/O=Example Ltd' -out $work/$spec.pem");

        $signer = new AwsKmsSigner($client, 'alias/pdf-'.strtolower($spec), (string) file_get_contents("$work/$spec.pem"), sendDigest: false);
        $signed = PdfSigner::fromBytes($pdf)
            ->addField('signature', page: 0, x: 60, y: 60, width: 250, height: 75, appearance: SignatureAppearance::simple())
            ->sign(new SignatureConfig(signer: $signer, reason: 'smoke'));
        file_put_contents("$out/aws-$spec.pdf", $signed);

        $s = SignatureValidator::fromBytes($signed)->validate($trust)->signatures[0];
        printf("%-14s %s | %s | valid=%s errors=%s\n", $spec, $signer->signingAlgorithm(), $signer->digestAlgorithm()->value, var_export($s->isValid(), true), json_encode($s->errors));
        $failed = $failed || ! $s->isValid();
    } catch (Throwable $e) {
        printf("%-14s FAILED %s: %s\n", $spec, $e::class, $e->getMessage());
        $failed = true;
    }
}

// The error for an unknown key.
try {
    (new AwsKmsSigner($client, 'alias/missing', (string) file_get_contents("$work/RSA_2048.pem"), sendDigest: false))->sign('data');
    echo "missing key    FAILED: no error\n";
    $failed = true;
} catch (KmsException $e) {
    printf("%-14s ok: %s\n", 'missing key', $e->getMessage());
}

exit($failed ? 1 : 0);

function run(string $command): void
{
    exec($command.' 2>&1', $output, $code);
    if ($code !== 0) {
        throw new RuntimeException($command.': '.implode("\n", $output));
    }
}
