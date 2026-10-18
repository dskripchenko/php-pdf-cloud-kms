#!/usr/bin/env bash
# Signs PDFs through AwsKmsSigner with RSA and EC keys created in an AWS KMS
# emulator, and validates them with php-pdf and poppler's pdfsig.
set -euo pipefail

OUT="${OUT:-/app/docker/dist/out}"
mkdir -p "$OUT"
cd /app
composer update --no-interaction --no-progress -q
OUT="$OUT" php docker/smoke/aws.php
for f in "$OUT"/aws-*.pdf; do
    printf '%s: ' "$(basename "$f")"
    pdfsig "$f" 2>/dev/null | grep -E 'Signature Validation' | sed 's/^ *- //'
done
