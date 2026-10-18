# Live check against an AWS KMS emulator

[moto](https://github.com/getmoto/moto) emulates AWS KMS. The smoke test:

1. creates `SIGN_VERIFY` keys `RSA_2048`, `RSA_3072`, `ECC_NIST_P256` and
   `ECC_NIST_P384` with aliases in the emulator;
2. issues a certificate for each key's public key (`GetPublicKey`) from a
   throwaway root;
3. signs a PDF through `AwsKmsSigner` by alias and validates it with php-pdf's
   `SignatureValidator` and poppler's `pdfsig`;
4. checks the error for an unknown alias.

```bash
docker compose -f docker/compose.yml run --rm --build php bash docker/smoke/run.sh
docker compose -f docker/compose.yml down
```

The signed PDFs land in `docker/dist/out/` (ignored by git).

moto does not implement `MessageType: DIGEST` — it hashes the digest once
more — so the smoke test signs with `sendDigest: false` (the signed
attributes go as a `RAW` message and KMS hashes them). Real AWS KMS supports
both.

Expected output:

```
RSA_2048       RSASSA_PKCS1_V1_5_SHA_256 | sha256 | valid=true errors=[]
RSA_3072       RSASSA_PKCS1_V1_5_SHA_256 | sha256 | valid=true errors=[]
ECC_NIST_P256  ECDSA_SHA_256 | sha256 | valid=true errors=[]
ECC_NIST_P384  ECDSA_SHA_384 | sha384 | valid=true errors=[]
missing key    ok: AWS KMS: signing with alias/missing failed — no such key or alias in this account and region (…)
aws-ECC_NIST_P256.pdf: Signature Validation: Signature is Valid.
aws-ECC_NIST_P384.pdf: Signature Validation: Signature is Valid.
aws-RSA_2048.pdf: Signature Validation: Signature is Valid.
aws-RSA_3072.pdf: Signature Validation: Signature is Valid.
```

LocalStack is not used: its current image needs an account token.
