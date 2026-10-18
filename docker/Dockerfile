# PHP 8.3 with the openssl command and poppler, to sign and check PDFs
# against an AWS KMS emulator (moto) — see docker/README.md.
FROM php:8.3-cli

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git unzip openssl poppler-utils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

WORKDIR /app
