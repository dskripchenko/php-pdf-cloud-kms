# Security policy

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/dskripchenko/php-pdf-cloud-kms/security/advisories/new)
or by e-mail to denskrp90@gmail.com — not in public issues.

Supported: the latest minor release.

Prefer workload identities (an IAM role, a GCP service account on the
workload, an Azure managed identity) to long-lived secrets. When a secret is
needed — a service account key, a client secret — keep it out of logs and
process arguments; the package passes it only to the token endpoint and
marks it `#[\SensitiveParameter]`. Grant the signing identity only the sign
permission on the one key.
