# Security reporting

Report suspected vulnerabilities privately to info@nextquest.cloud. Include the affected component, impact, and reproducible steps with sensitive data removed. Do not put exploit details, credentials, or customer data in public issues.

There is no published response SLA yet. Critical reports should clearly identify their severity in the subject. Rotate exposed credentials at their issuing service and notify the organization owner.

## Development baseline

Use least-privilege credentials, environment-specific configuration, immutable action versions, and reviewed dependency updates. Never commit secrets or Terraform state. Store deployment credentials in the target repository environment after access controls are configured; prefer short-lived OIDC credentials when the deployment provider is chosen.

## Credential-file hygiene

CI checks the tracked HEAD snapshot for environment files (except `.env.example`, `.env.sample`, and `.env.template`), SSH private-key filenames, PKCS#12 containers, Terraform state, AWS credential files, and private-key headers. It reports paths and reasons without printing matching contents. Templates must contain placeholders only.

This narrow check does not scan full history or detect all tokens, passwords, or confidential data. It supplements human review; it is not a comprehensive secret scanner or push protection. If a credential was committed, rotate/revoke it at the provider even after removing it, and assess history cleanup with the owner.
