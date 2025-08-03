# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

MagicRune is a security-focused project, and we take security vulnerabilities seriously.

### Where to Report

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via email to: security@magicrune.dev

### What to Include

When reporting a vulnerability, please include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 60 days

### Disclosure Policy

We follow responsible disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge receipt and begin investigation
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the vulnerability after users have had time to update

## Security Best Practices

When using MagicRune:

1. Always keep MagicRune updated to the latest version
2. Review the audit logs regularly
3. Never disable the `enforce_sandbox` policy for external code
4. Use signature verification for production deployments
5. Monitor the GitHub repository for security announcements

## Scope

The following are in scope for security reports:

- Sandbox escape vulnerabilities
- Policy bypass techniques
- Signature verification weaknesses
- Information disclosure through audit logs
- Privilege escalation within the sandbox

The following are **out of scope**:

- Denial of Service attacks on the sandbox
- Social engineering attacks
- Attacks requiring physical access
- Vulnerabilities in dependencies (report to the dependency maintainer)