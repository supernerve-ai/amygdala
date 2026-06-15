# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x.x   | ✅ Current release |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Amygdala, we appreciate responsible disclosure. Here's how:

### How to Report

1. **Email:** Send a detailed report to **security@supernerve.in** (or [open a private security advisory on GitHub](https://github.com/supernerve-ai/amygdala/security/advisories/new))
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with our assessment
- **Fix timeline** communicated once the issue is validated
- **Credit** in the release notes (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Authentication/authorization bypass in MCP token handling
- Injection vulnerabilities in SPL query construction
- Secrets exposure (tokens, credentials) in logs or output
- Unauthorized access to Splunk data via the agent pipeline
- Container escape or privilege escalation in Docker deployments
- Dependency vulnerabilities with a known exploit path

### Out of Scope

- Denial of service via resource exhaustion (alert flooding)
- Issues in upstream dependencies without a direct exploit in Amygdala
- Social engineering attacks
- Vulnerabilities in Splunk itself (report to Splunk directly)

## Security Best Practices

When deploying Amygdala:

- **Never commit `.env.local`** or any file containing real credentials
- **Rotate Splunk HEC tokens** on a regular cadence
- **Run containers as non-root** in production
- **Use network policies** to restrict MCP server access
- **Enable audit logging** for all Splunk API interactions
- **Pin dependency versions** — review updates before upgrading

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We validate and develop a fix
3. Fix is released with a security advisory
4. Reporter is credited (with consent)
5. Full details published after users have time to upgrade (typically 30 days)

Thank you for helping keep Amygdala and its users safe. 🛡️
