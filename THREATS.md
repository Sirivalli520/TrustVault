# TrustVault threat model

## Assets
- Confidential document contents and metadata
- User credentials and session cookies
- Document permission grants
- Audit history and administrative user list

## Trust boundaries
1. Browser ↔ Flask application
2. Authenticated user ↔ each individual document
3. Flask application ↔ SQLite database and upload directory
4. Administrator ↔ ordinary owner/viewer accounts

## Threats and mitigations

| Threat | Mitigation in this prototype | Residual risk / next step |
|---|---|---|
| Unauthenticated user reads a document | Authenticated routes and server-side checks | Login redirect behavior should be standardized |
| User guesses another document ID (IDOR) | Every document route calls document-level authorization | Add dedicated tests for every route and fuzz route IDs |
| Viewer self-promotes to admin | Public registration accepts only owner/viewer | Admin provisioning currently uses environment variables at first DB initialization |
| Password database leak | Werkzeug password hashes, not plaintext | Add rate limiting, MFA, password reset workflow |
| Path traversal / overwrite | `secure_filename`, random stored name, storage path controlled by app | Keep upload directory outside public web root and use least-privilege OS permissions |
| Oversized upload | Flask request limit plus stream size check | Reverse proxy limits and quotas are also needed |
| Malicious file content | Extension allowlist | No MIME sniffing, antivirus, sandboxing, or content disarm/reconstruction |
| SQL injection | Parameterized SQL queries | Continue parameterizing all future queries |
| Cross-site scripting | Jinja autoescaping; CSP header | Carefully review any future unsafe HTML rendering |
| CSRF changes permissions or deletes a file | Not fully mitigated | **Known gap:** add CSRF tokens to every state-changing form before deployment |
| Audit tampering | App records important actions and admin can view logs | SQLite owner can alter logs; use append-only remote logging/WORM storage for stronger assurance |
| Session theft | HttpOnly, SameSite=Lax cookies | Enable Secure over HTTPS; consider short expiry and rotation policy |
| Data loss | Database and file storage separated | No automated backups or recovery test implemented |
| Unauthorized access after revocation | Access check consults current grants on every request | Already-issued downloaded copies cannot be revoked |
| Concurrent writes / operational load | SQLite for a small demo | Use PostgreSQL and a tested migration strategy for larger deployments |

## Security testing plan
- Create two unrelated accounts and ensure one cannot open, download, edit, delete, or change permissions on the other's document.
- Grant read-only access and verify read/download succeeds but metadata edit fails.
- Revoke access and verify subsequent requests fail.
- Attempt registration with `role=admin`.
- Upload disallowed extensions, empty files, and files above the size limit.
- Verify admin route returns 403 to non-admin users.
- Verify audit entries for upload, download, edit, delete, grant, and revoke.

## Scope statement
This is a learning/challenge prototype, not a formal security audit. No penetration test, dependency audit, malware scan, production deployment review, or independent cryptographic review has been performed.
