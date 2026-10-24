# AI development prompt log

**Important:** This file is a template/example record. Edit it so it accurately reflects the prompts and tools you actually used during development. Do not claim a prompt was used unless it was.

## Example prompt records

### Prompt 1 — requirements decomposition
> Turn the TrustVault problem statement into a checklist of functional requirements, role definitions, access boundaries, and acceptance tests. Identify ambiguous requirements instead of assuming behavior.

### Prompt 2 — architecture
> Design a small Flask and SQLite application for secure document sharing. Use document-level permissions and check authorization on every read, download, edit, delete, and permission-management endpoint. Explain the trade-offs.

### Prompt 3 — security review
> Review this document-sharing application for IDOR, privilege escalation, unsafe uploads, path traversal, SQL injection, CSRF, session configuration, and audit-log gaps. Suggest specific tests for each finding.

### Prompt 4 — test review
> Write tests with two unrelated users to prove one user cannot access another user's document unless explicitly granted access. Test read-only grants, revocation, and attempts to register as an administrator.

## What I should be able to explain
- Why role-based access alone is insufficient: ownership/grants must be checked per document.
- Why upload filenames are not used as filesystem paths.
- Why a file extension allowlist is helpful but not a malware scanner.
- Why audit logs in the same SQLite database are not tamper-proof.
- Why CSRF protection and HTTPS are required before production use.
