# Implementation status

This file intentionally separates implemented behavior from known gaps. Update it after running the tests and checking the app in your own environment.

## Implemented in source
- Flask app factory and SQLite schema
- Password hashing and login/logout
- Owner/viewer registration; admin provisioning through environment variables
- Upload validation for allowed extensions, non-empty files, and request size
- Opaque randomized stored filenames
- Per-document owner and named-user permission checks
- Read-only and read/edit grants; owner can revoke grants
- Document list search by filename, description, owner, category, and date
- Metadata editing, deletion, and download
- Audit events for upload, download, metadata edit, delete, permission grant/revoke
- Admin-only audit and user dashboard
- Security response headers
- Automated tests for core authorization and feature paths

## Known gaps / unfinished
- CSRF protection is not implemented
- No password reset, email verification, MFA, login rate limiting, or account lockout
- No antivirus, MIME/content inspection, file preview sandbox, or quota enforcement per user
- Audit logs are not tamper-evident and do not record every failed access attempt
- Admin role is configured at initial database creation; no UI to manage users/roles
- No pagination for document lists; admin view displays latest 500 audit records
- No production deployment manifest, HTTPS configuration, backup/restore automation, or monitoring
- Tests are a starter suite and do not yet test every route/edge case
- Viewer accounts can upload in the current prototype; decide whether this should be permitted and enforce the chosen policy consistently
- File content replacement/version history is not implemented; “edit” means metadata only

## Before submission
1. Run `python -m pytest -q` and record the real result.
2. Start the app and complete the demo walkthrough.
3. Replace example AI prompts in `PROMPTS.md` with your actual prompt history.
4. Do not claim the unfinished items are implemented.
5. Be prepared to explain and fix a small issue live.
