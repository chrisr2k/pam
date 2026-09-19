# PAM Features Guide

This guide documents every feature of the Privileged Access Manager (PAM):
what it does, how to use it, how to configure it, the audit events it writes,
and its operational gotchas.

**Audience:** PAM administrators (staff/admins), approvers, requesters, auditors,
and operators responsible for deploying and running the system.

---

## 1. Just-in-Time Access (Entra PIM & AWS Identity Center)

The core of PAM: users request temporary elevation to privileged cloud roles,
the request is approved (or auto-approved), access is provisioned to the cloud
provider, and is automatically removed when it expires.

**Supported providers:**

| Provider | Mechanism |
|----------|-----------|
| AWS Identity Center | Account assignments for permission sets (optionally via Entra directory attributes — ABAC) |
| Entra ID PIM | Role assignments via Microsoft Graph `roleAssignments` |
| PAM Vault | Secret checkout (see §6) — rides the same JIT machinery |

**Lifecycle:**

```
PENDING → APPROVED → PROVISIONING → PROVISIONED/ACTIVE → EXPIRED
                                  ↘ FAILED          ↘ REVOKED/EXPIRED (early revoke)
```

**Expiry has four redundant safety nets** — any one suffices:

1. Celery ETA task scheduled at provision time
2. Celery Beat sweep every 5 minutes (`check_expired_sessions`)
3. A per-request middleware sweep (works even if Beat is down)
4. A cron-able management command: `python manage.py check_expired`

**Request duration** is clamped to the role's `max_duration_minutes` on submit
(the user sees a "was reduced" warning). Roles with `requires_approval=False`
skip approval entirely: the request is created directly APPROVED and
provisioned immediately (audit `REQUEST_CREATED` with `auto: true`).

**Users without an Entra object ID** cannot use the cloud providers (their
provisioning fails cleanly with `PROVISIONING_FAILED`) but *can* check out
vault secrets — vault checkout does not require an Entra identity.

---

## 2. Approval Workflows: Quorum & Auto-Approval

### Per-role approval policy

Each role has an `approval_policy`:

| Policy | Meaning |
|--------|---------|
| `ANY_ONE` (default) | The first approver's vote finalizes the request |
| `ALL` | Every current approver of the role must vote |
| `QUORUM` | A fixed number of distinct votes (`quorum_count`) |

- The threshold is computed **at vote time**: `ALL` uses the current approver
  count; `QUORUM` is capped at the approver count, so a request can never
  become unapprovable (e.g. quorum 5 on a role with 2 approvers → 2 required).
- **Partial votes** leave the request PENDING and write
  `APPROVAL_RECORDED`; the requester is notified only when quorum is met
  (`REQUEST_APPROVED`).
- **Duplicate votes** are handled gracefully — an approver who already voted
  sees "You approved this request on …" on the detail page instead of the
  approve form, and any duplicate submission is rejected without error.
- **Deny is immediate**: any approver can deny the whole request regardless of
  quorum (`REQUEST_DENIED`).
- The detail page shows live progress ("**2 of 3 approved**") with a progress
  bar and the policy name.

### Who can approve

**Role membership is the sole authority.** Anyone listed in a role's
`approvers` list can approve requests for that role, regardless of their
PAM-level role (Requester/Approver/Admin/Auditor). Users added as role
approvers automatically become MFA-required (§3).

### Assigning approvers

Role creation and approver assignment happen in the Django admin
(`/pam-admin/roles/privilegedrole/` — Policy fieldset: approvers, approval
policy, quorum count).

---

## 3. Elevation-Time MFA (TOTP)

Time-based one-time passwords protect every elevation action.

**Who must enroll** (`mfa_required`): approvers, admins, staff — **and anyone
listed as a role approver**. Plain requesters may enroll optionally.

**What is challenged:**

| Action | When challenged |
|--------|-----------------|
| Request submit | If the user is enrolled |
| Request approve | If the user is enrolled (required for approvers) |
| Break-glass | Always — mandatory, blocked until enrolled |
| Vault reveal | If the user is enrolled |

Deny and revoke are intentionally *not* challenged.

### Enrollment

Profile → **MFA Setup** (`/accounts/mfa/setup/`): scan the QR code with any
TOTP authenticator (Microsoft/Google Authenticator, 1Password, …) or enter
the secret manually, then confirm with a 6-digit code. Codes entered with
spaces or dashes ("123 456") are accepted. Re-enrolling replaces the previous
secret (audited as `MFA_ENROLLED` with `re_enroll: true`). MFA cannot be
removed by users whose role requires it.

### How the challenge works

1. The protected action is paused and a **single-use, HMAC-signed ticket**
   (10-minute TTL) is stored in the session; the form data rides along as
   hidden inputs and is re-validated at execution time.
2. The user enters their TOTP code on the "Verify Your Identity" page.
3. On success the ticket is consumed, the session key rotates, and the action
   executes with full re-validation (authorization may not have drifted while
   the challenge page was open).

### Lockout

5 consecutive wrong codes lock the browser session for 15 minutes
(`MFA_CHALLENGE_FAILED` is audited on every failure). The lockout is
per-session (per browser), not per-user — logging out and back in resets it.

### Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `PAM_MFA_ISSUER` | `PAM` | Authenticator app issuer label |
| `PAM_MFA_TICKET_TTL` | `600` | Challenge ticket lifetime (seconds) |
| `PAM_MFA_MAX_ATTEMPTS` | `5` | Failures before lockout |
| `PAM_MFA_LOCKOUT_MINUTES` | `15` | Lockout duration |

The TOTP secret is encrypted at rest (signed with the server SECRET_KEY).

---

## 4. Break-Glass Emergency Access

One-click emergency elevation for outages and incidents — no approval workflow,
heavily alarmed, fully audited.

- **Eligibility:** roles flagged `is_break_glass` (Django admin, Policy
  fieldset).
- **Who can pull it:** admins and staff only, from the red **Break Glass**
  link in the navbar.
- **MFA is mandatory** — admins who haven't enrolled are blocked with a
  "set up MFA first" message.
- **Duration** is clamped to `min(role.max_duration_minutes,
  PAM_BREAK_GLASS_DURATION_MINUTES)` (default 60 minutes).
- **Alarm:** every admin/staff user is notified by email (and Slack/Teams if
  configured) via the `break_glass_triggered` notification event.
- **Audit:** `BREAK_GLASS_TRIGGERED` with role, provider, duration, and
  justification. The request carries an `is_break_glass` flag shown as a red
  badge on the detail page.

**Configuration:** `PAM_BREAK_GLASS_DURATION_MINUTES` (default `60`).

---

## 5. Access Reviews & Role Mining

Periodic recertification campaigns where reviewers attest that existing access is
still needed — with usage-based role mining to focus them.

- **Campaign creation** (staff): entries are generated from grant history — one
  entry per user/role pair that has ever held access (PROVISIONED/ACTIVE/EXPIRED/
  REVOKED grants; break-glass grants excluded by design). The optional **unused
  access** filter includes only entitlements whose most recent grant is older
  than N days — the classic role-mining sweep.
- **Usage context**: every entry shows 90-day usage ("N requests, last <date>",
  active-now badge), and every role's detail page shows a usage card — reviewers
  decide with evidence, not vibes.
- **Decisions**: assigned reviewers (or admins) decide each entry —
  Approve (keep) / Revoke (remove) — with a comment. The review completes
  automatically when the last entry is decided.
- Audited as `REVIEW_CREATED` / `REVIEW_ENTRY_DECIDED` / `REVIEW_COMPLETED`.
- Review detail pages are visible to admins and assigned reviewers only.

---

## 6. Digital Vault

An encrypted store for passwords, SSH private keys, and API tokens, with
time-limited checkout, audited reveal, and automatic rotation. This is the
CyberArk-style "digital vault" pillar.

### Entries and encryption

- Each entry stores one secret, **encrypted at rest with Fernet AES** using a
  key derived from the server `SECRET_KEY`. The plaintext never appears in
  the database, logs, audit trail, notifications, or SIEM events.
- ⚠️ **Rotating SECRET_KEY permanently destroys all stored secrets.**
  Export every vault secret before any SECRET_KEY rotation.
- Entry fields: name, description, secret type (PASSWORD / SSH_KEY /
  API_TOKEN), `auto_rotate`, `requires_approval`, `max_checkout_minutes`
  (default 60), `is_active`.

### How checkout works

Every entry gets an automatically-maintained companion role named
`Vault: <entry>` (the **shim role**) — that is the entire trick:

1. **Staff create entries** on the Vault page (`/vault/`, navbar, staff only).
   The secret is stored encrypted and never displayed again.
2. **Assign approvers on the shim role** in the Django admin (approvers,
   quorum policy, and max duration are managed there; the rest syncs from the
   entry).
3. **Requesters check out from the Roles page** — "Vault: <entry>" appears
   like any other role. The request flows through the standard JIT pipeline:
   approval quorum (§2), MFA challenge (§3), time-limited window, expiry
   safety nets, notifications, audit, SIEM.
4. **Reveal** — while the checkout is active, the entry page and the role page
   show a **Reveal Secret** button. If the user is enrolled in MFA, revealing
   requires a TOTP challenge. The secret is shown **once** in a page message
   (server-side session storage, not cookies). Every reveal writes
   `VAULT_SECRET_REVEALED` with the entry name and checkout request id — never
   the value.

### Rotation

- **Auto-rotate on check-in** (`auto_rotate`): when a checkout expires or is
  revoked, the vault rotates the secret — so any secret that was revealed
  becomes worthless automatically.
- **Manual rotation** (staff): from the entry page.
  Reusing the current value or any **previously used** value is rejected
  (previous values are stored as keyed HMAC hashes — useless without the
  SECRET_KEY, but comparable for reuse detection).
- Rotation history is visible on the entry page; `VAULT_SECRET_ROTATED` is
  audited with the reason (`auto_checkin` / `manual`) plus `plugin` and
  `synced` fields.

### Rotation plugins — syncing to the real system (CPM-style)

By default rotation is **vault-only**: a strong 24-character random value
(all character classes) is generated and stored, and the target system is
not touched. Entries can instead be configured with a **rotation plugin**
that pushes the new credential to the actual system:

| Plugin | Config (`rotation_config`) | Entry value |
|--------|---------------------------|-------------|
| `aws_iam` — AWS IAM access key | `{"iam_user_name", "region"}` | Current key pair as JSON `{"access_key_id", "secret_access_key"}` |
| `entra_app_secret` — Entra app client secret | `{"tenant_id", "client_id"}` | Current client secret |
| `ssh` — SSH (Linux/Unix) | `{"host", "username", "port", "use_sudo"}` | Current password |
| `postgresql` — PostgreSQL password | `{"host", "username", "port", "dbname"}` | Current password |
| `mysql` — MySQL password (8+ / MariaDB 10.2+) | `{"host", "username", "port", "host_part"}` | Current password |
| `winrm` — Windows (WinRM) | `{"host", "username", "port", "use_ssl", "account_type"}` | Current password |
| `http` — Generic HTTP webhook | `{"url", "method", "headers", "body_template", "verify_url", "cleanup_url"}` | Current value |

**Rotation semantics:**

1. **Create → verify → store → delete** (create-before-delete): the plugin
   creates the new credential and verifies it works (STS identity check /
   token acquisition), the vault stores it, and only then is the old
   credential revoked. A crash mid-rotation leaves one extra valid
   credential — never a broken one. (IAM's 2-key cap surfaces a clear
   `LimitExceeded` error if an old key was orphaned.)
2. **Failure keeps the old value**: if plugin rotation fails, nothing is
   stored and the target system is untouched (failed events are recorded
   with `synced: false` + an error) — the vault never drifts from the target.
3. **Cleanup failures** orphan the old credential (still valid!) and are
   recorded in the rotation history for manual follow-up; they never fail
   the rotation itself.
4. **Manual rotation on plugin entries is plugin-driven** — typed values are
   rejected, since a hand-typed value would desync the vault from the target.
5. `rotation_config` is connection info only — never secrets (the current
   credential *is* the entry value). `rotation_state` is machine-managed
   bookkeeping (e.g. the Entra credential keyId, needed to remove the old
   secret).
6. **Entra prerequisite**: an app can rotate only its own credentials and
   needs the `Application.ReadWrite.OwnedBy` permission. Without it, Graph
   returns 403 and rotation fails cleanly (old value kept). New secrets get
   a 2-year lifetime (Graph maximum).
7. **Legacy entries** storing an AWS key as plain text (not the JSON pair)
   fail with an explicit "re-import" message — nothing destructive happens.
8. **Password-replacement atomicity** (ssh/postgresql/mysql/winrm/http): the
   candidate value is generated and reuse-checked *before* the target is
   touched, then applied, verified, and stored — with best-effort rollback to
   the old password if verification fails. A rollback failure is recorded with
   a "reconcile manually" instruction. HTTP has no rollback (webhooks can't be
   compensated) and says so in its error text.
9. **Password plugins need no cleanup** — replacing the password orphans
   nothing. The exception is `http`, where an optional `cleanup_url` is called
   after the store.
10. **Transport notes**: SSH uses TOFU host keys (AutoAddPolicy) and stdin-fed
    `chpasswd` (never argv; `sudo -S` handles requiretty). WinRM defaults to
    `cert_validation=ignore` (documented risk) and generates quote-free
    passwords for PowerShell command lines; `net user` needs local admin,
    `Set-ADAccountPassword` needs the AD module + reset rights. MySQL escapes
    per `sql_mode` (NO_BACKSLASH_ESCAPES switches to quote-doubling) and
    `host_part` must match the real account host. PostgreSQL uses
    `Identifier` + bind parameters (injection-proof).

### Semantics worth knowing

- **Deleting an entry** deactivates its shim role but preserves history
  (audit rows and past checkouts survive). Active checkouts simply fail to
  reveal and expire normally. Prefer deactivating (`is_active=False`) over
  deleting when checkouts may be active.
- **Concurrent checkouts** of the same entry are allowed; each reveal and
  rotation is audited independently.
- **A shim with no approvers** can never reach quorum — the request detail
  page shows "No approvers assigned to this role."

---

## 7. SIEM Export

Streams every audit event to a SIEM over HTTPS within ~45 seconds of it being
written.

**Configuration** (staff → **SIEM Settings**, `/audit/siem-settings/`):

| Field | Meaning |
|-------|---------|
| Webhook URL | Splunk HEC endpoint, Sentinel DCR, or any JSON webhook |
| Payload mode | `Splunk HEC` (event envelope + sourcetype `pam:audit`) · `Microsoft Sentinel` (array) · `Generic` (bare event) |
| API token | Encrypted at rest; blank keeps the current value; falls back to the `SIEM_API_TOKEN` env/vault secret |
| Token header / prefix | Defaults `Authorization: Splunk <token>`; set `Bearer ` for Sentinel |
| Action filter | Comma-separated action names; blank = all actions |

**Delivery guarantees:** events forward in order, at least once. The
forwarder keeps a watermark (highest forwarded event id) on the config row,
drains up to 200 events per run (every 45 s via Celery Beat), and retries the
same batch after any failure — so a network blip never silently drops events,
but a rare duplicate is possible. Failures surface in `last_error` on the
settings page.

**Event set** (see §8) includes login/logout, provisioning outcomes, expiry,
MFA events, break-glass, vault lifecycle, and reviews.

---

## 8. Audit Logging

An append-only trail of every meaningful action. The audit log page
(`/audit/`, auditors and admins) supports pagination and `?action=` filtering.

**Actions:**

| Action | Written when |
|--------|--------------|
| `LOGIN` / `LOGOUT` | OIDC or local login / logout (method in details) |
| `REQUEST_CREATED` | Request submitted (details include `auto` for auto-approval roles) |
| `APPROVAL_RECORDED` | A vote is cast but quorum not yet met |
| `REQUEST_APPROVED` | Quorum met, request finalized (votes/threshold in details) |
| `REQUEST_DENIED` | Request denied |
| `PROVISIONING_STARTED` / `PROVISIONING_SUCCEEDED` / `PROVISIONING_FAILED` | Provisioning lifecycle (error in details) |
| `ACCESS_EXPIRED` | Expiry-driven deprovisioning |
| `ACCESS_REVOKED` / `ADMIN_REVOKED` | User/admin-initiated revocation |
| `MFA_ENROLLED` / `MFA_REMOVED` / `MFA_CHALLENGE_FAILED` | MFA lifecycle and failures |
| `BREAK_GLASS_TRIGGERED` | Emergency access pulled |
| `ROLE_CREATED` / `ROLE_UPDATED` | Role catalog changes |
| `REVIEW_CREATED` / `REVIEW_COMPLETED` | Recertification campaigns |
| `VAULT_ENTRY_CREATED` / `VAULT_ENTRY_UPDATED` / `VAULT_ENTRY_DELETED` | Vault entry lifecycle |
| `VAULT_SECRET_REVEALED` | Secret revealed (entry + checkout id only) |
| `VAULT_SECRET_ROTATED` | Rotation (reason in details) |

**System events** (vault auto-rotation, entry deletion) are recorded with no
actor and display as "System" in the UI. Entries are immutable via the admin
(no add/change/delete for non-superusers).

---

## 9. Notifications

Per-channel alerts (email via SMTP, Slack and Teams webhooks) with per-event
toggles — configured by staff under **Notification Settings**.

**Events:** request created · request approved · request denied · access
provisioned · access expiring · **break-glass triggered** (defaults on and
alerts every admin/staff user).

---

## 10. Threat Analytics

Rule-based anomaly detection over the audit stream: a Celery beat scan runs every
60 seconds, evaluates five detection rules against recent `AuditLog` rows, and raises
`ThreatAlert`s. Every alert also writes an `ALERT_RAISED` audit row (auto-forwarded to
your SIEM) and — when enabled — notifies all admins/staff by email, Slack, and Teams.

| Rule | Watches | Default | Heuristic |
|------|---------|---------|-----------|
| Impossible travel | `LOGIN` | ≥2 distinct IPs in ≥2 networks in 30 min | Geo-free: IPs grouped into /16 (IPv4) or /64 (IPv6) networks. Corporate NATs cause false negatives; VPN travel causes false positives. |
| Off-hours elevation | `BREAK_GLASS_TRIGGERED`, `REQUEST_APPROVED`, `ADMIN_REVOKED` | outside 07:00–18:00 (window 18:00–07:00) + all weekend | Boundaries are `HH:MM`; start > end wraps midnight; evaluated in the server timezone (UTC). |
| MFA storm | `MFA_CHALLENGE_FAILED` per actor | ≥5 failures in 10 min | CRITICAL severity. |
| Checkout spike | `REQUEST_CREATED` per actor | ≥10 requests in 60 min | Includes vault checkouts (same pipeline). |
| Vault reveal spike | `VAULT_SECRET_REVEALED` per entry | ≥5 reveals in 10 min | Grouped by entry; reveal volume is a common exfiltration pattern. |

**Configuration** — Threat Settings page (staff): a global scan switch and cooldown
(default 30 min — duplicate alerts for the same rule + subject are fully suppressed
within it), plus per-rule enable switches and thresholds. All settings live in the
`ThreatConfig` singleton; alerts land on the Alerts page (staff) where they can be
acknowledged.

**Semantics**: the scan window per rule is `max(rule window, cooldown)` so a restart
never misses events; at most 50 alerts per scan (storm guard); the raw audit trail
keeps every event regardless of suppression. Off-hours uses the server timezone
(`TIME_ZONE`, currently UTC) — operators wanting local hours must change that setting.

## 11. SCIM v2 / Entra Provisioning

A hand-rolled SCIM v2 endpoint at `/scim/v2/` lets Entra ID provision and
deprovision PAM users automatically (no group mapping in v1 — PAM roles default
to Requester and are assigned in the Django admin).

- **Auth**: `Authorization: Bearer <token>` — the token from SCIM Settings
  (encrypted at rest; env/vault fallback `SCIM_BEARER_TOKEN`). Disabled or
  mismatched → 401 with `WWW-Authenticate: Bearer`.
- **Users**: GET (list with `filter=userName eq` / `externalId eq`, pagination),
  GET/PUT/PATCH/DELETE by id (PAM pk or Entra object id). POST is an **upsert**
  (201 created / 200 existing) so Entra retries converge; username conflicts
  → 409. `userName` maps to the username local part (same convention as OIDC
  login, so both provisioning orders converge).
- **Deprovisioning** deactivates (`is_active = False`) — never deletes, so audit
  history survives. Deactivated users cannot log in via OIDC either; re-enable
  them from Entra (PATCH active or re-assign).
- **Groups**: empty list on GET, 501 on POST — keep group provisioning disabled
  in the Entra app. Discovery endpoints (ServiceProviderConfig with
  oauthbearertoken scheme, Schemas, ResourceTypes) return valid stubs so Entra's
  test-connection and sync flows are clean.
- **Setup**: SCIM Settings → enable + token → Entra Enterprise Application
  (non-gallery) → Provisioning mode Automatic → tenant URL `https://<host>/scim/v2/`
  + secret token → attribute mapping (userPrincipalName → userName, mail → email,
  givenName/familyName, accountEnabled → active) → provision on demand.
  `DJANGO_ALLOWED_HOSTS` must include the public hostname — Entra calls it
  directly.

## 12. Configuration Reference

Application settings (env vars, all optional with safe defaults):

| Variable | Default | Purpose |
|----------|---------|---------|
| `PAM_BASE_URL` | — | Base URL used in notification links |
| `PAM_DEFAULT_MAX_HOURS` | `8` | Default role max duration hint |
| `PAM_MFA_ISSUER` | `PAM` | Authenticator issuer label |
| `PAM_MFA_TICKET_TTL` | `600` | Challenge ticket lifetime (seconds) |
| `PAM_MFA_MAX_ATTEMPTS` | `5` | Failures before MFA lockout |
| `PAM_MFA_LOCKOUT_MINUTES` | `15` | MFA lockout duration |
| `PAM_BREAK_GLASS_DURATION_MINUTES` | `60` | Break-glass duration cap |
| `SIEM_API_TOKEN` | — | Fallback SIEM token (env/vault; DB config preferred) |
| `PAM_ADMIN_URL` | `pam-admin/` | Django admin path |
| `PAM_ADMIN_ALLOWED_IPS` | — | Optional IP/CIDR allowlist for the admin path |

Cloud and database settings (`ENTRA_*`, `AWS_*`, `DATABASE_URL`, `REDIS_URL`,
`DJANGO_SECRET_KEY`) are documented in `deploy/README.md`; secrets resolve
from Azure Key Vault / AWS Secrets Manager / GCP Secret Manager / OCI Vault,
falling back to environment variables.

---

## 13. Security Notes & Gotchas

1. **SECRET_KEY is the master key.** Rotating it invalidates all
   Signer-encrypted config fields **and every vault secret** — export vault
   contents first. There is no re-encryption tooling.
2. **MFA lockout is per browser session**, not per user (logout resets it) —
   per-user throttling is a future hardening item.
3. **SIEM delivery is at-least-once** — a lost response after a successful
   POST causes one duplicate; correct behavior for a SIEM, never silent loss.
4. **Vault reveal shows the secret in a page message once** — residual risks
   are screenshots/screen-sharing/browser history; copy immediately and close
   the tab.
5. **Auto-rotation destroys the previous secret by design.** Only flag entries
   `auto_rotate` when the checked-out secret truly becomes worthless on
   check-in (app-generated credentials), or pair with a manual rotation
   workflow for externally-managed systems.
6. **Approver lists are live.** Adding an approver to a role makes pending
   requests appear in their Approvals immediately, and makes them
   MFA-required; `ALL`-policy requests include newly added approvers in the
   required votes.
7. **Beat waits for migrations.** The beat container loops on
   `manage.py migrate --check` at startup, so it can never crash against a
   half-migrated database again.
