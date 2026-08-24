# Security controls

## Secrets

`DJANGO_SECRET_KEY` and `DJANGO_ENCRYPTION_KEY` come from the process
environment or approved secret storage; no source-controlled fallback exists.
The Fernet key encrypts integration credential secrets, SSO provider secrets,
and sensitive webhook-header values. Browser and admin/UI paths use masked or
configured-state patterns; they must not expose plaintext values or `enc:v1:`
ciphertext.

## Authorization

User management, permission management, form management, submission
administration, integrations, external database configuration, saved queries,
approved procedures, diagnostic endpoints, and SSO management use server-side
authorization. The principal management surfaces are superuser-only. Frontend
navigation is not an authorization boundary.

## My Submissions: intentionally disabled

**My Submissions is intentionally disabled.** `FormSubmission` has no owner
relation. Do not infer ownership from email, username, answers, form
permission, or form UUID. The user-side submission routes fail closed until a
separate data-model/ownership design is approved.

## SQL and procedures

External SQL accepts one read-only SELECT/read-only CTE statement, rejects
write/control tokens, and applies timeout/result limits. Read-only transaction
enforcement is connector-dependent; use database least-privilege accounts.

Only `ApprovedProcedure` entries may execute. They have reviewed identity,
enabled state, `READ_EXPECTED`/behavior classification, typed and bound
parameters, timeout and bounded result limits, transaction/cleanup handling,
and persistent sanitized execution audit data. Execution can still have
external side effects according to its approved policy.

## Uploads

Only configured dynamic-form file fields accept uploads. The default maximum is
10 MB per file, 25 MB total, and five files. Type/extension policy is applied,
and Pillow verifies image uploads with a pixel limit. Submitted files live
under `media/uploads/` and use protected, authorized downloads.

## Webhooks

Webhook delivery permits HTTPS targets only, rejects local/private/non-global
addresses after DNS pre-resolution, disables redirects, uses connect/read
timeouts, verifies TLS, ignores proxy environment settings, validates headers,
encrypts sensitive header values, and does not retain remote response bodies.
Delivery is one-shot; there is no retry or idempotency queue.

DNS validation has a residual DNS-rebinding/TOCTOU limitation: the HTTP client
can resolve again when connecting after application validation. This is a
defense-in-depth control, not mathematically complete SSRF protection.

## SAML signatures

Active SAML providers require strict validation, a configured IdP X.509
certificate, and a signed SAML Assertion. The outer SAML Response signature is
provider-configurable: `Want Messages Signed` may require it or allow an
unsigned outer Response, while `Want Assertions Signed` remains mandatory.
python3-saml continues to verify the signed Assertion against the configured
certificate. This policy supports IdPs that sign only Assertions without
trusting unsigned identity data or weakening strict validation.

Certificate rollover uses python3-saml's native `x509certMulti` mechanism: a
primary certificate plus zero or more additional rollover certificates are all
accepted for signature verification, with no custom cryptographic code.

## SAML AuthnRequest binding and signing

The AuthnRequest SSO binding (`HTTP-Redirect` or `HTTP-POST`) is a
per-provider configuration value, not code. Redirect binding uses
python3-saml's built-in query-string signing. POST binding is built directly
from `OneLogin_Saml2_Authn_Request` (bypassing `OneLogin_Saml2_Auth.login()`,
which is hardcoded to Redirect); when the provider requires signed
AuthnRequests, the request XML is signed with `OneLogin_Saml2_Utils.add_sign`
— the same enveloped-XML-signature primitive the toolkit itself uses for
SP metadata signing — before base64 encoding. No custom XML signature
implementation exists in this codebase. Enabling AuthnRequest signing or
either logout-signing option requires an SP certificate and private key to be
configured; both the provider form and python3-saml's own settings validation
enforce this, so a provider cannot be saved or loaded in a state that would
silently downgrade to an unsigned request.

The auto-submitting POST-binding form uses Django's default template
autoescaping for `SAMLRequest`/`RelayState`; no `|safe` filter or manual XML
interpolation is used to build it.

## SAML metadata parsing

Pasted IdP metadata XML is untrusted input. Parsing reuses python3-saml's own
XML parser (`onelogin.saml2.xmlparser`), which is a defusedxml-derived lxml
parser with DTD processing, external entity resolution, and network entity
resolution disabled by default, plus lxml's `huge_tree=False` bound. An
explicit byte-size cap is enforced before parsing, since the toolkit does not
impose one itself. No custom XML defusal logic was written — the toolkit's own
hardened parser is the security boundary. Metadata URL import is not
implemented: `integrator/webhook_security.py`'s SSRF controls are shaped for
one-shot webhook delivery and explicitly discard response bodies, and the
existing OIDC URL validator does not perform DNS resolution to catch a
hostname that resolves to a private address, so neither is a clean SSRF-safe
fit for a metadata GET-with-body fetch. Building a new SSRF control for this
was out of scope for this pass; only metadata paste is supported.

## SAML identity trust

Two SAML identity policies bind local accounts: Persistent NameID (unchanged)
and Configured immutable attribute, which reads a provider-specified,
non-empty assertion attribute as the external subject. Both resolve to the
same provider+subject uniqueness constraint used by OIDC's `sub`; neither
policy, nor any fallback, trusts email, username, or display name as identity.
The immutable-attribute policy is opt-in and requires the operator to name an
attribute the IdP issues as a stable, unique, non-user-editable identifier —
the application does not and cannot verify that a configured attribute name is
actually immutable at the IdP.

## Remaining intentional limitations

- My Submissions remains disabled pending explicit ownership architecture.
- Webhooks have no retry or idempotency queue.
- `saml_auth` remains for migration history.
- Production media and reverse-proxy rules are operator responsibilities.
- SAML metadata URL import is deferred; only metadata XML paste is supported.
- SAML Single Logout uses HTTP-Redirect only; there is no per-provider logout
  binding field.

Report suspected secret exposure without placing credentials, tokens, private
keys, session material, or production data in issues, fixtures, or logs.
