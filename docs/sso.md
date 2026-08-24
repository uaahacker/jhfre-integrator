# Single sign-on

## What requires environment configuration?

Only deployment-wide, host/proxy/cookie/security settings that apply
regardless of which SSO provider is active: `DJANGO_ALLOWED_HOSTS`,
`DJANGO_CSRF_TRUSTED_ORIGINS`, `DJANGO_SESSION_COOKIE_SAMESITE`,
`DJANGO_SESSION_COOKIE_SECURE`, `DJANGO_TRUST_X_FORWARDED_PROTO`, and the
other HTTPS/HSTS settings in [deployment](deployment.md). None of these name a
specific IdP or provider.

## What requires provider configuration?

Everything specific to one SAML or OIDC identity provider — entity IDs,
endpoints, bindings, certificates, identity policy, attribute mappings, and
signature requirements — is configured per provider through the SSO
Management UI (`/sso/management/`) and stored in the database. It is never
set through environment variables or edited in source code. See [Adding a New
SAML Provider After Deployment](#adding-a-new-saml-provider-after-deployment)
below.

## Active implementation

`sso_auth` is the active OIDC/SAML application and is mounted under `/sso/`.
It owns provider configuration, management UI, login/callback flows, identity
records, secret encryption, replay protection, and minimized audit logs.

`saml_auth` is **legacy and migration-history-required**. Its routes are not
mounted by `core.urls`. It remains installed because a historical `sso_auth`
migration depends on its migration state and legacy configuration model. Do not
remove it or its migrations without a separately reviewed migration-state and
data-retirement plan.

## Provider lifecycle and management

Superusers manage providers at `/sso/management/`. A provider authenticates
only when it is both `enabled` and has `status=active`; disabled or inactive
providers are not login choices. Provider test, edit, delete, details, and
audit endpoints are management functions, not public configuration APIs.

Do not put client secrets, private keys, certificates requiring confidentiality,
or provider exports in source control. UI fields use blank/masked configured
state for existing secrets rather than rendering stored secret/ciphertext.

## OIDC controls

OIDC authentication uses provider-bound state and nonce values, discovery/JWKS
handling, ID-token signature validation with allowed asymmetric algorithms,
issuer and audience checks, and a UserInfo `sub` match where UserInfo is used.
Identity is bound to the provider plus the validated `sub`; email or username
does not silently link a local account.

## SAML controls

Active SAML providers use strict settings, a configured IdP certificate, a
signed Assertion, and request/callback correlation. The outer SAML Response
signature is provider-configurable through `Want Messages Signed`: when true,
both the outer Response and Assertion must be signed; when false, the outer
Response may be unsigned but the Assertion remains mandatory and is still
verified by python3-saml. Strict validation, certificate verification, and
signed assertions are never disabled for active providers.

Requiring both signatures can reduce interoperability because some valid IdPs
sign only the Assertion. An AuthnRequest ID is correlated through
`InResponseTo` with one-time session state; this correlation is identical
whether the AuthnRequest was sent via HTTP-Redirect or HTTP-POST. Validated
assertion IDs are SHA-256 hashed and stored briefly to reject replay.

### Identity trust policy

Two policies bind SAML identity to a local account, in addition to `Disabled`:

- **Persistent NameID** — requires the response's NameID format to be
  `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`; the NameID value is
  the external subject.
- **Configured immutable attribute** — the provider stores an exact assertion
  attribute name (`SAML Immutable Attribute Name`), for example an object GUID
  or employee ID. The assertion must contain a non-empty value for that exact
  attribute name, which becomes the external subject. This is for IdPs that
  do not issue a persistent NameID but do issue a stable, IdP-controlled
  identifier as a regular attribute.

Both policies resolve to the same identity binding: **provider + external
subject**, enforced by a database-level unique constraint on
`SSOUserProfile`. Neither policy — nor any fallback path — ever trusts email,
username, or display name as identity. Choosing the wrong attribute name for
"Configured immutable attribute" (for example an email or display-name
attribute) defeats this protection at the configuration layer, so only use
attributes the IdP issues as stable, unique, non-user-editable identifiers.

### SSO binding

`SSO Binding` (`SAML IdP SSO Binding` on the provider) selects which
SingleSignOnService binding the AuthnRequest is sent with:

- **HTTP-Redirect** (default) — preserves existing behavior for all providers
  created before this field existed.
- **HTTP-POST** — for IdPs that only expose a POST-binding SSO endpoint. The
  AuthnRequest is rendered as a minimal auto-submitting HTML form (escaped by
  Django's default template autoescaping) that POSTs `SAMLRequest` and
  `RelayState` directly to the IdP's SSO URL from the browser; there is no
  server-to-server POST. Request correlation (`InResponseTo`, session state)
  is identical to the Redirect flow.

`Sign AuthN Requests` is supported for both bindings. For Redirect it uses
python3-saml's built-in query-string signing; for POST it uses
`OneLogin_Saml2_Utils.add_sign` to produce an enveloped XML signature on the
AuthnRequest before base64-encoding it — the same toolkit primitive used
elsewhere for signing SP metadata. No custom SAML signature logic is
implemented. Enabling AuthnRequest signing, or either logout signing option,
requires an SP certificate and private key to be configured; the provider
form rejects saving an active provider without them (python3-saml itself
enforces the same requirement when the settings are loaded).

Single Logout continues to use the HTTP-Redirect binding only; there is no
per-provider logout binding field.

### Certificate rollover

An IdP signing certificate rotation can be represented without code changes:
configure the current certificate in `IdP Certificate` as usual, and paste one
or more upcoming/rollover certificates into `Additional IdP Certificates
(rollover)`. Both are passed to python3-saml as `x509cert` plus
`x509certMulti.signing`, which is the toolkit's own native multi-certificate
signature-verification mechanism — assertions signed by any listed
certificate validate successfully.

### Metadata-assisted onboarding

The provider form accepts pasted IdP metadata XML (`IdP Metadata & Endpoints`
→ paste → **Parse Metadata**). Parsing reuses python3-saml's own hardened XML
parser (`onelogin.saml2.xmlparser`, a defusedxml-derived lxml parser that
already disables DTDs, external entities, and network entity resolution) plus
an explicit size cap, then extracts the entity ID, every advertised
SingleSignOnService endpoint and binding, every SingleLogoutService endpoint
and binding, every signing certificate, and every advertised NameID format.
Parsing only prefills the (unsaved) form; nothing is written to the database
until the operator reviews the fields and submits normally. Metadata
advertising a capability (for example an emailAddress NameID format) does not
by itself grant trust — trusted identity remains governed solely by `SAML
Identity Policy`.

Metadata **URL** import is not implemented; paste the XML directly. See
[security](security.md) for why URL import was deferred rather than built
with a weaker SSRF control.

When a reverse proxy terminates TLS, configure the provider's SP ACS URL with
the public HTTPS URL, for example `https://example.com/sso/saml/acs/`. Do not
include the internal Django, Gunicorn, or container port. The active SAML
request adapter reconstructs the public port from Django's trusted request
semantics: HTTPS without an explicit host port uses 443, HTTP without one uses
80, and an explicit public nonstandard port is preserved.

## Provisioning and collision policy

`allow_registration` controls whether a provider can create a new local user.
Collisions involving existing local normal, staff, or superuser accounts fail
closed; there is no implicit email/username linking. IdP group or role claims
do not elevate local privileges.

## Secrets and audit

`sso_auth/secret_encryption.py` uses the stable `DJANGO_ENCRYPTION_KEY` Fernet
key for OIDC client secrets and SAML private keys. `saml_replay.py` maintains
replay records. Audit records contain minimized event metadata; do not use
provider audit output as a secret export mechanism.

## Operator setup

Configure providers through the authorized management UI with correct callback
URLs, trusted HTTPS/proxy topology, issuer/discovery/JWKS details for OIDC, or
IdP/SP/certificate details for SAML. Test in a controlled environment first.
Do not weaken OIDC state/nonce/token validation or SAML signatures/correlation
to make a provider appear to work.

## Adding a New SAML Provider After Deployment

Onboarding a standards-compliant SAML 2.0 IdP is a configuration task; it does
not require editing Python, templates, or `settings.py`.

1. Obtain the IdP's metadata XML from the identity provider administrator.
2. In the SSO management UI, **Add SSO Provider** and select **SAML 2.0**.
3. Paste the metadata XML under `IdP Metadata & Endpoints` and click **Parse
   Metadata**. Review the discovered Entity ID, SSO endpoint(s)/binding, SLO
   endpoint, and certificate(s) — all fields remain editable.
4. If the IdP advertises both Redirect and POST SSO endpoints, `SSO Binding`
   defaults to Redirect; switch it (and the matching SSO URL) if the IdP
   should be used via POST instead.
5. Configure `SAML Identity Policy` (Persistent NameID, or Configured
   immutable attribute with its exact attribute name) under `Identity Trust`.
6. Configure `Attribute Mapping` (email/username/first name/last name
   attribute names) to match this IdP's actual assertion attributes — do not
   assume another provider's attribute names apply.
7. Configure `Security`: strict mode and signed-assertion requirements cannot
   be disabled for an active provider; decide whether to require a signed
   outer Response (`Want Messages Signed`) and whether to sign outgoing
   AuthnRequests/logout messages (requires an SP certificate and key if so).
8. Save the provider with `Status` set to **Testing** and `Enabled` off first.
9. Use the provider's **Test connection** action to check the saved
   configuration.
10. Enable the provider (only one provider is active at a time) and run an
    SP-initiated login against the real IdP.
11. Verify the SSO audit log recorded the login attempt/success.
12. Verify the resulting user's mapped attributes and privileges (SSO
    provisioning never grants staff/superuser access).

This flow does not cover every conceivable SAML deployment — see
[security](security.md) for documented compatibility limits (metadata URL
import, single-binding logout, single-certificate-set unless rollover fields
are used).
