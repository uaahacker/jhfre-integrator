# Frontend

## Current frontend architecture

The frontend is DjangoTemplates rendered by Django views. It uses Metronic HTML
Demo 1 assets, Bootstrap, vanilla JavaScript, and Fetch/AJAX where needed.
There is no frontend build system and no React, Vue, Angular, Vite, or client
JWT architecture.

## Base layout and sidebar

`templates/base.html` provides the shared layout and asset/script blocks.
`templates/partials/sidebar.html` is the active hardcoded navigation. Normal
authenticated users receive Dashboard and Account links; superusers also see
Forms and administrative links for users, permissions, integrations,
configurations, and SSO. Navigation does not grant access.

## Template areas

| Area | Location |
|---|---|
| Shared layout/partials | `templates/base.html`, `templates/partials/` |
| Dynamic forms and submissions | `templates/pages/forms/`, `templates/form_templates/` |
| Integrations | `templates/pages/integrations/` |
| External DB and procedures | `templates/pages/configurations/` |
| User/account screens | `templates/pages/Users/`, `templates/pages/user-profile/` |
| User-side legacy submission templates | `templates/pages/userside/` (routes fail closed) |
| SSO management and provider forms | `templates/sso_auth/` |

## JavaScript and AJAX

Page-specific JavaScript may live in a template `extra_scripts` block; reusable
assets belong in `static/`. Existing AJAX endpoints use Django CSRF handling.
New code should define a clear server response contract, show loading/error
states, handle 400/401/403/404/500 responses, and escape values before placing
them into HTML. Do not add a second framework casually.

## Adding a page

1. Add an authorized view in the appropriate Django app.
2. Register its route in that app's `urls.py`.
3. Add the template under the feature's template area and extend `base.html`
   where appropriate.
4. Add a sidebar link only when the workflow needs navigation.
5. Add or confirm server-side permissions and automated tests.

## Secret handling

Never render plaintext credentials, encrypted `enc:v1:` values, webhook header
secrets, OIDC client secrets, or SAML private keys. Use the existing masked or
configured-state presentation. Client-side code is not a secrets boundary.

## Frontend testing

After backend tests, manually check the SSO protocol toggle and audit modal,
integration credential modal, dynamic form builder, sidebar at responsive
sizes, browser console, and static-file 404s. The SSO management table leaves
its body empty for zero providers and uses DataTables' `emptyTable` message,
avoiding the unequal-column warning.
