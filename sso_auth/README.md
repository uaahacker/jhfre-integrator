# Unified SSO Authentication System

This document provides a comprehensive guide to the unified Single Sign-On (SSO) authentication system that supports both SAML 2.0 and OpenID Connect (OIDC) protocols.

## Overview

The unified SSO system consolidates authentication management into a single interface, replacing the previous scattered configuration locations. It provides:

- **Unified Management Interface**: Single location for all SSO configurations
- **Protocol Support**: Both SAML 2.0 and OpenID Connect (OIDC)
- **Testing Capabilities**: Built-in connection testing for all providers
- **Audit Logging**: Complete audit trail of all SSO events
- **Import/Export**: Configuration backup and migration tools
- **Dynamic Configuration**: No code changes required for new providers

## Features

### Supported Protocols

1. **SAML 2.0**
   - Identity Provider (IdP) configuration
   - Service Provider (SP) configuration  
   - Certificate management
   - Metadata generation
   - Security options (signing, encryption)

2. **OpenID Connect (OIDC)**
   - Discovery endpoint support
   - Manual endpoint configuration
   - JWT token handling
   - Scope management

### Management Features

- **Web UI**: User-friendly interface for configuration
- **Testing Tools**: Connection and configuration validation
- **Audit Logging**: Track all authentication events
- **Backup/Restore**: Export/import configurations
- **Command Line Tools**: Management commands for automation

## Installation & Setup

### 1. Dependencies

The system requires the following Python packages (already included in requirements.txt):
```
python3-saml==1.16.0  # SAML support
PyJWT==2.10.1         # JWT token handling
python-jose==3.5.0    # OIDC token validation
requests==2.32.3      # HTTP requests for OIDC
```

### 2. Database Setup

Run migrations to create the necessary tables:
```bash
python manage.py migrate sso_auth
```

### 3. URL Configuration

The system is already configured with URLs under `/sso/`:
- Management interface: `/sso/management/`
- SAML endpoints: `/sso/saml/...`
- OIDC endpoints: `/sso/oidc/...`

## Usage

### Web Interface

1. **Access Management Interface**
   - Navigate to `/sso/management/` or use the "SSO Configuration" card in the main configurations page
   - Login with superuser credentials

2. **Create SSO Provider**
   - Click "Add SSO Provider"
   - Select protocol (SAML or OIDC)
   - Fill in required configuration fields
   - Save and test the connection

3. **Manage Existing Providers**
   - View all providers in the main interface
   - Edit, test, or delete providers
   - View audit logs for each provider

### SAML Configuration

#### Required Fields
- **IdP Entity ID**: Identity Provider's entity identifier
- **IdP SSO URL**: Single Sign-On endpoint URL
- **SP Entity ID**: Your Service Provider entity ID
- **SP ACS URL**: Assertion Consumer Service URL

#### Optional Fields
- **IdP SLO URL**: Single Logout endpoint
- **IdP Certificate**: X.509 certificate for signature verification
- **SP Certificate/Key**: For signing requests (optional)

#### Metadata
- SAML metadata is automatically generated at `/sso/saml/metadata/<provider_name>/`
- Use this URL when configuring the IdP

### OIDC Configuration

#### Required Fields
- **Client ID**: OAuth2/OIDC client identifier
- **Client Secret**: Client secret for authentication
- **Discovery URL** OR manual endpoints:
  - Authorization Endpoint
  - Token Endpoint
  - UserInfo Endpoint

#### Optional Fields
- **JWKS URI**: For token signature verification
- **Issuer**: Expected token issuer
- **Scopes**: Space-separated list of OAuth2 scopes

### Testing Providers

#### Web Interface
- Use the "Test Connection" button in the management interface
- Results are displayed with detailed error information

#### Command Line
```bash
# Test all enabled providers
python manage.py test_sso_providers

# Test specific provider
python manage.py test_sso_providers --provider "Provider Name"

# Test by protocol
python manage.py test_sso_providers --protocol saml
python manage.py test_sso_providers --protocol oidc
```

### Configuration Backup/Restore

#### Export Configuration
```bash
# Export all providers
python manage.py export_sso_config /path/to/backup.json

# Export specific provider
python manage.py export_sso_config /path/to/backup.json --provider "Provider Name"

# Export without sensitive data
python manage.py export_sso_config /path/to/backup.json
```

## Authentication Flow

### SAML Authentication
1. User clicks SSO login link
2. User is redirected to IdP for authentication
3. IdP sends SAML assertion to ACS endpoint
4. System validates assertion and creates/updates user
5. User is logged in and redirected to target page

### OIDC Authentication
1. User clicks SSO login link
2. User is redirected to authorization endpoint
3. User authenticates with IdP
4. System receives authorization code
5. System exchanges code for access token
6. System retrieves user info and creates/updates user
7. User is logged in and redirected to target page

## URLs and Endpoints

### Management URLs
- `/sso/management/` - Main management interface
- `/sso/create/` - Create new provider
- `/sso/edit/<id>/` - Edit provider
- `/sso/test/<id>/` - Test provider connection

### SAML URLs
- `/sso/saml/login/` - Initiate SAML login (default provider)
- `/sso/saml/login/<provider>/` - Initiate SAML login (specific provider)
- `/sso/saml/acs/` - Assertion Consumer Service (default)
- `/sso/saml/acs/<provider>/` - ACS for specific provider
- `/sso/saml/logout/` - SAML logout
- `/sso/saml/metadata/` - SAML metadata (default)
- `/sso/saml/metadata/<provider>/` - Metadata for specific provider

### OIDC URLs
- `/sso/oidc/login/` - Initiate OIDC login (default provider)
- `/sso/oidc/login/<provider>/` - Initiate OIDC login (specific provider)  
- `/sso/oidc/callback/<provider>/` - OIDC callback endpoint

## Migration from Legacy System

The system automatically migrates existing SAML configurations from the old `saml_auth` app. The migration:

1. Preserves all existing configuration data
2. Creates new SSO providers with appropriate settings
3. Maintains backward compatibility through utility functions

### Manual Migration Steps (if needed)
1. Export legacy configuration using the old system
2. Create new SSO providers with the same settings
3. Test the new providers
4. Update any hardcoded references to use the new system

## Security Considerations

### SAML Security
- Always validate IdP certificates in production
- Use signed requests when supported by IdP
- Enable strict mode for production environments
- Rotate SP certificates regularly if using signing

### OIDC Security  
- Use HTTPS for all endpoints in production
- Validate JWT tokens properly
- Store client secrets securely
- Use appropriate scopes (minimal required)

### General Security
- Enable audit logging in production
- Monitor authentication events
- Use strong certificates and keys
- Keep dependencies updated

## Troubleshooting

### Common SAML Issues
1. **Metadata validation errors**: Check SP certificate configuration
2. **Clock skew issues**: Ensure server time is synchronized
3. **Signature validation failures**: Verify IdP certificate
4. **Attribute mapping errors**: Check attribute names in IdP

### Common OIDC Issues
1. **Discovery endpoint failures**: Check URL and network connectivity
2. **Token validation errors**: Verify client ID and secret
3. **Scope errors**: Ensure required scopes are configured
4. **Redirect URI mismatch**: Verify callback URL configuration

### Debug Mode
Enable debug mode for detailed logging:
1. Set `debug_mode=True` in provider configuration
2. Check Django logs for detailed error information
3. Use browser developer tools to inspect redirects

### Testing Connectivity
```bash
# Test discovery endpoint manually
curl -k https://your-idp.com/.well-known/openid_configuration

# Test SAML metadata  
curl -k https://your-app.com/sso/saml/metadata/provider-name/
```

## API Reference

### Models

#### SSOProvider
Main model for SSO provider configuration with fields for both SAML and OIDC settings.

#### SSOAuditLog  
Audit logging model tracking all SSO authentication events.

### Utility Functions

#### SSOUtils.get_saml_settings(provider_name=None)
Get SAML configuration for specified or default provider.

#### SSOUtils.get_oidc_settings(provider_name=None) 
Get OIDC configuration for specified or default provider.

#### SSOUtils.create_or_update_user(provider, user_data)
Create or update Django user from SSO provider data.

### Management Commands

#### test_sso_providers
Test SSO provider connections and configuration.

#### export_sso_config
Export provider configurations to JSON file.

## Support and Maintenance

### Regular Tasks
1. **Certificate Rotation**: Update SP and IdP certificates before expiration
2. **Provider Testing**: Regular connection tests to ensure availability
3. **Audit Review**: Monitor authentication logs for suspicious activity
4. **Backup**: Regular export of configurations for disaster recovery

### Monitoring
- Monitor authentication success/failure rates
- Watch for certificate expiration warnings
- Track provider availability and response times
- Review audit logs for security events

For additional support, check the audit logs and enable debug mode for detailed error information.
