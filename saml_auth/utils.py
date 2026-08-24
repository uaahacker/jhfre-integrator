from sso_auth.utils import SSOUtils

def get_saml_settings():
    """
    Fetches SAML settings from the unified SSO system.
    This function maintains backward compatibility.
    """
    return SSOUtils.get_saml_settings()
