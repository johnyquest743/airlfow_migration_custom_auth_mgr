# Airflow 2.4 to 2.10: Authentication Configuration Migration Guide

## Table of Contents
1. [Key Differences: auth_manager vs auth_backends](#key-differences)
2. [Configuration Changes: Airflow 2.4 vs 2.10](#configuration-changes)
3. [Custom OIDC Authentication Setup](#custom-oidc-setup)
4. [Required Files and Code](#required-files)

---

## Key Differences: auth_manager vs auth_backends {#key-differences}

### **auth_backends** (Legacy - Airflow < 2.x)
- **Purpose**: API authentication only
- **Location**: `[api]` section in `airflow.cfg`
- **Scope**: Controls how API requests are authenticated
- **Example**: `airflow.api.auth.backend.basic_auth`

### **auth_manager** (New - Airflow 2.x+)
- **Purpose**: Unified authentication and authorization framework
- **Location**: `[core]` section in `airflow.cfg`
- **Scope**: Controls both webserver UI and API authentication
- **Default in 2.10**: `airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager`
- **Pluggable**: You can switch between different auth managers

---

## Configuration Changes: Airflow 2.4 vs 2.10 {#configuration-changes}

### Major Configuration Differences

| Feature | Airflow 2.4 | Airflow 2.10 |
|---------|------------|--------------|
| **Auth Framework** | FAB-based auth with `auth_backend` | New `auth_manager` framework in `[core]` section |
| **API Auth Config** | `[api] auth_backend` (singular) → `[fab] auth_backends` (plural) | `[fab] auth_backends` (supports multiple backends) |
| **webserver_config.py** | ✅ Required for OAuth/OIDC | ⚠️ **Still supported but documentation notes it as "legacy"** - You still need it for custom OIDC! |
| **Default Auth Manager** | FAB Auth Manager (implicit) | Must be explicitly set: `[core] auth_manager` |
| **OAuth Redirect URL** | `/oauth-authorized/{provider}` | `/auth/oauth-authorized/{provider}` (Airflow 3.0+) |

### Configuration File Changes

#### **Airflow 2.4 - airflow.cfg**
```ini
[api]
auth_backend = airflow.api.auth.backend.basic_auth

[webserver]
rbac = True
authenticate = True
```

#### **Airflow 2.10 - airflow.cfg**
```ini
[core]
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager

[fab]
auth_backends = airflow.providers.fab.auth_manager.api.auth.backend.basic_auth
```

### Important Notes for 2.10

1. **webserver_config.py is STILL REQUIRED** for custom OAuth/OIDC authentication despite documentation saying it's "legacy"
2. The `[api]` section's `auth_backend` has been moved to `[fab]` section's `auth_backends`
3. Auth manager must be explicitly configured in `[core]` section
4. OAuth redirect routes changed in Airflow 3.0: `/oauth-authorized/` → `/auth/oauth-authorized/`

---

## Custom OIDC Authentication Setup {#custom-oidc-setup}

### Overview

To implement custom OIDC authentication in Airflow 2.10, you need:
1. ✅ webserver_config.py (YES, still required!)
2. ✅ client_secret.json (OIDC credentials)
3. ✅ Custom Security Manager (Python class)
4. ✅ Modified airflow.cfg
5. ✅ Additional Python packages

### Prerequisites

Install required packages:
```bash
pip install apache-airflow-providers-fab==1.2.0+
pip install authlib==1.3.0
pip install requests
```

---

## Required Files and Code {#required-files}

### 1. airflow.cfg Configuration

```ini
[core]
# Set the auth manager to FAB
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager

# Other core settings
dags_folder = /path/to/dags
base_log_folder = /path/to/logs
executor = LocalExecutor
sql_alchemy_conn = postgresql+psycopg2://user:pass@localhost/airflow

[fab]
# API authentication backends (can have multiple, comma-separated)
auth_backends = airflow.providers.fab.auth_manager.api.auth.backend.basic_auth

[webserver]
# Webserver settings
base_url = http://localhost:8080
web_server_host = 0.0.0.0
web_server_port = 8080

# Expose config for debugging (disable in production)
expose_config = False
```

### 2. webserver_config.py

**Location**: `$AIRFLOW_HOME/webserver_config.py`

```python
# -*- coding: utf-8 -*-
"""
Airflow Webserver Configuration for Custom OIDC Authentication
"""
import os
import logging
from base64 import b64decode
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from flask import redirect, session
from flask_appbuilder import expose
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.views import AuthOAuthView
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride
from airflow.configuration import conf

# Setup logging
log = logging.getLogger(__name__)
log.setLevel(os.getenv("AIRFLOW__LOGGING__FAB_LOGGING_LEVEL", "INFO"))

# Flask-WTF CSRF protection
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True

# SQLAlchemy Database URI
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Authentication Type - Using OAuth for OIDC
AUTH_TYPE = AUTH_OAUTH

# User Registration Settings
AUTH_USER_REGISTRATION = True  # Allow automatic user registration
AUTH_USER_REGISTRATION_ROLE = "Viewer"  # Default role for new users
AUTH_ROLES_SYNC_AT_LOGIN = True  # Sync roles at each login

# OIDC Cookie Settings (set to True in production with HTTPS)
OIDC_COOKIE_SECURE = False  # Set to True in production with HTTPS
OIDC_USER_INFO_ENABLED = True

# Session Settings
PERMANENT_SESSION_LIFETIME = 43200  # 12 hours in seconds

# OIDC Configuration
OIDC_ISSUER = os.getenv('OIDC_ISSUER', 'https://your-oidc-provider.com/realms/airflow')
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID', 'airflow')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', 'your-client-secret')
OIDC_SCOPES = ['openid', 'email', 'profile', 'groups']

# Role Mapping from OIDC groups to Airflow roles
AUTH_ROLES_MAPPING = {
    "airflow_admin": ["Admin"],
    "airflow_op": ["Op"],
    "airflow_user": ["User"],
    "airflow_viewer": ["Viewer"],
    "airflow_public": ["Public"],
}

# OAuth Provider Configuration
OAUTH_PROVIDERS = [
    {
        'name': 'oidc',  # Provider name
        'icon': 'fa-key',  # Font Awesome icon
        'token_key': 'access_token',  # Key to extract token
        'remote_app': {
            'client_id': OIDC_CLIENT_ID,
            'client_secret': OIDC_CLIENT_SECRET,
            'server_metadata_url': f'{OIDC_ISSUER}/.well-known/openid-configuration',
            'client_kwargs': {
                'scope': ' '.join(OIDC_SCOPES)
            },
        }
    }
]

# Custom OAuth View to handle login/logout
class CustomAuthOAuthView(AuthOAuthView):
    """Custom OAuth View to handle OIDC authentication"""
    
    @expose('/logout/')
    def logout(self):
        """Custom logout to clear session and revoke tokens"""
        # Clear the session
        session.clear()
        
        # Redirect to OIDC provider logout if needed
        logout_url = f"{OIDC_ISSUER}/protocol/openid-connect/logout"
        post_logout_redirect = self.appbuilder.get_url_for_index
        
        return redirect(f"{logout_url}?post_logout_redirect_uri={post_logout_redirect}")


# Custom Security Manager
class CustomSecurityManager(FabAirflowSecurityManagerOverride):
    """
    Custom Security Manager to handle OIDC authentication and role mapping
    """
    
    # Use custom OAuth view
    authoauthview = CustomAuthOAuthView
    
    def oauth_user_info(self, provider, response=None):
        """
        Extract user information from OIDC provider response
        
        Args:
            provider: OAuth provider name
            response: OAuth response containing tokens
            
        Returns:
            Dictionary with user info: username, email, first_name, last_name, role_keys
        """
        if provider == 'oidc':
            # Get access token
            access_token = response.get('access_token')
            
            if not access_token:
                log.error("No access token found in OAuth response")
                return {}
            
            try:
                # Fetch user info from OIDC provider
                userinfo_url = f"{OIDC_ISSUER}/protocol/openid-connect/userinfo"
                headers = {'Authorization': f'Bearer {access_token}'}
                
                userinfo_response = requests.get(userinfo_url, headers=headers)
                userinfo_response.raise_for_status()
                userinfo = userinfo_response.json()
                
                log.info(f"Received user info: {userinfo}")
                
                # Extract groups/roles from userinfo
                groups = userinfo.get('groups', [])
                
                # Map OIDC groups to Airflow roles
                role_keys = []
                for group in groups:
                    if group in AUTH_ROLES_MAPPING:
                        role_keys.extend(AUTH_ROLES_MAPPING[group])
                
                # If no roles mapped, assign default role
                if not role_keys:
                    role_keys = [AUTH_USER_REGISTRATION_ROLE]
                
                # Build user info dict
                user_info = {
                    'username': userinfo.get('preferred_username', userinfo.get('email')),
                    'email': userinfo.get('email'),
                    'first_name': userinfo.get('given_name', ''),
                    'last_name': userinfo.get('family_name', ''),
                    'role_keys': role_keys
                }
                
                log.info(f"Mapped user info: {user_info}")
                return user_info
                
            except Exception as e:
                log.error(f"Error fetching user info from OIDC provider: {e}")
                return {}
        
        return {}

# Set the custom security manager
SECURITY_MANAGER_CLASS = CustomSecurityManager

# Theme Configuration (Optional)
# APP_THEME = "darkly.css"  # Bootstrap theme
```

### 3. client_secret.json (Alternative to Environment Variables)

**Location**: `$AIRFLOW_HOME/client_secret.json`

```json
{
  "web": {
    "client_id": "airflow-client-id",
    "client_secret": "your-client-secret-here",
    "auth_uri": "https://your-oidc-provider.com/oauth2/v1/authorize",
    "token_uri": "https://your-oidc-provider.com/oauth2/v1/token",
    "userinfo_uri": "https://your-oidc-provider.com/oauth2/v1/userinfo",
    "issuer": "https://your-oidc-provider.com",
    "redirect_uris": [
      "http://localhost:8080/oauth-authorized/oidc"
    ]
  }
}
```

**Note**: For Airflow 2.10, use `/oauth-authorized/`. For Airflow 3.0+, use `/auth/oauth-authorized/`

### 4. Dockerfile (Optional - for Docker deployments)

```dockerfile
FROM apache/airflow:2.10.5-python3.11

USER root

# Install system dependencies if needed
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER airflow

# Install Python dependencies for OIDC
RUN pip install --no-cache-dir \
    apache-airflow-providers-fab==1.2.0 \
    authlib==1.3.0 \
    requests \
    cryptography

# Copy configuration files
COPY --chown=airflow:root webserver_config.py ${AIRFLOW_HOME}/webserver_config.py
COPY --chown=airflow:root client_secret.json ${AIRFLOW_HOME}/client_secret.json
```

### 5. Environment Variables

```bash
# OIDC Configuration
export OIDC_ISSUER="https://your-oidc-provider.com/realms/airflow"
export OIDC_CLIENT_ID="airflow"
export OIDC_CLIENT_SECRET="your-client-secret"

# Airflow Configuration
export AIRFLOW__CORE__AUTH_MANAGER="airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager"
export AIRFLOW__FAB__AUTH_BACKENDS="airflow.providers.fab.auth_manager.api.auth.backend.basic_auth"
export AIRFLOW__WEBSERVER__BASE_URL="http://localhost:8080"

# Optional: API authentication
export AIRFLOW__API__AUTH_BACKEND="airflow.api.auth.backend.basic_auth"
```

---

## Summary of File Changes

| File | Purpose | Required in 2.10? |
|------|---------|-------------------|
| `airflow.cfg` | Main configuration with `auth_manager` | ✅ YES |
| `webserver_config.py` | OAuth/OIDC configuration and custom security manager | ✅ YES (despite docs saying "legacy") |
| `client_secret.json` | OIDC client credentials | ⚠️ Optional (can use env vars) |
| Custom Python module | Security manager if not in webserver_config.py | ⚠️ Optional |

---

## Migration Checklist

- [ ] Update `airflow.cfg`: Add `[core] auth_manager` setting
- [ ] Update `airflow.cfg`: Move `[api] auth_backend` to `[fab] auth_backends`
- [ ] Create/Update `webserver_config.py` with OIDC configuration
- [ ] Install required packages: `authlib`, `requests`
- [ ] Configure OIDC provider with correct redirect URL
- [ ] Set environment variables for OIDC credentials
- [ ] Test authentication flow
- [ ] Verify role mapping works correctly
- [ ] Update to `/auth/oauth-authorized/` if migrating to Airflow 3.0

---

## Common Issues and Solutions

### Issue 1: "Auth manager not configured"
**Solution**: Ensure `[core] auth_manager` is set in `airflow.cfg`

### Issue 2: "webserver_config.py not loaded"
**Solution**: Verify file is in `$AIRFLOW_HOME` directory and permissions are correct

### Issue 3: OAuth redirect fails
**Solution**: 
- For Airflow 2.x: Use `/oauth-authorized/{provider}`
- For Airflow 3.x: Use `/auth/oauth-authorized/{provider}`

### Issue 4: Roles not syncing
**Solution**: Ensure `AUTH_ROLES_SYNC_AT_LOGIN = True` in webserver_config.py

---

## Next Steps

Would you like me to generate:
1. Sample OIDC provider configurations (Keycloak, Okta, Azure AD)?
2. Database migration scripts for user/role setup?
3. Testing scripts to verify authentication?
4. Production-ready deployment configurations?

Let me know and I'll create those files next!