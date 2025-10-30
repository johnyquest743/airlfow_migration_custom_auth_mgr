# OIDC Custom Redirect URI Setup Guide for Airflow 2.10

## Overview

This guide shows you how to configure a **custom redirect URI** for OIDC authentication in Airflow 2.10, instead of using the default `/oauth-authorized/oidc` path.

## What Changed

### Default Behavior (Before)
- Redirect URI: `http://your-domain:8080/oauth-authorized/oidc`
- Fixed by Flask-AppBuilder, cannot be easily customized

### Custom Behavior (After)
- Redirect URI: `http://your-domain:8080/YOUR-CUSTOM-PATH`
- Examples:
  - `http://your-domain:8080/oidc/callback`
  - `http://your-domain:8080/auth/callback`
  - `http://your-domain:8080/sso/return`
  - Any path you want!

---

## Step-by-Step Setup

### Step 1: Update Your Code

Use the updated `oidc_auth_manager_with_auto_redirect.py` file. The key changes:

1. **Custom redirect URI configuration** in `oauth_authorize()` method
2. **Dynamic route registration** in `_register_custom_callback_route()` method
3. **Unified callback handler** in `_handle_oauth_callback()` method

### Step 2: Configure airflow.cfg

Add the custom redirect URI to your `[oidc]` section:

```ini
[oidc]
client_id = your-client-id
client_secret = your-client-secret
server_metadata_url = https://your-oidc-provider.com/.well-known/openid-configuration

# Set your custom redirect URI here
custom_redirect_uri = http://localhost:8080/oidc/callback

# Or use any other path:
# custom_redirect_uri = http://localhost:8080/auth/callback
# custom_redirect_uri = http://localhost:8080/sso/return

scope = openid email profile groups
default_role = Viewer
role_mapping = {"admin-group": "Admin", "user-group": "User"}
auto_redirect = True
```

### Step 3: Configure Your OIDC Provider

**IMPORTANT**: Update the redirect URI in your OIDC provider settings to match your custom URI.

#### For Okta:
1. Go to Applications → Your App → General Settings
2. Find "Login redirect URIs"
3. Add: `http://your-domain:8080/oidc/callback`
4. Save

#### For Auth0:
1. Go to Applications → Your App → Settings
2. Find "Allowed Callback URLs"
3. Add: `http://your-domain:8080/oidc/callback`
4. Save

#### For Keycloak:
1. Go to Clients → Your Client → Settings
2. Find "Valid Redirect URIs"
3. Add: `http://your-domain:8080/oidc/callback`
4. Save

#### For Azure AD:
1. Go to App registrations → Your App → Authentication
2. Find "Redirect URIs"
3. Add: `http://your-domain:8080/oidc/callback`
4. Save

### Step 4: Restart Airflow

```bash
# Stop Airflow
pkill -f "airflow webserver"
pkill -f "airflow scheduler"

# Clear any cached sessions (optional but recommended)
airflow db reset  # WARNING: This resets the database!
# OR just clear the session table if you know how

# Start Airflow
airflow webserver -p 8080
```

---

## How It Works

### 1. Authorization Flow Starts

When a user tries to access Airflow:
- Auto-redirect is enabled → Immediately redirects to OIDC provider
- Auto-redirect is disabled → Shows "Sign in with OIDC" button

### 2. Redirect to OIDC Provider

The `oauth_authorize()` method:
1. Reads `custom_redirect_uri` from config
2. Generates state and nonce for security
3. Redirects user to OIDC provider with custom redirect URI

```python
# In oauth_authorize method
custom_redirect_uri = conf.get('oidc', 'custom_redirect_uri', fallback=None)

if custom_redirect_uri:
    redirect_uri = custom_redirect_uri
else:
    redirect_uri = url_for('AuthOAuthView.oauth_authorized', provider='oidc', _external=True)
```

### 3. OIDC Provider Authenticates User

User logs in at OIDC provider (Okta, Auth0, etc.)

### 4. Callback to Custom URI

OIDC provider redirects back to your custom URI:
- `http://your-domain:8080/oidc/callback?code=XXX&state=YYY`

### 5. Custom Route Handles Callback

The `_register_custom_callback_route()` method:
1. Parses your custom URI to extract the path
2. Dynamically registers a Flask route at that path
3. Routes the request to the unified callback handler

```python
@custom_callback_bp.route(custom_path)
def custom_oidc_callback():
    auth_view = self.appbuilder.security_manager_class.authoauthview(self.appbuilder)
    return auth_view._handle_oauth_callback('oidc')
```

### 6. User Authentication

The `_handle_oauth_callback()` method:
1. Verifies state (CSRF protection)
2. Exchanges authorization code for tokens
3. Gets user info from OIDC provider
4. Creates/updates user in Airflow
5. Logs user in
6. Redirects to original destination

---

## Configuration Examples

### Example 1: Simple Custom Path

```ini
[oidc]
custom_redirect_uri = http://localhost:8080/auth/callback
```

Your OIDC provider redirect URI: `http://localhost:8080/auth/callback`

### Example 2: Nested Path

```ini
[oidc]
custom_redirect_uri = http://localhost:8080/api/v1/auth/oidc/callback
```

Your OIDC provider redirect URI: `http://localhost:8080/api/v1/auth/oidc/callback`

### Example 3: Production with HTTPS

```ini
[oidc]
custom_redirect_uri = https://airflow.yourcompany.com/sso/callback
```

Your OIDC provider redirect URI: `https://airflow.yourcompany.com/sso/callback`

### Example 4: Keep Default Behavior

Don't set `custom_redirect_uri` or comment it out:

```ini
[oidc]
# custom_redirect_uri = http://localhost:8080/oidc/callback
```

Your OIDC provider redirect URI: `http://localhost:8080/oauth-authorized/oidc`

---

## Testing Your Setup

### Test 1: Check Route Registration

Start Airflow and check logs for:

```
INFO - Custom callback route registered: /oidc/callback
```

### Test 2: Access Airflow

Navigate to `http://localhost:8080`

- Should auto-redirect to OIDC provider (if auto_redirect=True)
- Check browser URL, it should redirect to your OIDC provider

### Test 3: Complete Authentication

Login at OIDC provider and check:

1. Redirects back to your custom URI
2. Check logs for: `Custom callback route triggered: /oidc/callback`
3. User is created/updated
4. User is logged in to Airflow

### Test 4: Check User Creation

```bash
airflow users list
```

You should see your OIDC user with the correct role.

---

## Troubleshooting

### Issue: 404 Not Found on Callback

**Symptoms**: After OIDC login, you get a 404 error.

**Solutions**:
1. Check that `custom_redirect_uri` in airflow.cfg matches OIDC provider settings
2. Verify the route was registered (check logs for "Custom callback route registered")
3. Restart Airflow webserver
4. Ensure the path doesn't conflict with existing Airflow routes

### Issue: Still Using Default Redirect URI

**Symptoms**: OIDC provider redirects to `/oauth-authorized/oidc` instead of custom path.

**Solutions**:
1. Verify `custom_redirect_uri` is set in `[oidc]` section (not `[fab]`)
2. Check OIDC provider has the correct redirect URI configured
3. Clear browser cache and session cookies
4. Restart Airflow webserver

### Issue: State Mismatch Error

**Symptoms**: "Authentication failed: Invalid state" error.

**Solutions**:
1. Clear session cookies
2. Ensure session configuration is correct
3. Check that `SESSION_COOKIE_SECURE` matches your protocol (HTTP vs HTTPS)
4. Try in incognito/private browsing mode

### Issue: User Not Created

**Symptoms**: Authentication succeeds but no user in Airflow.

**Solutions**:
1. Check logs for errors in `auth_user_oauth()`
2. Verify OIDC provider returns `email` field
3. Check that default role exists: `airflow roles list`
4. Verify database connectivity

### Issue: Role Mapping Not Working

**Symptoms**: User created but with wrong role.

**Solutions**:
1. Check `role_mapping` is valid JSON
2. Verify OIDC provider returns `groups` or `roles` field
3. Check logs for role mapping messages
4. Ensure the target Airflow roles exist

---

## Security Considerations

### 1. HTTPS in Production

Always use HTTPS in production:

```ini
[oidc]
custom_redirect_uri = https://airflow.yourcompany.com/oidc/callback

[webserver]
cookie_secure = True
```

### 2. State and Nonce

The implementation includes:
- **State**: CSRF protection
- **Nonce**: Replay attack protection

Both are automatically generated and validated.

### 3. Session Security

Recommended session settings:

```ini
[webserver]
session_lifetime_minutes = 43200  # 30 days
cookie_secure = True  # For HTTPS
cookie_httponly = True  # Prevent XSS
cookie_samesite = Lax  # CSRF protection
```

### 4. Token Storage

OAuth tokens are stored in Flask session (server-side), not in cookies.

---

## Advanced Configuration

### Multiple Redirect URIs

If you need to support multiple environments:

```ini
# Development
# custom_redirect_uri = http://localhost:8080/oidc/callback

# Staging
# custom_redirect_uri = https://airflow-staging.company.com/oidc/callback

# Production
custom_redirect_uri = https://airflow.company.com/oidc/callback
```

Configure all three in your OIDC provider as allowed redirect URIs.

### Path-based Routing

If Airflow is behind a reverse proxy with path-based routing:

```ini
[oidc]
custom_redirect_uri = https://company.com/airflow/oidc/callback

[webserver]
base_url = https://company.com/airflow
```

### Dynamic Redirect URI

For more complex scenarios, you can modify the code to dynamically determine the redirect URI:

```python
# In _register_oidc_provider method
import os
environment = os.getenv('ENVIRONMENT', 'dev')

redirect_uris = {
    'dev': 'http://localhost:8080/oidc/callback',
    'staging': 'https://airflow-staging.company.com/oidc/callback',
    'prod': 'https://airflow.company.com/oidc/callback'
}

custom_redirect_uri = redirect_uris.get(environment)
```

---

## Complete Working Example

### airflow.cfg
```ini
[fab]
auth_type = AUTH_OAUTH
auth_manager = your_package.oidc_auth_manager.OIDCAuthManager

[oidc]
# Okta Configuration
client_id = 0oa1234567890abcdef
client_secret = your-secret-key-here
server_metadata_url = https://dev-123456.okta.com/.well-known/openid-configuration

# Custom redirect URI
custom_redirect_uri = http://localhost:8080/oidc/callback

scope = openid email profile groups
default_role = Viewer
role_mapping = {"Airflow-Admins": "Admin", "Airflow-Users": "User"}
auto_redirect = True

[webserver]
base_url = http://localhost:8080
session_lifetime_minutes = 43200
cookie_secure = False
cookie_samesite = Lax
```

### Okta Application Settings
- Sign-in redirect URIs: `http://localhost:8080/oidc/callback`
- Sign-out redirect URIs: `http://localhost:8080`
- Assignments: Assign relevant groups

### Test Flow
1. Navigate to `http://localhost:8080`
2. Auto-redirects to Okta
3. Login with Okta credentials
4. Redirects back to `http://localhost:8080/oidc/callback?code=XXX`
5. User created/logged in
6. Redirects to Airflow UI

---

## Summary

✅ **Custom redirect URI fully supported**
✅ **Auto-redirect to OIDC provider**
✅ **Dynamic route registration**
✅ **Role mapping from OIDC groups**
✅ **Production-ready security**

The implementation handles all the complexity internally - you just need to set `custom_redirect_uri` in your config!
