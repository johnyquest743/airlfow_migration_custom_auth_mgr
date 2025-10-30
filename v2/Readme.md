I'll help you resolve these issues with your Airflow 2.10 OIDC authentication migration. The problems you're facing are due to changes in how Airflow 2.10 handles authentication and routing.

## Issues Identified

1. **Route Registration**: In Airflow 2.10+, custom routes need to be registered differently
2. **OAuth Callback URL**: FAB has a default OAuth callback pattern that's overriding your custom routes
3. **Auto-redirect**: The login page requires configuration changes to bypass the button

## Solution

Here's the corrected implementation:Now here's the Airflow configuration file with all necessary settings:Now let me create an alternative version that includes auto-redirect functionality:## Key Changes Explained

### 1. **Route Registration Issue - SOLVED**

**Problem**: Your custom routes weren't being called because Airflow 2.10+ uses Flask-AppBuilder's built-in OAuth handling.

**Solution**: Instead of creating custom routes, override the `OIDCSecurityManager` class methods:
- `oauth_user_info()` - Extracts user info from OAuth response
- `auth_user_oauth()` - Authenticates and creates/updates the user

### 2. **Redirect URI Issue - SOLVED**

**Problem**: FAB defaults to `/oauth-authorized/oidc` callback URL.

**Solution**: 
- The redirect URI is **automatically** set to `/oauth-authorized/<provider_name>` where provider name is `oidc`
- In your OIDC provider settings, set the redirect URI to: `http://your-domain:8080/oauth-authorized/oidc`
- The `redirect_uri` config is for reference only

### 3. **Auto-Redirect (Bypass Login Button) - SOLVED**

**Problem**: Users see a "Sign in with OIDC" button instead of auto-redirecting.

**Solution**: Two approaches:

**Approach A** (Recommended): Use the second code file with `CustomAuthOAuthView` that overrides the login method to auto-redirect.

**Approach B**: Add JavaScript to custom login template (less clean).

## Complete Setup Instructions

### Step 1: Update Your Code

Use either:
- First artifact: Basic OIDC without auto-redirect
- Second artifact: OIDC with auto-redirect

### Step 2: Configure airflow.cfg

```ini
[fab]
auth_type = AUTH_OAUTH
auth_manager = your_package.oidc_auth_manager.OIDCAuthManager

[oidc]
client_id = your-client-id
client_secret = your-client-secret
server_metadata_url = https://your-provider.com/.well-known/openid-configuration
scope = openid email profile groups
default_role = Viewer
role_mapping = {"admin-group": "Admin", "user-group": "User"}
auto_redirect = True  # For auto-redirect version
```

### Step 3: Configure OIDC Provider

In your OIDC provider (Okta/Auth0/Keycloak), set:
- **Redirect URI**: `http://your-domain:8080/oauth-authorized/oidc`
- **Logout URI** (optional): `http://your-domain:8080`

### Step 4: Restart Airflow

```bash
airflow webserver
```

## Testing Checklist

1. ✅ Navigate to Airflow URL
2. ✅ Should auto-redirect to OIDC provider (with auto-redirect version)
3. ✅ After login, redirects back to `/oauth-authorized/oidc`
4. ✅ User is created/updated in Airflow
5. ✅ User is logged in with correct role

## Common Issues & Solutions

**Issue**: Still seeing login button
- **Fix**: Use the second artifact with `CustomAuthOAuthView`
- **Fix**: Ensure `auto_redirect = True` in config

**Issue**: 404 on callback
- **Fix**: Ensure redirect URI in OIDC provider matches `/oauth-authorized/oidc`

**Issue**: User not created
- **Fix**: Check logs for errors in `auth_user_oauth()`
- **Fix**: Ensure email is returned by OIDC provider

Let me know if you need any clarification or run into issues!