# IDA OIDC Authentication Setup Guide for Airflow 2.10
## Internal Firm Authentication - Python 3.12 Compatible

---

## 📋 Overview

This guide provides complete setup instructions for integrating Airflow 2.10 with your firm's internal **IDA (Identity and Access)** authentication system using OIDC protocol.

---

## 🎯 Prerequisites

### Information Needed from IDA Team

Before starting, obtain the following from your firm's IDA team:

1. **IDA OIDC Endpoints**:
   - Authorization URL
   - Token URL
   - UserInfo URL
   - JWKS URI (for token validation)
   - Logout URL
   - Discovery/Metadata URL (`.well-known/openid-configuration`)

2. **Client Credentials**:
   - Client ID (e.g., `airflow-prod`)
   - Client Secret

3. **Group/Role Information**:
   - List of IDA groups available
   - Group naming convention (e.g., `IDA-AIRFLOW-ADMIN`)
   - How groups are returned (in token vs userinfo endpoint)

4. **Network Requirements**:
   - Any proxy configuration needed
   - Firewall rules
   - SSL/TLS certificates if using internal CA

5. **Scopes**:
   - Required OAuth scopes (typically: `openid email profile groups`)
   - Any custom scopes required by IDA

---

## 📁 File Structure

```
$AIRFLOW_HOME/
├── config/
│   ├── oidc_client.json          # IDA client credentials & endpoints
│   ├── oidc_roles.json            # IDA group to Airflow role mapping
│   └── oidc_settings.json         # Additional OIDC settings
├── airflow.cfg                    # Main Airflow configuration
├── webserver_config.py            # Flask-AppBuilder config (IDA-specific)
├── plugins/
│   └── custom_oidc_auth.py        # Custom authentication module
└── .env                           # Environment variables (secrets)
```

---

## 🚀 Step-by-Step Setup

### Step 1: Prepare Environment

```bash
# Set Airflow home
export AIRFLOW_HOME=/opt/airflow
mkdir -p $AIRFLOW_HOME/{config,dags,logs,plugins}

# Create Python 3.12 virtual environment
python3.12 -m venv $AIRFLOW_HOME/venv
source $AIRFLOW_HOME/venv/bin/activate

# Install dependencies
pip install apache-airflow==2.10.5
pip install apache-airflow-providers-fab==1.2.0
pip install authlib==1.3.0
pip install requests
pip install cryptography
pip install psycopg2-binary  # For PostgreSQL
```

### Step 2: Configure IDA Client Settings

Create `$AIRFLOW_HOME/config/oidc_client.json` with your IDA details:

```json
{
  "providers": [
    {
      "name": "ida",
      "enabled": true,
      "type": "custom_ida",
      "client_id": "YOUR_IDA_CLIENT_ID",
      "client_secret": "YOUR_IDA_CLIENT_SECRET",
      "issuer": "https://ida.yourfirm.com",
      "server_metadata_url": "https://ida.yourfirm.com/.well-known/openid-configuration",
      "authorize_url": "https://ida.yourfirm.com/oauth2/authorize",
      "access_token_url": "https://ida.yourfirm.com/oauth2/token",
      "userinfo_url": "https://ida.yourfirm.com/oauth2/userinfo",
      "jwks_uri": "https://ida.yourfirm.com/oauth2/jwks",
      "logout_url": "https://ida.yourfirm.com/oauth2/logout",
      "scope": "openid email profile groups",
      "icon": "fa-building",
      "display_name": "IDA Login",
      "username_claim": "preferred_username",
      "group_claim": "groups",
      "verify_ssl": true,
      "ca_bundle_path": "/path/to/your/firm/ca-bundle.crt"
    }
  ],
  "redirect_uris": [
    "http://localhost:8080/oauth-authorized/ida",
    "https://airflow.yourfirm.com/oauth-authorized/ida"
  ]
}
```

**Important Fields to Update**:
- `client_id`: From IDA team
- `client_secret`: From IDA team
- All URLs (`issuer`, `authorize_url`, etc.)
- `ca_bundle_path`: If using internal CA certificates
- `scope`: Verify with IDA team

### Step 3: Configure Role Mapping

Create `$AIRFLOW_HOME/config/oidc_roles.json`:

```json
{
  "role_mapping": {
    "IDA-AIRFLOW-ADMIN": ["Admin"],
    "IDA-AIRFLOW-OPS": ["Op"],
    "IDA-AIRFLOW-USER": ["User"],
    "IDA-AIRFLOW-VIEWER": ["Viewer"],
    "IDA-DATA-ENGINEERING": ["Op"],
    "IDA-DATA-ANALYSTS": ["User"]
  }
}
```

**Update with your firm's actual IDA group names!**

### Step 4: Configure Additional Settings

Create `$AIRFLOW_HOME/config/oidc_settings.json`:

```json
{
  "authentication": {
    "auth_user_registration": true,
    "auth_user_registration_role": "Viewer",
    "auth_roles_sync_at_login": true
  },
  "session": {
    "session_lifetime_hours": 8,
    "session_cookie_secure": true,
    "session_cookie_httponly": true
  },
  "security": {
    "csrf_enabled": true
  },
  "network": {
    "request_timeout": 30,
    "verify_ssl": true
  }
}
```

### Step 5: Configure airflow.cfg

Edit `$AIRFLOW_HOME/airflow.cfg`:

```ini
[core]
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
dags_folder = /opt/airflow/dags
base_log_folder = /opt/airflow/logs
executor = LocalExecutor

[database]
sql_alchemy_conn = postgresql+psycopg2://airflow:airflow@localhost:5432/airflow

[fab]
auth_backends = airflow.providers.fab.auth_manager.api.auth.backend.basic_auth

[webserver]
base_url = https://airflow.yourfirm.com
web_server_host = 0.0.0.0
web_server_port = 8080
```

Generate and add secrets:

```bash
# Generate Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Generate secret key
openssl rand -hex 30
```

Add to `airflow.cfg`:

```ini
[core]
fernet_key = YOUR_GENERATED_FERNET_KEY

[webserver]
secret_key = YOUR_GENERATED_SECRET_KEY
```

### Step 6: Copy Configuration Files

Copy the IDA-specific configuration files:

1. **webserver_config.py**: See artifact "ida-webserver-config"
   - Copy to `$AIRFLOW_HOME/webserver_config.py`
   - No modifications needed - it automatically reads JSON files

2. **custom_oidc_auth.py**: See artifact "custom-oidc-auth-module"
   - Copy to `$AIRFLOW_HOME/plugins/custom_oidc_auth.py`

```bash
# Verify files are in place
ls -la $AIRFLOW_HOME/webserver_config.py
ls -la $AIRFLOW_HOME/plugins/custom_oidc_auth.py
ls -la $AIRFLOW_HOME/config/*.json
```

### Step 7: Register Airflow with IDA

Contact your IDA team to register Airflow as an OAuth client. Provide:

1. **Application Name**: `Airflow Production` (or appropriate name)
2. **Client Type**: `Confidential`
3. **Redirect URIs**:
   ```
   http://localhost:8080/oauth-authorized/ida  # For development
   https://airflow.yourfirm.com/oauth-authorized/ida  # For production
   ```
4. **Post-Logout Redirect URIs**:
   ```
   http://localhost:8080
   https://airflow.yourfirm.com
   ```
5. **Scopes Needed**: `openid email profile groups`
6. **Token Endpoint Auth Method**: `client_secret_post`

They will provide you with:
- Client ID
- Client Secret

Update these in `oidc_client.json`.

### Step 8: Configure Network (If Behind Proxy)

If your firm requires proxy to reach IDA:

Update `oidc_client.json`:

```json
{
  "providers": [{
    ...
    "proxy_enabled": true,
    "proxy_url": "http://proxy.yourfirm.com:8080",
    "custom_headers": {
      "X-Firm-ID": "your-firm-id"
    }
  }]
}
```

### Step 9: Initialize Airflow Database

```bash
# Source environment
export AIRFLOW_HOME=/opt/airflow
source $AIRFLOW_HOME/venv/bin/activate

# Initialize database
airflow db migrate

# Create a fallback admin user (optional)
airflow users create \
  --username admin \
  --firstname Admin \
  --lastname User \
  --role Admin \
  --email admin@yourfirm.com \
  --password admin
```

### Step 10: Start Airflow

```bash
# Start webserver
airflow webserver -p 8080 &

# Start scheduler
airflow scheduler &

# Check logs
tail -f $AIRFLOW_HOME/logs/webserver.log
```

### Step 11: Test IDA Authentication

1. Open browser: `https://airflow.yourfirm.com` or `http://localhost:8080`
2. You should see an "IDA Login" button
3. Click it to redirect to IDA
4. Login with your firm credentials
5. You should be redirected back to Airflow
6. Verify your assigned roles

---

## 🧪 Validation & Testing

### Validate Configuration

Create validation script `$AIRFLOW_HOME/validate_ida.py`:

```python
#!/usr/bin/env python3
import json
import sys
from pathlib import Path
import requests

def validate_ida_config():
    airflow_home = Path('/opt/airflow')
    config_dir = airflow_home / 'config'
    
    print("="*70)
    print("IDA OIDC Configuration Validation")
    print("="*70)
    
    errors = []
    
    # Check files exist
    required_files = ['oidc_client.json', 'oidc_roles.json', 'oidc_settings.json']
    for filename in required_files:
        file_path = config_dir / filename
        if not file_path.exists():
            errors.append(f"Missing file: {file_path}")
        else:
            try:
                with open(file_path) as f:
                    json.load(f)
                print(f"✓ {filename} is valid")
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in {filename}: {e}")
    
    # Load and validate client config
    try:
        with open(config_dir / 'oidc_client.json') as f:
            client_config = json.load(f)
        
        providers = client_config.get('providers', [])
        if not providers:
            errors.append("No providers configured")
        
        for provider in providers:
            if provider.get('type') == 'custom_ida':
                print(f"\nIDA Provider Configuration:")
                print(f"  Name: {provider.get('name')}")
                print(f"  Client ID: {provider.get('client_id', 'NOT SET')}")
                print(f"  Issuer: {provider.get('issuer', 'NOT SET')}")
                
                # Check if client secret is set
                if provider.get('client_secret', '').startswith('REPLACE'):
                    errors.append("Client secret not updated in oidc_client.json")
                
                # Test metadata endpoint
                metadata_url = provider.get('server_metadata_url')
                if metadata_url:
                    try:
                        print(f"\nTesting IDA metadata endpoint...")
                        response = requests.get(metadata_url, timeout=10, verify=provider.get('verify_ssl', True))
                        if response.status_code == 200:
                            print(f"✓ Metadata endpoint accessible")
                            metadata = response.json()
                            print(f"  Issuer: {metadata.get('issuer')}")
                            print(f"  Authorization endpoint: {metadata.get('authorization_endpoint')}")
                        else:
                            errors.append(f"Metadata endpoint returned {response.status_code}")
                    except Exception as e:
                        errors.append(f"Cannot reach metadata endpoint: {e}")
    
    except Exception as e:
        errors.append(f"Error validating configuration: {e}")
    
    # Print results
    print("\n" + "="*70)
    if errors:
        print("✗ Validation failed with errors:")
        for error in errors:
            print(f"  - {error}")
        return False
    else:
        print("✓ All validation checks passed!")
        return True
    print("="*70)

if __name__ == '__main__':
    success = validate_ida_config()
    sys.exit(0 if success else 1)
```

Run validation:

```bash
python $AIRFLOW_HOME/validate_ida.py
```

### Test IDA Endpoints

```bash
# Test metadata endpoint
curl https://ida.yourfirm.com/.well-known/openid-configuration

# Test with proper CA certificate
curl --cacert /path/to/firm-ca.crt \
     https://ida.yourfirm.com/.well-known/openid-configuration
```

### Debug Mode

Enable debug logging temporarily in `oidc_settings.json`:

```json
{
  "logging": {
    "fab_logging_level": "DEBUG",
    "log_userinfo_requests": true,
    "log_authorization_requests": true
  }
}
```

Restart Airflow and check logs:

```bash
tail -f $AIRFLOW_HOME/logs/webserver.log | grep -i ida
```

---

## 🔧 Troubleshooting

### Issue 1: "Cannot connect to IDA endpoints"

**Possible Causes**:
- Firewall blocking connection
- Proxy not configured
- SSL certificate issues

**Solutions**:
```bash
# Test network connectivity
curl -v https://ida.yourfirm.com

# Test with proxy
curl -x http://proxy.yourfirm.com:8080 https://ida.yourfirm.com

# Test with custom CA
curl --cacert /path/to/ca.crt https://ida.yourfirm.com
```

Update `oidc_client.json` with correct proxy and CA settings.

### Issue 2: "SSL Certificate Verification Failed"

**Solution**:

1. Get your firm's CA certificate from IT team
2. Update `oidc_client.json`:
   ```json
   {
     "verify_ssl": true,
     "ca_bundle_path": "/etc/ssl/certs/yourfirm-ca.crt"
   }
   ```

3. Or for development only (NOT production):
   ```json
   {
     "verify_ssl": false
   }
   ```

### Issue 3: "No groups returned from IDA"

**Check**:
1. Verify `group_claim` name in `oidc_client.json`
2. Common values: `groups`, `roles`, `memberOf`
3. Contact IDA team to confirm claim name

**Test**:
```bash
# Decode access token to see claims
# Use https://jwt.io or:
python -c "
import jwt
token = 'YOUR_ACCESS_TOKEN'
decoded = jwt.decode(token, options={'verify_signature': False})
print(decoded)
"
```

### Issue 4: "User not found in IDA groups"

**Verify**:
1. User is assigned to correct IDA groups
2. Group names in `oidc_roles.json` match exactly
3. Check case sensitivity

Update `oidc_settings.json`:
```json
{
  "group_extraction": {
    "ida": {
      "case_sensitive": false,
      "normalize_names": true
    }
  }
}
```

### Issue 5: "Redirect URI mismatch"

**Solution**:
1. Check redirect URI registered in IDA matches exactly
2. For Airflow 2.x: `/oauth-authorized/ida`
3. For Airflow 3.x: `/auth/oauth-authorized/ida`
4. Must include protocol: `https://` not just `airflow.yourfirm.com`

---

## 🔐 Security Checklist

Before production deployment:

- [ ] HTTPS enabled (not HTTP)
- [ ] Valid SSL certificates installed
- [ ] `session_cookie_secure` set to `true`
- [ ] Client secret stored securely (not in version control)
- [ ] Fernet key rotated and secured
- [ ] Database credentials secured
- [ ] Firewall rules configured
- [ ] Network segmentation in place
- [ ] Audit logging enabled
- [ ] Regular security reviews scheduled
- [ ] Incident response plan documented

---

## 📞 Getting Help

### From IDA Team

Contact your firm's IDA team for:
- Client ID and secret
- Endpoint URLs
- Group/role information
- SSL certificates
- Troubleshooting authentication issues

### From Airflow Team

Contact your Airflow administrators for:
- Deployment issues
- Role mapping configuration
- Database configuration
- DAG access issues

---

## 📚 Additional Documentation

- **IDA Documentation**: Check your firm's internal wiki/confluence
- **Airflow Docs**: https://airflow.apache.org/docs/apache-airflow/2.10.5/
- **OIDC Spec**: https://openid.net/specs/openid-connect-core-1_0.html

---

## ✅ Post-Setup Checklist

- [ ] All JSON configuration files created
- [ ] IDA endpoints verified and accessible
- [ ] Client credentials obtained from IDA team
- [ ] Role mapping configured for your firm's groups
- [ ] SSL certificates installed (if needed)
- [ ] Proxy configured (if needed)
- [ ] Redirect URIs registered with IDA
- [ ] Configuration validated with validation script
- [ ] Test login successful
- [ ] User groups mapped correctly
- [ ] Logs checked for errors
- [ ] Production URL configured
- [ ] Documentation updated with firm-specific details

---

**Version**: 1.0 (IDA-specific)  
**Last Updated**: 2025-01-01  
**Maintainer**: Data Platform Team