# Airflow 2.10 OIDC Authentication - Complete Deployment Guide
## Python 3.12 Compatible | JSON-Based Configuration

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [Quick Start](#quick-start)
4. [Detailed Setup](#detailed-setup)
5. [Configuration Files](#configuration-files)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

This deployment package provides a complete OIDC authentication solution for Airflow 2.10 with:

- ✅ **JSON-based configuration** - All OIDC settings in JSON files
- ✅ **Python 3.12 compatible**
- ✅ **Multiple provider support** - Keycloak, Okta, Azure AD, Google
- ✅ **Custom authentication module** - Using authlib
- ✅ **Complete role mapping** - Group-to-role mapping
- ✅ **Production ready** - Includes security best practices

---

## 📁 File Structure

```
$AIRFLOW_HOME/
├── config/
│   ├── oidc_client.json          # Client credentials & provider config
│   ├── oidc_roles.json            # Role mapping configuration
│   └── oidc_settings.json         # Additional OIDC settings
├── airflow.cfg                    # Main Airflow configuration
├── webserver_config.py            # Flask-AppBuilder configuration
├── plugins/
│   └── custom_oidc_auth.py        # Custom authentication module
├── dags/                          # Your DAG files
├── logs/                          # Airflow logs
└── .env                           # Environment variables (secrets)
```

---

## 🚀 Quick Start

### Option 1: Automated Setup

```bash
# Download setup script
wget https://your-repo/setup_airflow_oidc.py

# Run setup for your provider
python setup_airflow_oidc.py --provider keycloak

# Update configuration files with your credentials
vi $AIRFLOW_HOME/config/oidc_client.json

# Initialize Airflow
source $AIRFLOW_HOME/env_template.sh
airflow db migrate

# Start Airflow
airflow webserver &
airflow scheduler &
```

### Option 2: Manual Setup

Follow the detailed setup instructions below.

---

## 📝 Detailed Setup

### Step 1: Install Dependencies

```bash
# Python 3.12 environment
python3.12 -m venv airflow-venv
source airflow-venv/bin/activate

# Install Airflow and dependencies
pip install apache-airflow==2.10.5
pip install apache-airflow-providers-fab==1.2.0
pip install authlib==1.3.0
pip install requests
pip install cryptography
```

### Step 2: Set Airflow Home

```bash
export AIRFLOW_HOME=/opt/airflow
mkdir -p $AIRFLOW_HOME/{config,dags,logs,plugins}
```

### Step 3: Create Configuration Files

#### **File 1: $AIRFLOW_HOME/config/oidc_client.json**

See artifact "oidc-json-configs" for complete template. Key sections:

```json
{
  "providers": [
    {
      "name": "keycloak",
      "enabled": true,
      "client_id": "YOUR_CLIENT_ID",
      "client_secret": "YOUR_CLIENT_SECRET",
      "server_metadata_url": "https://keycloak.example.com/realms/airflow/.well-known/openid-configuration",
      ...
    }
  ]
}
```

**Important**: Update these fields:
- `client_id`
- `client_secret`
- `issuer` URL
- `server_metadata_url`

#### **File 2: $AIRFLOW_HOME/config/oidc_roles.json**

See artifact "oidc-roles-json" for complete template:

```json
{
  "role_mapping": {
    "airflow_admin": ["Admin"],
    "airflow_op": ["Op"],
    "airflow_user": ["User"],
    "airflow_viewer": ["Viewer"]
  }
}
```

**Important**: Map your OIDC groups to Airflow roles.

#### **File 3: $AIRFLOW_HOME/config/oidc_settings.json**

See artifact "oidc-settings-json" for complete template. Customize:
- Session lifetime
- Security settings
- Rate limiting
- Logging preferences

#### **File 4: $AIRFLOW_HOME/airflow.cfg**

See artifact "complete-airflow-cfg" for full configuration. Key settings:

```ini
[core]
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager

[fab]
auth_backends = airflow.providers.fab.auth_manager.api.auth.backend.basic_auth

[database]
sql_alchemy_conn = postgresql+psycopg2://airflow:airflow@localhost:5432/airflow
```

**Generate secrets**:
```bash
# Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Secret key
openssl rand -hex 30
```

#### **File 5: $AIRFLOW_HOME/webserver_config.py**

See artifact "complete-webserver-config" for the complete file. This file:
- Loads JSON configurations
- Configures OAuth providers
- Sets up Flask-AppBuilder

**No changes needed** - it automatically reads from JSON files!

#### **File 6: $AIRFLOW_HOME/plugins/custom_oidc_auth.py**

See artifact "custom-oidc-auth-module" for the complete custom authentication module. This provides:
- Configuration loading from JSON
- Token validation
- User info extraction
- Role mapping
- Multiple provider support

Copy this file to your plugins directory.

### Step 4: Configure Your OIDC Provider

#### For Keycloak:

1. Create realm: `airflow`
2. Create client: `airflow`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `http://localhost:8080/oauth-authorized/keycloak`
3. Create roles/groups: `airflow_admin`, `airflow_op`, `airflow_user`, `airflow_viewer`
4. Assign users to groups
5. Copy client secret to `oidc_client.json`

#### For Okta:

1. Create OIDC Web Application
2. Configure redirect URI: `http://localhost:8080/oauth-authorized/okta`
3. Create groups: `AirflowAdmins`, `AirflowOperators`, etc.
4. Assign users to groups
5. Copy client credentials to `oidc_client.json`

#### For Azure AD:

1. Register application in Azure Portal
2. Add redirect URI: `http://localhost:8080/oauth-authorized/azure`
3. Generate client secret
4. Grant API permissions: `User.Read`, `GroupMember.Read.All`
5. Create security groups
6. Copy tenant ID, client ID, and secret to `oidc_client.json`

### Step 5: Initialize Airflow Database

```bash
# Initialize database
airflow db migrate

# Create initial admin user (optional - for fallback)
airflow users create \
  --username admin \
  --firstname Admin \
  --lastname User \
  --role Admin \
  --email admin@example.com \
  --password admin
```

### Step 6: Start Airflow

```bash
# Start webserver
airflow webserver -p 8080 &

# Start scheduler
airflow scheduler &
```

### Step 7: Test Authentication

1. Open browser: `http://localhost:8080`
2. Click on OIDC provider button (Keycloak/Okta/Azure)
3. Login with your OIDC credentials
4. Verify you're redirected back to Airflow
5. Check your assigned roles

---

## 🔧 Configuration Files

### Environment Variables

Create `$AIRFLOW_HOME/.env`:

```bash
# Core Configuration
export AIRFLOW_HOME=/opt/airflow
export AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager

# Database
export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://airflow:airflow@localhost:5432/airflow

# Secrets (generated earlier)
export AIRFLOW__CORE__FERNET_KEY=your-fernet-key-here
export AIRFLOW__WEBSERVER__SECRET_KEY=your-secret-key-here

# OIDC Provider Selection
export OIDC_PROVIDER=keycloak
```

Load with: `source $AIRFLOW_HOME/.env`

---

## 🧪 Testing

### Validate Configuration

```bash
# Run validation script
python setup_airflow_oidc.py --validate-only

# Or use custom module validation
python $AIRFLOW_HOME/plugins/custom_oidc_auth.py
```

### Test OIDC Endpoints

```bash
# Test metadata endpoint
curl https://your-oidc-provider/.well-known/openid-configuration

# Test with Python
python -c "
import requests
resp = requests.get('https://your-oidc-provider/.well-known/openid-configuration')
print(resp.json())
"
```

### Debug Logging

Enable debug logging in `$AIRFLOW_HOME/config/oidc_settings.json`:

```json
{
  "logging": {
    "fab_logging_level": "DEBUG",
    "log_userinfo_requests": true,
    "log_authorization_requests": true
  }
}
```

---

## 🔍 Troubleshooting

### Common Issues

#### 1. "No active OIDC provider configured"

**Solution**:
- Check `oidc_client.json` exists in config directory
- Ensure at least one provider has `"enabled": true`
- Verify JSON is valid (no syntax errors)

#### 2. "Failed to fetch user info"

**Solution**:
- Verify `userinfo_url` is correct in `oidc_client.json`
- Check access token is valid
- Ensure network connectivity to OIDC provider
- Review Airflow logs: `$AIRFLOW_HOME/logs/`

#### 3. "No groups matched role mapping"

**Solution**:
- Verify group claim name in `oidc_client.json` (`group_claim`)
- Check role mapping in `oidc_roles.json`
- Ensure OIDC provider includes groups in token/userinfo
- For Azure AD: Enable group claims in token configuration

#### 4. "Redirect URI mismatch"

**Solution**:
- For Airflow 2.x: Use `/oauth-authorized/{provider}`
- For Airflow 3.x: Use `/auth/oauth-authorized/{provider}`
- Update redirect URI in OIDC provider configuration
- Match exactly with `redirect_uris` in `oidc_client.json`

#### 5. "Module 'authlib' not found"

**Solution**:
```bash
pip install authlib==1.3.0
```

#### 6. "Configuration file not found"

**Solution**:
- Verify `$AIRFLOW_HOME` is set correctly
- Check files are in `$AIRFLOW_HOME/config/` directory
- Ensure proper file permissions: `chmod 644 $AIRFLOW_HOME/config/*.json`

### Debugging Commands

```bash
# Check Airflow configuration
airflow config list

# Check database connection
airflow db check

# View webserver logs
tail -f $AIRFLOW_HOME/logs/webserver.log

# Test Python environment
python -c "import authlib; print(authlib.__version__)"
python -c "import airflow; print(airflow.__version__)"

# Validate JSON files
python -m json.tool $AIRFLOW_HOME/config/oidc_client.json
python -m json.tool $AIRFLOW_HOME/config/oidc_roles.json
python -m json.tool $AIRFLOW_HOME/config/oidc_settings.json
```

---

## 📊 Architecture Diagram

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ 1. Access Airflow
       ▼
┌─────────────────────────────────────┐
│   Airflow Webserver (2.10)          │
│   - webserver_config.py              │
│   - custom_oidc_auth.py (plugin)     │
└──────┬──────────────────────────────┘
       │ 2. Load config from JSON
       ▼
┌─────────────────────────────────────┐
│   Configuration Files                │
│   - oidc_client.json                 │
│   - oidc_roles.json                  │
│   - oidc_settings.json               │
└──────┬──────────────────────────────┘
       │ 3. Redirect to OIDC
       ▼
┌─────────────────────────────────────┐
│   OIDC Provider                      │
│   (Keycloak/Okta/Azure AD)           │
└──────┬──────────────────────────────┘
       │ 4. User authenticates
       │ 5. Return tokens
       ▼
┌─────────────────────────────────────┐
│   custom_oidc_auth.py                │
│   - Validate tokens                  │
│   - Fetch user info                  │
│   - Extract groups                   │
│   - Map to Airflow roles             │
└──────┬──────────────────────────────┘
       │ 6. Create/update user
       ▼
┌─────────────────────────────────────┐
│   Airflow Metadata Database          │
│   (PostgreSQL/MySQL)                 │
└─────────────────────────────────────┘
```

---

## 🔐 Security Best Practices

1. **Use HTTPS in production**
   - Set `session_cookie_secure: true` in `oidc_settings.json`
   - Use valid SSL certificates

2. **Secure secrets**
   - Never commit `oidc_client.json` to version control
   - Use environment variables or secrets manager
   - Rotate client secrets regularly

3. **Enable CSRF protection**
   - Already enabled by default in configuration

4. **Regular updates**
   - Keep Airflow and dependencies updated
   - Monitor security advisories

5. **Audit logging**
   - Enable audit logs in `oidc_settings.json`
   - Monitor authentication attempts

---

## 📚 Additional Resources

- [Airflow Documentation](https://airflow.apache.org/docs/apache-airflow/2.10.5/)
- [Authlib Documentation](https://docs.authlib.org/)
- [OIDC Specification](https://openid.net/connect/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Okta Developer Docs](https://developer.okta.com/)
- [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)

---

## 📞 Support

For issues:
1. Check troubleshooting section above
2. Review Airflow logs
3. Validate configuration with provided scripts
4. Check OIDC provider documentation

---

## ✅ Checklist

Before going to production:

- [ ] All JSON configuration files created and validated
- [ ] Client credentials configured correctly
- [ ] Role mapping tested
- [ ] HTTPS enabled
- [ ] Secrets secured (not in version control)
- [ ] Database properly configured (PostgreSQL/MySQL)
- [ ] Backup strategy in place
- [ ] Monitoring and logging configured
- [ ] Tested login flow end-to-end
- [ ] Tested role-based access control
- [ ] Documented custom configurations
- [ ] Team trained on new authentication

---

**Version**: 1.0  
**Last Updated**: 2025-01-01  
**Compatible**: Airflow 2.10.x, Python 3.12+