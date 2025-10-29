# =============================================================================
# Airflow 2.10 OIDC Authentication - Troubleshooting & Migration Scripts
# =============================================================================

import os
import sys
import logging
from sqlalchemy import create_engine, text
from datetime import datetime

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# =============================================================================
# DATABASE MIGRATION SCRIPT
# =============================================================================

class AirflowAuthMigration:
    """
    Migration script to prepare Airflow database for OIDC authentication
    """
    
    def __init__(self, connection_string=None):
        """Initialize with database connection"""
        self.conn_string = connection_string or os.getenv(
            'AIRFLOW__DATABASE__SQL_ALCHEMY_CONN',
            'postgresql+psycopg2://airflow:airflow@localhost/airflow'
        )
        self.engine = create_engine(self.conn_string)
    
    def check_existing_users(self):
        """Check existing users in the database"""
        log.info("Checking existing users...")
        
        query = text("""
            SELECT id, username, email, first_name, last_name, active
            FROM ab_user
            ORDER BY id
        """)
        
        with self.engine.connect() as conn:
            result = conn.execute(query)
            users = result.fetchall()
            
            if users:
                log.info(f"Found {len(users)} existing users:")
                for user in users:
                    log.info(f"  - ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Active: {user[5]}")
            else:
                log.info("No existing users found")
            
            return users
    
    def check_existing_roles(self):
        """Check existing roles in the database"""
        log.info("Checking existing roles...")
        
        query = text("""
            SELECT id, name
            FROM ab_role
            ORDER BY id
        """)
        
        with self.engine.connect() as conn:
            result = conn.execute(query)
            roles = result.fetchall()
            
            if roles:
                log.info(f"Found {len(roles)} existing roles:")
                for role in roles:
                    log.info(f"  - ID: {role[0]}, Name: {role[1]}")
            else:
                log.info("No existing roles found")
            
            return roles
    
    def create_oidc_roles(self):
        """Create roles for OIDC authentication if they don't exist"""
        log.info("Creating OIDC roles...")
        
        required_roles = ['Admin', 'Op', 'User', 'Viewer', 'Public']
        
        with self.engine.connect() as conn:
            for role_name in required_roles:
                # Check if role exists
                check_query = text("SELECT id FROM ab_role WHERE name = :role_name")
                result = conn.execute(check_query, {'role_name': role_name})
                
                if result.fetchone():
                    log.info(f"  ✓ Role '{role_name}' already exists")
                else:
                    # Create role
                    insert_query = text("""
                        INSERT INTO ab_role (name)
                        VALUES (:role_name)
                    """)
                    conn.execute(insert_query, {'role_name': role_name})
                    conn.commit()
                    log.info(f"  + Created role '{role_name}'")
    
    def backup_users(self, backup_file='airflow_users_backup.sql'):
        """Create a backup of existing users"""
        log.info(f"Creating user backup to {backup_file}...")
        
        query = text("""
            SELECT * FROM ab_user
        """)
        
        with self.engine.connect() as conn:
            result = conn.execute(query)
            users = result.fetchall()
            
            with open(backup_file, 'w') as f:
                f.write(f"-- Airflow Users Backup - {datetime.now()}\n")
                f.write(f"-- Total users: {len(users)}\n\n")
                
                for user in users:
                    f.write(f"-- User: {user[1]}\n")
                    f.write(f"-- Email: {user[2]}\n\n")
            
            log.info(f"✓ Backup created: {backup_file}")
    
    def migrate(self, create_backup=True):
        """Run full migration"""
        log.info("="*60)
        log.info("Starting Airflow OIDC Authentication Migration")
        log.info("="*60)
        
        try:
            # Step 1: Check current state
            self.check_existing_users()
            self.check_existing_roles()
            
            # Step 2: Create backup
            if create_backup:
                self.backup_users()
            
            # Step 3: Create OIDC roles
            self.create_oidc_roles()
            
            # Step 4: Final verification
            log.info("\nMigration complete! Final state:")
            self.check_existing_roles()
            
            log.info("="*60)
            log.info("✓ Migration completed successfully!")
            log.info("="*60)
            
        except Exception as e:
            log.error(f"✗ Migration failed: {e}")
            raise


# =============================================================================
# TROUBLESHOOTING SCRIPT
# =============================================================================

class OIDCTroubleshooter:
    """
    Troubleshooting tool for Airflow OIDC authentication issues
    """
    
    def __init__(self):
        self.issues_found = []
        self.warnings = []
    
    def check_environment_variables(self, provider='keycloak'):
        """Check if required environment variables are set"""
        log.info("Checking environment variables...")
        
        common_vars = [
            'AIRFLOW__CORE__AUTH_MANAGER',
            'AIRFLOW__FAB__AUTH_BACKENDS',
        ]
        
        provider_vars = {
            'keycloak': [
                'KEYCLOAK_BASE_URL',
                'KEYCLOAK_REALM',
                'KEYCLOAK_CLIENT_ID',
                'KEYCLOAK_CLIENT_SECRET',
            ],
            'okta': [
                'OKTA_DOMAIN',
                'OKTA_CLIENT_ID',
                'OKTA_CLIENT_SECRET',
            ],
            'azure': [
                'AZURE_TENANT_ID',
                'AZURE_CLIENT_ID',
                'AZURE_CLIENT_SECRET',
            ]
        }
        
        required_vars = common_vars + provider_vars.get(provider, [])
        
        for var in required_vars:
            value = os.getenv(var)
            if value:
                # Mask secrets
                if 'SECRET' in var or 'PASSWORD' in var:
                    log.info(f"  ✓ {var}: {'*' * 20}")
                else:
                    log.info(f"  ✓ {var}: {value}")
            else:
                issue = f"Missing environment variable: {var}"
                self.issues_found.append(issue)
                log.warning(f"  ✗ {issue}")
    
    def check_webserver_config(self):
        """Check if webserver_config.py exists and is valid"""
        log.info("Checking webserver_config.py...")
        
        airflow_home = os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow'))
        config_path = os.path.join(airflow_home, 'webserver_config.py')
        
        if os.path.exists(config_path):
            log.info(f"  ✓ Found webserver_config.py at {config_path}")
            
            # Check if file is readable
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                    
                    # Check for required components
                    required_components = [
                        ('AUTH_TYPE', 'AUTH_TYPE not defined'),
                        ('OAUTH_PROVIDERS', 'OAUTH_PROVIDERS not defined'),
                        ('SECURITY_MANAGER_CLASS', 'SECURITY_MANAGER_CLASS not defined'),
                    ]
                    
                    for component, error_msg in required_components:
                        if component in content:
                            log.info(f"  ✓ {component} is defined")
                        else:
                            issue = f"webserver_config.py: {error_msg}"
                            self.issues_found.append(issue)
                            log.warning(f"  ✗ {issue}")
                
            except Exception as e:
                issue = f"Cannot read webserver_config.py: {e}"
                self.issues_found.append(issue)
                log.error(f"  ✗ {issue}")
        else:
            issue = f"webserver_config.py not found at {config_path}"
            self.issues_found.append(issue)
            log.error(f"  ✗ {issue}")
    
    def check_packages(self):
        """Check if required Python packages are installed"""
        log.info("Checking required Python packages...")
        
        required_packages = {
            'authlib': '1.3.0',
            'requests': None,
            'flask_appbuilder': None,
        }
        
        for package, min_version in required_packages.items():
            try:
                import importlib
                mod = importlib.import_module(package)
                version = getattr(mod, '__version__', 'unknown')
                log.info(f"  ✓ {package}: {version}")
                
                if min_version and version != 'unknown':
                    # Simple version comparison
                    if version < min_version:
                        warning = f"{package} version {version} is older than recommended {min_version}"
                        self.warnings.append(warning)
                        log.warning(f"  ⚠ {warning}")
            except ImportError:
                issue = f"Required package not installed: {package}"
                self.issues_found.append(issue)
                log.error(f"  ✗ {issue}")
    
    def check_airflow_config(self):
        """Check Airflow configuration file"""
        log.info("Checking airflow.cfg...")
        
        try:
            from airflow.configuration import conf
            
            # Check auth_manager
            auth_manager = conf.get('core', 'auth_manager', fallback=None)
            if auth_manager:
                log.info(f"  ✓ auth_manager: {auth_manager}")
                if 'fab_auth_manager' not in auth_manager:
                    warning = "auth_manager is not set to FabAuthManager"
                    self.warnings.append(warning)
                    log.warning(f"  ⚠ {warning}")
            else:
                issue = "auth_manager not configured in [core] section"
                self.issues_found.append(issue)
                log.error(f"  ✗ {issue}")
            
            # Check auth_backends
            auth_backends = conf.get('fab', 'auth_backends', fallback=None)
            if auth_backends:
                log.info(f"  ✓ auth_backends: {auth_backends}")
            else:
                warning = "auth_backends not configured in [fab] section"
                self.warnings.append(warning)
                log.warning(f"  ⚠ {warning}")
            
        except Exception as e:
            issue = f"Cannot read airflow.cfg: {e}"
            self.issues_found.append(issue)
            log.error(f"  ✗ {issue}")
    
    def check_database_connection(self):
        """Check if database is accessible"""
        log.info("Checking database connection...")
        
        try:
            from airflow.configuration import conf
            conn_string = conf.get('database', 'sql_alchemy_conn')
            
            engine = create_engine(conn_string)
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            
            log.info(f"  ✓ Database connection successful")
            
        except Exception as e:
            issue = f"Database connection failed: {e}"
            self.issues_found.append(issue)
            log.error(f"  ✗ {issue}")
    
    def test_oidc_endpoint(self, provider='keycloak'):
        """Test OIDC provider endpoint connectivity"""
        log.info(f"Testing {provider} OIDC endpoint...")
        
        import requests
        
        endpoints = {
            'keycloak': f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/.well-known/openid-configuration",
            'okta': f"https://{os.getenv('OKTA_DOMAIN')}/oauth2/{os.getenv('OKTA_AUTH_SERVER', 'default')}/.well-known/openid-configuration",
            'azure': f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}/v2.0/.well-known/openid-configuration",
        }
        
        endpoint = endpoints.get(provider)
        
        if not endpoint or 'None' in endpoint:
            issue = f"Cannot construct {provider} endpoint - missing environment variables"
            self.issues_found.append(issue)
            log.error(f"  ✗ {issue}")
            return
        
        try:
            response = requests.get(endpoint, timeout=10)
            response.raise_for_status()
            config = response.json()
            
            log.info(f"  ✓ Successfully connected to {provider} OIDC endpoint")
            log.info(f"  - Issuer: {config.get('issuer')}")
            log.info(f"  - Authorization endpoint: {config.get('authorization_endpoint')}")
            log.info(f"  - Token endpoint: {config.get('token_endpoint')}")
            
        except requests.exceptions.RequestException as e:
            issue = f"Cannot connect to {provider} OIDC endpoint: {e}"
            self.issues_found.append(issue)
            log.error(f"  ✗ {issue}")
    
    def run_diagnostics(self, provider='keycloak'):
        """Run all diagnostic checks"""
        log.info("="*60)
        log.info("Airflow OIDC Authentication Diagnostics")
        log.info("="*60)
        log.info("")
        
        self.check_environment_variables(provider)
        log.info("")
        
        self.check_airflow_config()
        log.info("")
        
        self.check_webserver_config()
        log.info("")
        
        self.check_packages()
        log.info("")
        
        self.check_database_connection()
        log.info("")
        
        self.test_oidc_endpoint(provider)
        log.info("")
        
        # Summary
        log.info("="*60)
        log.info("Diagnostic Summary")
        log.info("="*60)
        
        if not self.issues_found and not self.warnings:
            log.info("✓ All checks passed! Your OIDC configuration looks good.")
        else:
            if self.issues_found:
                log.error(f"\n✗ Found {len(self.issues_found)} critical issues:")
                for i, issue in enumerate(self.issues_found, 1):
                    log.error(f"  {i}. {issue}")
            
            if self.warnings:
                log.warning(f"\n⚠ Found {len(self.warnings)} warnings:")
                for i, warning in enumerate(self.warnings, 1):
                    log.warning(f"  {i}. {warning}")
        
        log.info("="*60)
        
        return len(self.issues_found) == 0


# =============================================================================
# COMMON ISSUES AND SOLUTIONS
# =============================================================================

COMMON_ISSUES = """
# =============================================================================
# COMMON OIDC AUTHENTICATION ISSUES AND SOLUTIONS
# =============================================================================

## Issue 1: "Auth manager not configured"
**Error**: KeyError: 'auth_manager' or auth manager not found

**Solution**:
Add to airflow.cfg:
```ini
[core]
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
```

## Issue 2: "webserver_config.py not loaded"
**Error**: OAuth provider not found, or AUTH_TYPE not set

**Solution**:
1. Ensure webserver_config.py is in $AIRFLOW_HOME directory
2. Check file permissions: chmod 644 webserver_config.py
3. Verify AIRFLOW_HOME environment variable is set
4. Restart Airflow webserver

## Issue 3: "OAuth redirect URI mismatch"
**Error**: redirect_uri_mismatch or invalid redirect

**Solution**:
1. For Airflow 2.x: Use /oauth-authorized/{provider}
2. For Airflow 3.x: Use /auth/oauth-authorized/{provider}
3. Update redirect URI in OIDC provider configuration
4. Ensure base_url in airflow.cfg matches your deployment URL

## Issue 4: "No access token in response"
**Error**: OAuth flow completes but user not authenticated

**Solution**:
1. Check OIDC client configuration in provider
2. Ensure client type is "confidential" (not public)
3. Verify client secret is correct
4. Check that required scopes are granted (openid, email, profile)

## Issue 5: "User not automatically registered"
**Error**: User successfully authenticates but cannot access Airflow

**Solution**:
Add to webserver_config.py:
```python
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Viewer"
```

## Issue 6: "Groups/roles not syncing"
**Error**: User logs in but has no permissions

**Solution**:
1. Enable role sync:
   ```python
   AUTH_ROLES_SYNC_AT_LOGIN = True
   ```
2. Verify AUTH_ROLES_MAPPING in webserver_config.py
3. Check that OIDC provider returns groups in userinfo
4. For Azure AD: Ensure "groups" claim is included in token configuration
5. For Okta: Add "groups" scope and ensure groups are included in claims

## Issue 7: "ImportError: No module named 'authlib'"
**Error**: Cannot import required modules

**Solution**:
```bash
pip install authlib==1.3.0 requests
```

## Issue 8: "CSRF token missing"
**Error**: CSRF validation failed

**Solution**:
Add to webserver_config.py:
```python
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None  # or set a reasonable limit
```

## Issue 9: "SSL certificate verification failed"
**Error**: SSLError when connecting to OIDC provider

**Solution**:
For development only (NOT for production):
```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

For production: Fix SSL certificate issues on OIDC provider

## Issue 10: "Token expired" or "Session expired"
**Error**: Users logged out frequently

**Solution**:
Adjust session lifetime in webserver_config.py:
```python
PERMANENT_SESSION_LIFETIME = 43200  # 12 hours in seconds
```

## Issue 11: "Database connection failed"
**Error**: Cannot connect to Airflow metadata database

**Solution**:
1. Verify SQL_ALCHEMY_CONN in airflow.cfg
2. Run database migrations: airflow db migrate
3. Check database credentials and network connectivity

## Issue 12: "Provider metadata not found"
**Error**: Cannot fetch .well-known/openid-configuration

**Solution**:
1. Verify OIDC issuer URL is correct
2. Check network connectivity to OIDC provider
3. Ensure OIDC provider is properly configured
4. Test manually: curl https://your-provider/.well-known/openid-configuration

## Issue 13: "Multiple auth managers configured"
**Error**: Conflicting authentication configurations

**Solution**:
Remove old auth_backend from [api] section in airflow.cfg
Only use [core] auth_manager and [fab] auth_backends

## Issue 14: "Callback URL not whitelisted"
**Error**: OIDC provider rejects callback

**Solution**:
In OIDC provider configuration, add to allowed redirect URIs:
- http://your-domain:8080/oauth-authorized/{provider}
- https://your-domain/oauth-authorized/{provider}

## Issue 15: "Groups not visible in Azure AD token"
**Error**: AUTH_ROLES_MAPPING not working with Azure AD

**Solution**:
1. In Azure AD app registration > Token configuration
2. Add optional claim "groups"
3. Or use Microsoft Graph API to fetch groups (already in example code)
4. Ensure API permissions include GroupMember.Read.All

# =============================================================================
# DEBUGGING TIPS
# =============================================================================

## Enable Debug Logging
Add to webserver_config.py:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
```

## Check Airflow Logs
```bash
# Webserver logs
tail -f $AIRFLOW_HOME/logs/scheduler/latest/*.log

# Or if using systemd
journalctl -u airflow-webserver -f
```

## Test OIDC Configuration
```bash
# Run the troubleshooting script
python test_oidc_auth.py

# Or use the OIDCTroubleshooter class
python -c "from troubleshoot import OIDCTroubleshooter; OIDCTroubleshooter().run_diagnostics('keycloak')"
```

## Verify Database State
```python
from airflow.configuration import conf
from sqlalchemy import create_engine, text

engine = create_engine(conf.get('database', 'sql_alchemy_conn'))
with engine.connect() as conn:
    # Check users
    result = conn.execute(text("SELECT username, email FROM ab_user"))
    print("Users:", result.fetchall())
    
    # Check roles
    result = conn.execute(text("SELECT name FROM ab_role"))
    print("Roles:", result.fetchall())
```

## Test OAuth Flow Manually
```bash
# Get authorization URL
curl "https://your-oidc-provider/.well-known/openid-configuration"

# Test with browser - navigate to authorization URL
# Should redirect back to Airflow with code parameter
```
"""


# =============================================================================
# CLI TOOLS
# =============================================================================

def main():
    """Main CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Airflow OIDC Authentication Tools'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Migrate command
    migrate_parser = subparsers.add_parser(
        'migrate',
        help='Run database migration for OIDC authentication'
    )
    migrate_parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip user backup'
    )
    migrate_parser.add_argument(
        '--connection',
        help='Database connection string (optional)'
    )
    
    # Diagnose command
    diagnose_parser = subparsers.add_parser(
        'diagnose',
        help='Run diagnostic checks'
    )
    diagnose_parser.add_argument(
        '--provider',
        choices=['keycloak', 'okta', 'azure'],
        default='keycloak',
        help='OIDC provider to test'
    )
    
    # Show issues command
    issues_parser = subparsers.add_parser(
        'issues',
        help='Show common issues and solutions'
    )
    
    args = parser.parse_args()
    
    if args.command == 'migrate':
        migrator = AirflowAuthMigration(args.connection)
        migrator.migrate(create_backup=not args.no_backup)
    
    elif args.command == 'diagnose':
        troubleshooter = OIDCTroubleshooter()
        success = troubleshooter.run_diagnostics(args.provider)
        sys.exit(0 if success else 1)
    
    elif args.command == 'issues':
        print(COMMON_ISSUES)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
# Run database migration
python airflow_oidc_tools.py migrate

# Run diagnostics for Keycloak
python airflow_oidc_tools.py diagnose --provider keycloak

# Run diagnostics for Okta
python airflow_oidc_tools.py diagnose --provider okta

# Run diagnostics for Azure AD
python airflow_oidc_tools.py diagnose --provider azure

# Show common issues
python airflow_oidc_tools.py issues

# Run migration without backup
python airflow_oidc_tools.py migrate --no-backup

# Run migration with custom connection string
python airflow_oidc_tools.py migrate --connection "postgresql://user:pass@host/db"
"""


# =============================================================================
# PRODUCTION CHECKLIST
# =============================================================================

PRODUCTION_CHECKLIST = """
# =============================================================================
# AIRFLOW OIDC PRODUCTION DEPLOYMENT CHECKLIST
# =============================================================================

## Pre-Deployment

- [ ] OIDC provider is configured and tested
- [ ] Client ID and Client Secret are securely stored
- [ ] Redirect URIs are whitelisted in OIDC provider
- [ ] Required groups/roles are created in OIDC provider
- [ ] Users are assigned to appropriate groups
- [ ] Database backup is created
- [ ] All configuration files are version controlled
- [ ] Environment variables are set via secrets management (not hardcoded)

## Configuration

- [ ] airflow.cfg has auth_manager set to FabAuthManager
- [ ] webserver_config.py is present and configured
- [ ] AUTH_ROLES_MAPPING matches your organization's groups
- [ ] OIDC_COOKIE_SECURE is set to True (for HTTPS)
- [ ] Session timeout is appropriate for your security policy
- [ ] CSRF protection is enabled
- [ ] Debug logging is disabled in production

## Security

- [ ] HTTPS is enabled (required for OIDC)
- [ ] Client secret is stored in secrets manager (not in files)
- [ ] Database credentials are secured
- [ ] Fernet key is properly configured and secured
- [ ] Network security groups/firewall rules are configured
- [ ] OIDC provider allows connections only from Airflow servers
- [ ] Least privilege principle applied to service accounts

## Testing

- [ ] Admin users can log in via OIDC
- [ ] Regular users can log in via OIDC
- [ ] Role mapping works correctly
- [ ] Users see only permitted DAGs/resources
- [ ] Session expiration works as expected
- [ ] Logout redirects correctly
- [ ] API authentication works (if needed)
- [ ] Load testing completed

## Monitoring

- [ ] Authentication failures are logged
- [ ] Failed login attempts are monitored
- [ ] Session metrics are collected
- [ ] OIDC provider health is monitored
- [ ] Alerts configured for authentication issues
- [ ] Database connection pool is monitored

## Documentation

- [ ] Architecture diagram created
- [ ] OIDC configuration documented
- [ ] Troubleshooting guide prepared
- [ ] User onboarding guide created
- [ ] Disaster recovery plan documented
- [ ] Runbook for common issues prepared

## Rollback Plan

- [ ] Database backup verified and restorable
- [ ] Previous authentication method can be re-enabled
- [ ] Rollback procedure documented and tested
- [ ] Communication plan for users in case of issues

## Post-Deployment

- [ ] Monitor logs for first 24-48 hours
- [ ] Verify all users can authenticate
- [ ] Check for any authorization issues
- [ ] Confirm no performance degradation
- [ ] Update documentation with any lessons learned
- [ ] Schedule post-mortem if issues occurred

## Maintenance

- [ ] Schedule regular review of user access
- [ ] Plan for certificate renewals
- [ ] Keep authlib and dependencies updated
- [ ] Review and update role mappings periodically
- [ ] Monitor OIDC provider for updates/changes
"""

print(PRODUCTION_CHECKLIST)