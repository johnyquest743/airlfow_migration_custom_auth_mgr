#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
Airflow 2.10 OIDC Setup Script
Python 3.12 Compatible
===============================================================================

This script sets up Airflow 2.10 with OIDC authentication by:
1. Creating necessary directory structure
2. Generating sample configuration files
3. Installing required dependencies
4. Validating configuration

Usage:
    python setup_airflow_oidc.py --provider keycloak
    python setup_airflow_oidc.py --provider okta
    python setup_airflow_oidc.py --provider azure

===============================================================================
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# ============================================================================
# CONFIGURATION TEMPLATES
# ============================================================================

def get_keycloak_template() -> Dict[str, Any]:
    """Get Keycloak configuration template"""
    return {
        "name": "keycloak",
        "enabled": True,
        "type": "keycloak",
        "client_id": "airflow",
        "client_secret": "REPLACE_WITH_YOUR_CLIENT_SECRET",
        "issuer": "https://keycloak.example.com/realms/airflow",
        "server_metadata_url": "https://keycloak.example.com/realms/airflow/.well-known/openid-configuration",
        "authorize_url": "https://keycloak.example.com/realms/airflow/protocol/openid-connect/auth",
        "access_token_url": "https://keycloak.example.com/realms/airflow/protocol/openid-connect/token",
        "userinfo_url": "https://keycloak.example.com/realms/airflow/protocol/openid-connect/userinfo",
        "logout_url": "https://keycloak.example.com/realms/airflow/protocol/openid-connect/logout",
        "api_base_url": "https://keycloak.example.com/realms/airflow",
        "scope": "openid email profile groups",
        "icon": "fa-key",
        "token_key": "access_token",
        "group_claim": "groups",
        "username_claim": "preferred_username"
    }

def get_okta_template() -> Dict[str, Any]:
    """Get Okta configuration template"""
    return {
        "name": "okta",
        "enabled": True,
        "type": "okta",
        "client_id": "REPLACE_WITH_YOUR_CLIENT_ID",
        "client_secret": "REPLACE_WITH_YOUR_CLIENT_SECRET",
        "issuer": "https://your-domain.okta.com/oauth2/default",
        "server_metadata_url": "https://your-domain.okta.com/oauth2/default/.well-known/openid-configuration",
        "authorize_url": "https://your-domain.okta.com/oauth2/default/v1/authorize",
        "access_token_url": "https://your-domain.okta.com/oauth2/default/v1/token",
        "userinfo_url": "https://your-domain.okta.com/oauth2/default/v1/userinfo",
        "logout_url": "https://your-domain.okta.com/oauth2/default/v1/logout",
        "api_base_url": "https://your-domain.okta.com",
        "scope": "openid email profile groups",
        "icon": "fa-okta",
        "token_key": "access_token",
        "group_claim": "groups",
        "username_claim": "preferred_username"
    }

def get_azure_template() -> Dict[str, Any]:
    """Get Azure AD configuration template"""
    return {
        "name": "azure",
        "enabled": True,
        "type": "azure_ad",
        "client_id": "REPLACE_WITH_YOUR_CLIENT_ID",
        "client_secret": "REPLACE_WITH_YOUR_CLIENT_SECRET",
        "issuer": "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
        "server_metadata_url": "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration",
        "authorize_url": "https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/authorize",
        "access_token_url": "https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "groups_url": "https://graph.microsoft.com/v1.0/me/memberOf",
        "logout_url": "https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/logout",
        "api_base_url": "https://graph.microsoft.com/v1.0/",
        "scope": "openid email profile User.Read GroupMember.Read.All",
        "icon": "fa-windows",
        "token_key": "access_token",
        "group_claim": "groups",
        "username_claim": "userPrincipalName"
    }

# ============================================================================
# SETUP CLASS
# ============================================================================

class AirflowOIDCSetup:
    """Setup Airflow with OIDC authentication"""
    
    def __init__(self, airflow_home: str = None, provider: str = 'keycloak'):
        self.airflow_home = Path(airflow_home or os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow')))
        self.config_dir = self.airflow_home / 'config'
        self.provider = provider
        
        print(f"Airflow Home: {self.airflow_home}")
        print(f"Config Directory: {self.config_dir}")
    
    def create_directories(self):
        """Create necessary directory structure"""
        print("\n" + "="*70)
        print("Creating Directory Structure")
        print("="*70)
        
        directories = [
            self.airflow_home,
            self.config_dir,
            self.airflow_home / 'dags',
            self.airflow_home / 'logs',
            self.airflow_home / 'plugins',
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created: {directory}")
    
    def create_client_config(self):
        """Create oidc_client.json"""
        print("\n" + "="*70)
        print("Creating Client Configuration")
        print("="*70)
        
        provider_templates = {
            'keycloak': get_keycloak_template(),
            'okta': get_okta_template(),
            'azure': get_azure_template(),
        }
        
        provider_config = provider_templates.get(self.provider)
        if not provider_config:
            print(f"✗ Unknown provider: {self.provider}")
            return False
        
        # Create oidc_client.json
        client_config = {
            "providers": [provider_config],
            "redirect_uris": [
                f"http://localhost:8080/oauth-authorized/{self.provider}",
                f"https://your-domain.com/oauth-authorized/{self.provider}"
            ],
            "metadata": {
                "version": "1.0",
                "created": "2025-01-01",
                "description": f"OIDC client configuration for {self.provider}"
            }
        }
        
        file_path = self.config_dir / 'oidc_client.json'
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(client_config, f, indent=2)
        
        print(f"✓ Created: {file_path}")
        print(f"  Provider: {self.provider}")
        print(f"  ⚠️  Remember to update client_id and client_secret!")
        return True
    
    def create_roles_config(self):
        """Create oidc_roles.json"""
        print("\n" + "="*70)
        print("Creating Roles Configuration")
        print("="*70)
        
        roles_config = {
            "role_mapping": {
                f"{self.provider}_admin": ["Admin"],
                f"{self.provider}_op": ["Op"],
                f"{self.provider}_user": ["User"],
                f"{self.provider}_viewer": ["Viewer"],
            },
            "airflow_roles": {
                "Admin": {
                    "description": "Full administrative access",
                    "permissions": ["all"]
                },
                "Op": {
                    "description": "Operational access",
                    "permissions": ["can_edit", "can_create", "can_delete", "can_read"]
                },
                "User": {
                    "description": "Standard user access",
                    "permissions": ["can_read", "can_edit"]
                },
                "Viewer": {
                    "description": "Read-only access",
                    "permissions": ["can_read"]
                }
            },
            "metadata": {
                "version": "1.0",
                "created": "2025-01-01"
            }
        }
        
        file_path = self.config_dir / 'oidc_roles.json'
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(roles_config, f, indent=2)
        
        print(f"✓ Created: {file_path}")
        print(f"  Default role mapping configured for {self.provider}")
        return True
    
    def create_settings_config(self):
        """Create oidc_settings.json"""
        print("\n" + "="*70)
        print("Creating Settings Configuration")
        print("="*70)
        
        settings_config = {
            "authentication": {
                "auth_user_registration": True,
                "auth_user_registration_role": "Viewer",
                "auth_roles_sync_at_login": True
            },
            "session": {
                "session_lifetime_hours": 12,
                "session_cookie_secure": False,
                "session_cookie_httponly": True,
                "session_cookie_samesite": "Lax"
            },
            "application": {
                "app_name": "Airflow",
                "app_theme": "",
                "app_icon": "/static/pin_100.png"
            },
            "rate_limiting": {
                "ratelimit_enabled": True,
                "ratelimit_storage_uri": "memory://",
                "ratelimit_strategy": "moving-window",
                "ratelimit_default": "200 per day, 50 per hour"
            },
            "security": {
                "csrf_enabled": True,
                "csrf_time_limit": None
            },
            "logging": {
                "fab_logging_level": "INFO",
                "log_userinfo_requests": True
            },
            "network": {
                "request_timeout": 30,
                "verify_ssl": True
            },
            "metadata": {
                "version": "1.0",
                "created": "2025-01-01"
            }
        }
        
        file_path = self.config_dir / 'oidc_settings.json'
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(settings_config, f, indent=2)
        
        print(f"✓ Created: {file_path}")
        return True
    
    def install_dependencies(self):
        """Install required Python packages"""
        print("\n" + "="*70)
        print("Installing Dependencies")
        print("="*70)
        
        packages = [
            'apache-airflow==2.10.5',
            'apache-airflow-providers-fab==1.2.0',
            'authlib==1.3.0',
            'requests==2.31.0',
            'cryptography',
        ]
        
        print("Required packages:")
        for package in packages:
            print(f"  - {package}")
        
        response = input("\nInstall these packages? (y/n): ")
        if response.lower() == 'y':
            try:
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', '--upgrade'
                ] + packages)
                print("✓ Dependencies installed successfully")
                return True
            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to install dependencies: {e}")
                return False
        else:
            print("⚠️  Skipped dependency installation")
            return False
    
    def generate_secrets(self):
        """Generate Fernet key and secret key"""
        print("\n" + "="*70)
        print("Generating Secrets")
        print("="*70)
        
        try:
            from cryptography.fernet import Fernet
            import secrets
            
            fernet_key = Fernet.generate_key().decode()
            secret_key = secrets.token_hex(32)
            
            print(f"\nFernet Key (for airflow.cfg):")
            print(f"  {fernet_key}")
            print(f"\nSecret Key (for airflow.cfg):")
            print(f"  {secret_key}")
            
            env_file = self.airflow_home / '.env'
            with open(env_file, 'w') as f:
                f.write(f"# Airflow Secrets\n")
                f.write(f"AIRFLOW__CORE__FERNET_KEY={fernet_key}\n")
                f.write(f"AIRFLOW__WEBSERVER__SECRET_KEY={secret_key}\n")
            
            print(f"\n✓ Secrets saved to: {env_file}")
            print("  ⚠️  Keep this file secure!")
            return True
            
        except ImportError:
            print("✗ cryptography package not installed")
            return False
    
    def create_env_template(self):
        """Create environment variables template"""
        print("\n" + "="*70)
        print("Creating Environment Template")
        print("="*70)
        
        env_template = f"""# Airflow Environment Variables
# Generated for {self.provider} OIDC authentication

# Airflow Configuration
export AIRFLOW_HOME={self.airflow_home}
export AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
export AIRFLOW__FAB__AUTH_BACKENDS=airflow.providers.fab.auth_manager.api.auth.backend.basic_auth

# Database (Update with your actual credentials)
export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://airflow:airflow@localhost:5432/airflow

# OIDC Provider
export OIDC_PROVIDER={self.provider}

# Security (Use the values from .env file)
# export AIRFLOW__CORE__FERNET_KEY=your-fernet-key
# export AIRFLOW__WEBSERVER__SECRET_KEY=your-secret-key

# {self.provider.upper()} Configuration
"""
        
        if self.provider == 'keycloak':
            env_template += """export KEYCLOAK_BASE_URL=https://keycloak.example.com
export KEYCLOAK_REALM=airflow
export KEYCLOAK_CLIENT_ID=airflow
export KEYCLOAK_CLIENT_SECRET=your-client-secret
"""
        elif self.provider == 'okta':
            env_template += """export OKTA_DOMAIN=your-domain.okta.com
export OKTA_AUTH_SERVER=default
export OKTA_CLIENT_ID=your-client-id
export OKTA_CLIENT_SECRET=your-client-secret
"""
        elif self.provider == 'azure':
            env_template += """export AZURE_TENANT_ID=your-tenant-id
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
"""
        
        env_file = self.airflow_home / 'env_template.sh'
        with open(env_file, 'w') as f:
            f.write(env_template)
        
        os.chmod(env_file, 0o644)
        print(f"✓ Created: {env_file}")
        print(f"  Run: source {env_file}")
        return True
    
    def print_next_steps(self):
        """Print next steps"""
        print("\n" + "="*70)
        print("Setup Complete! Next Steps")
        print("="*70)
        
        steps = [
            f"1. Update OIDC credentials in: {self.config_dir}/oidc_client.json",
            f"2. Configure role mapping in: {self.config_dir}/oidc_roles.json",
            f"3. Review settings in: {self.config_dir}/oidc_settings.json",
            f"4. Source environment variables: source {self.airflow_home}/env_template.sh",
            "5. Initialize Airflow database: airflow db migrate",
            "6. Create admin user: airflow users create --role Admin --username admin --email admin@example.com --firstname Admin --lastname User --password admin",
            "7. Start Airflow webserver: airflow webserver",
            "8. Start Airflow scheduler: airflow scheduler",
            f"9. Access Airflow UI: http://localhost:8080",
            f"10. Login with {self.provider.upper()} OIDC"
        ]
        
        for step in steps:
            print(f"  {step}")
        
        print("\n" + "="*70)
        print("Important Files:")
        print("="*70)
        print(f"  Config Dir: {self.config_dir}")
        print(f"  - oidc_client.json: Client credentials")
        print(f"  - oidc_roles.json: Role mapping")
        print(f"  - oidc_settings.json: Additional settings")
        print(f"  - webserver_config.py: Flask-AppBuilder config (separate file)")
        print(f"  - custom_oidc_auth.py: Authentication module (separate file)")
        print("="*70)
    
    def run(self):
        """Run complete setup"""
        print("="*70)
        print(f"Airflow 2.10 OIDC Setup - {self.provider.upper()}")
        print("="*70)
        
        self.create_directories()
        self.create_client_config()
        self.create_roles_config()
        self.create_settings_config()
        self.generate_secrets()
        self.create_env_template()
        self.install_dependencies()
        self.print_next_steps()

# ============================================================================
# VALIDATION SCRIPT
# ============================================================================

def validate_setup(airflow_home: str = None):
    """Validate OIDC setup"""
    airflow_home = Path(airflow_home or os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow')))
    config_dir = airflow_home / 'config'
    
    print("="*70)
    print("Validating OIDC Setup")
    print("="*70)
    
    checks = []
    
    # Check directories
    checks.append(("Config directory exists", config_dir.exists()))
    
    # Check files
    required_files = [
        'oidc_client.json',
        'oidc_roles.json',
        'oidc_settings.json'
    ]
    
    for filename in required_files:
        file_path = config_dir / filename
        checks.append((f"{filename} exists", file_path.exists()))
        
        if file_path.exists():
            try:
                with open(file_path) as f:
                    json.load(f)
                checks.append((f"{filename} is valid JSON", True))
            except json.JSONDecodeError:
                checks.append((f"{filename} is valid JSON", False))
    
    # Print results
    print("\nValidation Results:")
    all_passed = True
    for check_name, passed in checks:
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {check_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*70)
    if all_passed:
        print("✓ All checks passed!")
    else:
        print("✗ Some checks failed. Please review the configuration.")
    print("="*70)
    
    return all_passed

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Setup Airflow 2.10 with OIDC authentication'
    )
    parser.add_argument(
        '--provider',
        choices=['keycloak', 'okta', 'azure'],
        default='keycloak',
        help='OIDC provider to configure'
    )
    parser.add_argument(
        '--airflow-home',
        help='Airflow home directory (default: $AIRFLOW_HOME or ~/airflow)'
    )
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Only validate existing configuration'
    )
    
    args = parser.parse_args()
    
    if args.validate_only:
        validate_setup(args.airflow_home)
    else:
        setup = AirflowOIDCSetup(args.airflow_home, args.provider)
        setup.run()

if __name__ == '__main__':
    main()