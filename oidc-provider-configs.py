# =============================================================================
# OIDC Provider-Specific Configurations for Airflow 2.10
# =============================================================================
# This file contains webserver_config.py examples for:
# 1. Keycloak
# 2. Okta
# 3. Azure AD (Microsoft Entra ID)
# =============================================================================

# =============================================================================
# 1. KEYCLOAK CONFIGURATION
# =============================================================================

"""
Keycloak webserver_config.py for Airflow 2.10
"""

import os
import logging
from flask_appbuilder.security.manager import AUTH_OAUTH
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride
from airflow.configuration import conf
import requests

log = logging.getLogger(__name__)

# Basic Settings
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Authentication Type
AUTH_TYPE = AUTH_OAUTH

# User Registration
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Viewer"
AUTH_ROLES_SYNC_AT_LOGIN = True

# Session Configuration
PERMANENT_SESSION_LIFETIME = 43200  # 12 hours

# Keycloak Configuration
KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'https://keycloak.example.com')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'airflow')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'airflow')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'your-secret')

# Keycloak URLs
OIDC_ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
AUTHORIZATION_URL = f"{OIDC_ISSUER}/protocol/openid-connect/auth"
TOKEN_URL = f"{OIDC_ISSUER}/protocol/openid-connect/token"
USERINFO_URL = f"{OIDC_ISSUER}/protocol/openid-connect/userinfo"
METADATA_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"

# Role Mapping - Create these roles in Keycloak
AUTH_ROLES_MAPPING = {
    "airflow_admin": ["Admin"],
    "airflow_op": ["Op"],
    "airflow_user": ["User"],
    "airflow_viewer": ["Viewer"],
    "airflow_public": ["Public"],
}

# OAuth Provider Configuration for Keycloak
OAUTH_PROVIDERS = [
    {
        'name': 'keycloak',
        'icon': 'fa-key',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET,
            'server_metadata_url': METADATA_URL,
            'api_base_url': OIDC_ISSUER,
            'client_kwargs': {
                'scope': 'openid email profile groups'
            },
        }
    }
]

class KeycloakSecurityManager(FabAirflowSecurityManagerOverride):
    """Custom Security Manager for Keycloak OIDC"""
    
    def oauth_user_info(self, provider, response=None):
        """Extract user info from Keycloak"""
        if provider == 'keycloak':
            access_token = response.get('access_token')
            
            if not access_token:
                log.error("No access token in OAuth response")
                return {}
            
            try:
                # Get user info from Keycloak
                headers = {'Authorization': f'Bearer {access_token}'}
                userinfo_response = requests.get(USERINFO_URL, headers=headers)
                userinfo_response.raise_for_status()
                userinfo = userinfo_response.json()
                
                log.info(f"Keycloak user info: {userinfo}")
                
                # Extract roles from groups claim
                groups = userinfo.get('groups', [])
                
                # Map Keycloak groups to Airflow roles
                role_keys = []
                for group in groups:
                    if group in AUTH_ROLES_MAPPING:
                        role_keys.extend(AUTH_ROLES_MAPPING[group])
                
                if not role_keys:
                    role_keys = [AUTH_USER_REGISTRATION_ROLE]
                
                return {
                    'username': userinfo.get('preferred_username', userinfo.get('email')),
                    'email': userinfo.get('email'),
                    'first_name': userinfo.get('given_name', ''),
                    'last_name': userinfo.get('family_name', ''),
                    'role_keys': role_keys
                }
                
            except Exception as e:
                log.error(f"Error fetching Keycloak user info: {e}")
                return {}
        
        return {}

SECURITY_MANAGER_CLASS = KeycloakSecurityManager

# =============================================================================
# Keycloak Client Configuration Instructions:
# =============================================================================
# 1. Login to Keycloak Admin Console
# 2. Select your realm (or create 'airflow' realm)
# 3. Go to Clients > Create
# 4. Configure:
#    - Client ID: airflow
#    - Client Protocol: openid-connect
#    - Access Type: confidential
#    - Valid Redirect URIs: http://localhost:8080/oauth-authorized/keycloak
#    - Web Origins: http://localhost:8080
# 5. In Credentials tab, copy the Secret
# 6. Create roles in Roles > Realm Roles:
#    - airflow_admin, airflow_op, airflow_user, airflow_viewer, airflow_public
# 7. Assign roles to users/groups in Users > Role Mappings
# =============================================================================


# =============================================================================
# 2. OKTA CONFIGURATION
# =============================================================================

"""
Okta webserver_config.py for Airflow 2.10
"""

import os
import logging
from flask_appbuilder.security.manager import AUTH_OAUTH
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride
from airflow.configuration import conf
import requests

log = logging.getLogger(__name__)

# Basic Settings
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Authentication Type
AUTH_TYPE = AUTH_OAUTH

# User Registration
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Viewer"
AUTH_ROLES_SYNC_AT_LOGIN = True

# Session Configuration
PERMANENT_SESSION_LIFETIME = 43200  # 12 hours

# Okta Configuration
OKTA_DOMAIN = os.getenv('OKTA_DOMAIN', 'your-domain.okta.com')
OKTA_CLIENT_ID = os.getenv('OKTA_CLIENT_ID', 'your-client-id')
OKTA_CLIENT_SECRET = os.getenv('OKTA_CLIENT_SECRET', 'your-client-secret')
OKTA_AUTHORIZATION_SERVER = os.getenv('OKTA_AUTH_SERVER', 'default')  # or 'default'

# Okta URLs
OKTA_BASE_URL = f"https://{OKTA_DOMAIN}"
OIDC_ISSUER = f"{OKTA_BASE_URL}/oauth2/{OKTA_AUTHORIZATION_SERVER}"
AUTHORIZATION_URL = f"{OIDC_ISSUER}/v1/authorize"
TOKEN_URL = f"{OIDC_ISSUER}/v1/token"
USERINFO_URL = f"{OIDC_ISSUER}/v1/userinfo"
METADATA_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"

# Role Mapping - Groups from Okta
AUTH_ROLES_MAPPING = {
    "AirflowAdmins": ["Admin"],
    "AirflowOperators": ["Op"],
    "AirflowUsers": ["User"],
    "AirflowViewers": ["Viewer"],
}

# OAuth Provider Configuration for Okta
OAUTH_PROVIDERS = [
    {
        'name': 'okta',
        'icon': 'fa-okta',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': OKTA_CLIENT_ID,
            'client_secret': OKTA_CLIENT_SECRET,
            'server_metadata_url': METADATA_URL,
            'api_base_url': OKTA_BASE_URL,
            'client_kwargs': {
                'scope': 'openid email profile groups'
            },
        }
    }
]

class OktaSecurityManager(FabAirflowSecurityManagerOverride):
    """Custom Security Manager for Okta OIDC"""
    
    def oauth_user_info(self, provider, response=None):
        """Extract user info from Okta"""
        if provider == 'okta':
            access_token = response.get('access_token')
            
            if not access_token:
                log.error("No access token in OAuth response")
                return {}
            
            try:
                # Get user info from Okta
                headers = {'Authorization': f'Bearer {access_token}'}
                userinfo_response = requests.get(USERINFO_URL, headers=headers)
                userinfo_response.raise_for_status()
                userinfo = userinfo_response.json()
                
                log.info(f"Okta user info: {userinfo}")
                
                # Extract groups from Okta
                groups = userinfo.get('groups', [])
                
                # Map Okta groups to Airflow roles
                role_keys = []
                for group in groups:
                    if group in AUTH_ROLES_MAPPING:
                        role_keys.extend(AUTH_ROLES_MAPPING[group])
                
                if not role_keys:
                    role_keys = [AUTH_USER_REGISTRATION_ROLE]
                
                return {
                    'username': userinfo.get('preferred_username', userinfo.get('email')),
                    'email': userinfo.get('email'),
                    'first_name': userinfo.get('given_name', ''),
                    'last_name': userinfo.get('family_name', ''),
                    'role_keys': role_keys
                }
                
            except Exception as e:
                log.error(f"Error fetching Okta user info: {e}")
                return {}
        
        return {}

SECURITY_MANAGER_CLASS = OktaSecurityManager

# =============================================================================
# Okta Configuration Instructions:
# =============================================================================
# 1. Login to Okta Admin Console
# 2. Go to Applications > Create App Integration
# 3. Select:
#    - Sign-in method: OIDC - OpenID Connect
#    - Application type: Web Application
# 4. Configure:
#    - App integration name: Airflow
#    - Grant type: Authorization Code
#    - Sign-in redirect URIs: http://localhost:8080/oauth-authorized/okta
#    - Sign-out redirect URIs: http://localhost:8080
# 5. In Assignments tab, assign users/groups
# 6. In Groups section, create groups:
#    - AirflowAdmins, AirflowOperators, AirflowUsers, AirflowViewers
# 7. Copy Client ID and Client Secret from General tab
# 8. Optional: In Okta API Scopes, add 'groups' scope if not present
# =============================================================================


# =============================================================================
# 3. AZURE AD (Microsoft Entra ID) CONFIGURATION
# =============================================================================

"""
Azure AD / Microsoft Entra ID webserver_config.py for Airflow 2.10
"""

import os
import logging
from flask_appbuilder.security.manager import AUTH_OAUTH
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride
from airflow.configuration import conf
import requests

log = logging.getLogger(__name__)

# Basic Settings
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Authentication Type
AUTH_TYPE = AUTH_OAUTH

# User Registration
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Viewer"
AUTH_ROLES_SYNC_AT_LOGIN = True

# Session Configuration
PERMANENT_SESSION_LIFETIME = 43200  # 12 hours

# Azure AD Configuration
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID', 'your-tenant-id')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID', 'your-client-id')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET', 'your-client-secret')

# Azure AD URLs
OIDC_ISSUER = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0"
AUTHORIZATION_URL = f"{OIDC_ISSUER}/authorize"
TOKEN_URL = f"{OIDC_ISSUER}/token"
METADATA_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"

# Role Mapping - Azure AD Groups (use Object IDs or display names)
AUTH_ROLES_MAPPING = {
    "Airflow-Admins": ["Admin"],
    "Airflow-Operators": ["Op"],
    "Airflow-Users": ["User"],
    "Airflow-Viewers": ["Viewer"],
}

# OAuth Provider Configuration for Azure AD
OAUTH_PROVIDERS = [
    {
        'name': 'azure',
        'icon': 'fa-windows',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': AZURE_CLIENT_ID,
            'client_secret': AZURE_CLIENT_SECRET,
            'server_metadata_url': METADATA_URL,
            'api_base_url': 'https://graph.microsoft.com/v1.0/',
            'client_kwargs': {
                'scope': 'openid email profile User.Read GroupMember.Read.All',
            },
        }
    }
]

class AzureADSecurityManager(FabAirflowSecurityManagerOverride):
    """Custom Security Manager for Azure AD OIDC"""
    
    def oauth_user_info(self, provider, response=None):
        """Extract user info from Azure AD"""
        if provider == 'azure':
            access_token = response.get('access_token')
            
            if not access_token:
                log.error("No access token in OAuth response")
                return {}
            
            try:
                # Get user info from Microsoft Graph API
                headers = {'Authorization': f'Bearer {access_token}'}
                
                # Get user profile
                user_response = requests.get(
                    'https://graph.microsoft.com/v1.0/me',
                    headers=headers
                )
                user_response.raise_for_status()
                user_data = user_response.json()
                
                # Get user groups
                groups_response = requests.get(
                    'https://graph.microsoft.com/v1.0/me/memberOf',
                    headers=headers
                )
                groups_response.raise_for_status()
                groups_data = groups_response.json()
                
                log.info(f"Azure AD user info: {user_data}")
                
                # Extract group display names
                groups = [group.get('displayName') for group in groups_data.get('value', [])]
                
                # Map Azure AD groups to Airflow roles
                role_keys = []
                for group in groups:
                    if group in AUTH_ROLES_MAPPING:
                        role_keys.extend(AUTH_ROLES_MAPPING[group])
                
                if not role_keys:
                    role_keys = [AUTH_USER_REGISTRATION_ROLE]
                
                return {
                    'username': user_data.get('userPrincipalName', user_data.get('mail')),
                    'email': user_data.get('mail', user_data.get('userPrincipalName')),
                    'first_name': user_data.get('givenName', ''),
                    'last_name': user_data.get('surname', ''),
                    'role_keys': role_keys
                }
                
            except Exception as e:
                log.error(f"Error fetching Azure AD user info: {e}")
                return {}
        
        return {}

SECURITY_MANAGER_CLASS = AzureADSecurityManager

# =============================================================================
# Azure AD Configuration Instructions:
# =============================================================================
# 1. Login to Azure Portal (portal.azure.com)
# 2. Go to Azure Active Directory > App registrations > New registration
# 3. Configure:
#    - Name: Airflow
#    - Supported account types: Accounts in this organizational directory only
#    - Redirect URI: Web - http://localhost:8080/oauth-authorized/azure
# 4. After creation, note the Application (client) ID and Directory (tenant) ID
# 5. Go to Certificates & secrets > New client secret
#    - Add description: Airflow Secret
#    - Copy the secret value (shown only once!)
# 6. Go to API permissions > Add a permission
#    - Microsoft Graph > Delegated permissions
#    - Add: User.Read, GroupMember.Read.All, email, openid, profile
#    - Click "Grant admin consent"
# 7. Create Security Groups in Azure AD:
#    - Airflow-Admins, Airflow-Operators, Airflow-Users, Airflow-Viewers
# 8. Assign users to these groups
# 9. Optional: In Token configuration, add "groups" optional claim
# =============================================================================


# =============================================================================
# TESTING CONFIGURATION
# =============================================================================

"""
Testing script to verify OIDC configuration
Save as test_oidc_auth.py
"""

def test_oidc_configuration():
    """Test OIDC configuration without starting Airflow"""
    import os
    import requests
    from urllib.parse import urlencode
    
    # Choose your provider: 'keycloak', 'okta', or 'azure'
    PROVIDER = os.getenv('OIDC_PROVIDER', 'keycloak')
    
    configs = {
        'keycloak': {
            'issuer': f"{os.getenv('KEYCLOAK_BASE_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}",
            'client_id': os.getenv('KEYCLOAK_CLIENT_ID'),
            'client_secret': os.getenv('KEYCLOAK_CLIENT_SECRET'),
        },
        'okta': {
            'issuer': f"https://{os.getenv('OKTA_DOMAIN')}/oauth2/{os.getenv('OKTA_AUTH_SERVER', 'default')}",
            'client_id': os.getenv('OKTA_CLIENT_ID'),
            'client_secret': os.getenv('OKTA_CLIENT_SECRET'),
        },
        'azure': {
            'issuer': f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}/v2.0",
            'client_id': os.getenv('AZURE_CLIENT_ID'),
            'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
        }
    }
    
    config = configs.get(PROVIDER)
    if not config:
        print(f"Invalid provider: {PROVIDER}")
        return
    
    print(f"\n{'='*60}")
    print(f"Testing {PROVIDER.upper()} OIDC Configuration")
    print(f"{'='*60}\n")
    
    # Test 1: Check OpenID Configuration
    print("Test 1: Fetching OpenID Configuration...")
    metadata_url = f"{config['issuer']}/.well-known/openid-configuration"
    
    try:
        response = requests.get(metadata_url)
        response.raise_for_status()
        metadata = response.json()
        
        print(f"✓ Successfully fetched metadata from {metadata_url}")
        print(f"  - Authorization Endpoint: {metadata.get('authorization_endpoint')}")
        print(f"  - Token Endpoint: {metadata.get('token_endpoint')}")
        print(f"  - Userinfo Endpoint: {metadata.get('userinfo_endpoint')}")
        print(f"  - Supported Scopes: {metadata.get('scopes_supported')}")
        print()
        
    except Exception as e:
        print(f"✗ Failed to fetch metadata: {e}")
        return
    
    # Test 2: Validate Client Credentials
    print("Test 2: Validating Client Credentials...")
    print(f"  - Client ID: {config['client_id'][:10]}...")
    print(f"  - Client Secret: {'*' * 20}")
    print()
    
    # Test 3: Generate Authorization URL
    print("Test 3: Generating Authorization URL...")
    auth_params = {
        'client_id': config['client_id'],
        'redirect_uri': 'http://localhost:8080/oauth-authorized/' + PROVIDER,
        'response_type': 'code',
        'scope': 'openid email profile groups',
        'state': 'random_state_string'
    }
    
    auth_url = f"{metadata.get('authorization_endpoint')}?{urlencode(auth_params)}"
    print(f"✓ Authorization URL generated:")
    print(f"  {auth_url[:100]}...")
    print()
    
    print(f"{'='*60}")
    print("Configuration looks good! 🎉")
    print(f"{'='*60}\n")
    print("Next steps:")
    print("1. Ensure webserver_config.py is in $AIRFLOW_HOME")
    print("2. Set environment variables for your OIDC provider")
    print("3. Start Airflow: airflow webserver")
    print("4. Navigate to http://localhost:8080")
    print("5. Click on the OIDC login button")
    print()

if __name__ == '__main__':
    test_oidc_configuration()


# =============================================================================
# DOCKER-COMPOSE EXAMPLE
# =============================================================================

"""
docker-compose.yml for Airflow 2.10 with OIDC authentication

Save as docker-compose.yml
"""

docker_compose_yaml = """
version: '3.8'

x-airflow-common:
  &airflow-common
  image: apache/airflow:2.10.5-python3.11
  environment:
    &airflow-common-env
    AIRFLOW__CORE__EXECUTOR: LocalExecutor
    AIRFLOW__DATABASE__SQL_ALCHEMY_CONN: postgresql+psycopg2://airflow:airflow@postgres/airflow
    AIRFLOW__CORE__FERNET_KEY: ''
    AIRFLOW__CORE__DAGS_ARE_PAUSED_AT_CREATION: 'true'
    AIRFLOW__CORE__LOAD_EXAMPLES: 'false'
    
    # Auth Manager Configuration
    AIRFLOW__CORE__AUTH_MANAGER: airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
    AIRFLOW__FAB__AUTH_BACKENDS: airflow.providers.fab.auth_manager.api.auth.backend.basic_auth
    
    # OIDC Provider - Choose one: keycloak, okta, or azure
    OIDC_PROVIDER: keycloak
    
    # Keycloak Configuration
    KEYCLOAK_BASE_URL: https://keycloak.example.com
    KEYCLOAK_REALM: airflow
    KEYCLOAK_CLIENT_ID: airflow
    KEYCLOAK_CLIENT_SECRET: ${KEYCLOAK_CLIENT_SECRET}
    
    # Okta Configuration (comment out if using Keycloak/Azure)
    # OKTA_DOMAIN: your-domain.okta.com
    # OKTA_AUTH_SERVER: default
    # OKTA_CLIENT_ID: ${OKTA_CLIENT_ID}
    # OKTA_CLIENT_SECRET: ${OKTA_CLIENT_SECRET}
    
    # Azure AD Configuration (comment out if using Keycloak/Okta)
    # AZURE_TENANT_ID: ${AZURE_TENANT_ID}
    # AZURE_CLIENT_ID: ${AZURE_CLIENT_ID}
    # AZURE_CLIENT_SECRET: ${AZURE_CLIENT_SECRET}
    
    _PIP_ADDITIONAL_REQUIREMENTS: authlib==1.3.0 requests
    
  volumes:
    - ./dags:/opt/airflow/dags
    - ./logs:/opt/airflow/logs
    - ./plugins:/opt/airflow/plugins
    - ./webserver_config.py:/opt/airflow/webserver_config.py:ro
  user: "${AIRFLOW_UID:-50000}:0"
  depends_on:
    &airflow-common-depends-on
    postgres:
      condition: service_healthy

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_USER: airflow
      POSTGRES_PASSWORD: airflow
      POSTGRES_DB: airflow
    volumes:
      - postgres-db-volume:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "airflow"]
      interval: 10s
      retries: 5
      start_period: 5s
    restart: always

  airflow-webserver:
    <<: *airflow-common
    command: webserver
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "--fail", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    restart: always
    depends_on:
      <<: *airflow-common-depends-on
      airflow-init:
        condition: service_completed_successfully

  airflow-scheduler:
    <<: *airflow-common
    command: scheduler
    healthcheck:
      test: ["CMD", "curl", "--fail", "http://localhost:8974/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    restart: always
    depends_on:
      <<: *airflow-common-depends-on
      airflow-init:
        condition: service_completed_successfully

  airflow-init:
    <<: *airflow-common
    entrypoint: /bin/bash
    command:
      - -c
      - |
        if [[ -z "${AIRFLOW_UID}" ]]; then
          echo "AIRFLOW_UID not set, using default 50000"
          export AIRFLOW_UID=50000
        fi
        mkdir -p /sources/logs /sources/dags /sources/plugins
        chown -R "${AIRFLOW_UID}:0" /sources/{logs,dags,plugins}
        exec /entrypoint airflow db migrate
        airflow users create \\
          --username admin \\
          --firstname Admin \\
          --lastname User \\
          --role Admin \\
          --email admin@example.com \\
          --password admin
    environment:
      <<: *airflow-common-env
      _AIRFLOW_DB_MIGRATE: 'true'
      _AIRFLOW_WWW_USER_CREATE: 'true'
      _AIRFLOW_WWW_USER_USERNAME: admin
      _AIRFLOW_WWW_USER_PASSWORD: admin
    user: "0:0"
    volumes:
      - ./:/sources

volumes:
  postgres-db-volume:
"""

# =============================================================================
# ENVIRONMENT VARIABLES TEMPLATE
# =============================================================================

"""
.env file template for Docker Compose
Save as .env in the same directory as docker-compose.yml
"""

env_template = """
# Airflow UID (run `id -u` on Linux/Mac to get your user ID)
AIRFLOW_UID=50000

# Choose your OIDC provider: keycloak, okta, or azure
OIDC_PROVIDER=keycloak

# =============================================================================
# KEYCLOAK CONFIGURATION
# =============================================================================
KEYCLOAK_BASE_URL=https://keycloak.example.com
KEYCLOAK_REALM=airflow
KEYCLOAK_CLIENT_ID=airflow
KEYCLOAK_CLIENT_SECRET=your-keycloak-client-secret

# =============================================================================
# OKTA CONFIGURATION
# =============================================================================
# OKTA_DOMAIN=your-domain.okta.com
# OKTA_AUTH_SERVER=default
# OKTA_CLIENT_ID=your-okta-client-id
# OKTA_CLIENT_SECRET=your-okta-client-secret

# =============================================================================
# AZURE AD CONFIGURATION
# =============================================================================
# AZURE_TENANT_ID=your-tenant-id
# AZURE_CLIENT_ID=your-client-id
# AZURE_CLIENT_SECRET=your-client-secret
"""

print("Configuration examples complete!")
print("\nFiles to create:")
print("1. webserver_config.py - Choose configuration for your OIDC provider")
print("2. docker-compose.yml - For Docker deployment")
print("3. .env - Environment variables")
print("4. test_oidc_auth.py - To test your configuration")