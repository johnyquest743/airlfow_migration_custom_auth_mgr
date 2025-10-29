# -*- coding: utf-8 -*-
"""
===============================================================================
Airflow 2.10 Webserver Configuration for OIDC Authentication
Compatible with Python 3.12
===============================================================================

This file configures Flask-AppBuilder (FAB) authentication for Airflow webserver.
Location: $AIRFLOW_HOME/webserver_config.py

OIDC configuration is loaded from JSON files in $AIRFLOW_HOME/config/

Author: Airflow Admin
Date: 2025
Python Version: 3.12+
Airflow Version: 2.10.x
===============================================================================
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from datetime import timedelta

# Flask and Flask-AppBuilder imports
from flask import redirect, session, url_for, flash, request
from flask_appbuilder import expose
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.views import AuthOAuthView
from flask_login import logout_user, current_user

# Airflow imports
from airflow.configuration import conf
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride

# Third-party imports for OIDC
try:
    import requests
    from requests.exceptions import RequestException, Timeout, HTTPError
except ImportError:
    raise ImportError("requests library is required. Install with: pip install requests")

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.oauth2.rfc6749 import OAuth2Token
except ImportError:
    raise ImportError("authlib library is required. Install with: pip install authlib")

# Setup logging
log = logging.getLogger(__name__)
log.setLevel(os.getenv("AIRFLOW__LOGGING__FAB_LOGGING_LEVEL", "INFO"))

# ============================================================================
# CONFIGURATION FILE LOADER
# ============================================================================

class OIDCConfigLoader:
    """
    Loads OIDC configuration from JSON files in $AIRFLOW_HOME/config/
    
    Expected JSON files:
    - oidc_client.json: Client credentials and provider information
    - oidc_roles.json: Role mapping configuration
    - oidc_settings.json: Additional OIDC settings
    """
    
    def __init__(self):
        self.airflow_home = os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow'))
        self.config_dir = Path(self.airflow_home) / 'config'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        log.info(f"OIDC Config directory: {self.config_dir}")
    
    def load_json_file(self, filename: str) -> Dict[str, Any]:
        """Load and parse a JSON configuration file"""
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            log.warning(f"Configuration file not found: {file_path}")
            return {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                log.info(f"Successfully loaded configuration from {filename}")
                return config
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse JSON from {filename}: {e}")
            return {}
        except Exception as e:
            log.error(f"Error loading {filename}: {e}")
            return {}
    
    def load_client_config(self) -> Dict[str, Any]:
        """Load OIDC client configuration"""
        return self.load_json_file('oidc_client.json')
    
    def load_role_mapping(self) -> Dict[str, List[str]]:
        """Load OIDC role mapping configuration"""
        config = self.load_json_file('oidc_roles.json')
        return config.get('role_mapping', {})
    
    def load_settings(self) -> Dict[str, Any]:
        """Load additional OIDC settings"""
        return self.load_json_file('oidc_settings.json')
    
    def get_provider_config(self, provider_name: str = None) -> Dict[str, Any]:
        """Get configuration for a specific OIDC provider"""
        client_config = self.load_client_config()
        
        if not client_config:
            log.error("No OIDC client configuration found")
            return {}
        
        # If provider_name is specified, return that provider's config
        if provider_name:
            providers = client_config.get('providers', [])
            for provider in providers:
                if provider.get('name') == provider_name:
                    return provider
            log.warning(f"Provider '{provider_name}' not found in configuration")
            return {}
        
        # Return the first active provider
        providers = client_config.get('providers', [])
        for provider in providers:
            if provider.get('enabled', True):
                return provider
        
        # Fallback to first provider if none are marked as enabled
        return providers[0] if providers else {}

# Initialize config loader
config_loader = OIDCConfigLoader()

# ============================================================================
# BASIC FLASK CONFIGURATION
# ============================================================================

# Enable Flask-WTF CSRF protection
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None

# CSRF exempt list for API endpoints
WTF_CSRF_EXEMPT_LIST = []

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

SQLALCHEMY_DATABASE_URI = conf.get('database', 'SQL_ALCHEMY_CONN')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_POOL_SIZE = 5
SQLALCHEMY_POOL_RECYCLE = 1800
SQLALCHEMY_MAX_OVERFLOW = 10
SQLALCHEMY_POOL_PRE_PING = True

# ============================================================================
# AUTHENTICATION TYPE
# ============================================================================

AUTH_TYPE = AUTH_OAUTH

# ============================================================================
# LOAD OIDC CONFIGURATION FROM JSON FILES
# ============================================================================

# Load configurations
_client_config = config_loader.load_client_config()
_role_mapping_config = config_loader.load_role_mapping()
_settings_config = config_loader.load_settings()

# Get active provider configuration
_provider_config = config_loader.get_provider_config()

# ============================================================================
# USER REGISTRATION SETTINGS
# ============================================================================

AUTH_USER_REGISTRATION = _settings_config.get('auth_user_registration', True)
AUTH_USER_REGISTRATION_ROLE = _settings_config.get('auth_user_registration_role', 'Viewer')
AUTH_ROLES_SYNC_AT_LOGIN = _settings_config.get('auth_roles_sync_at_login', True)

# Role mapping from OIDC groups to Airflow roles
AUTH_ROLES_MAPPING = _role_mapping_config

# ============================================================================
# SESSION CONFIGURATION
# ============================================================================

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = _settings_config.get('session_cookie_secure', False)
SESSION_COOKIE_SAMESITE = _settings_config.get('session_cookie_samesite', 'Lax')

# Session lifetime from settings
_session_hours = _settings_config.get('session_lifetime_hours', 12)
PERMANENT_SESSION_LIFETIME = timedelta(hours=_session_hours)

REMEMBER_COOKIE_DURATION = timedelta(days=7)
REMEMBER_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE

# ============================================================================
# FLASK APP CONFIGURATION
# ============================================================================

APP_NAME = _settings_config.get('app_name', 'Airflow')
APP_THEME = _settings_config.get('app_theme', '')
APP_ICON = _settings_config.get('app_icon', '/static/pin_100.png')

# ============================================================================
# RATE LIMITING
# ============================================================================

RATELIMIT_ENABLED = _settings_config.get('ratelimit_enabled', True)
RATELIMIT_STORAGE_URI = _settings_config.get('ratelimit_storage_uri', 'memory://')
RATELIMIT_STRATEGY = _settings_config.get('ratelimit_strategy', 'moving-window')
RATELIMIT_DEFAULT = _settings_config.get('ratelimit_default', '200 per day, 50 per hour')

# ============================================================================
# BUILD OAUTH PROVIDERS FROM JSON CONFIGURATION
# ============================================================================

OAUTH_PROVIDERS = []

if _provider_config:
    provider_name = _provider_config.get('name', 'oidc')
    client_id = _provider_config.get('client_id', '')
    client_secret = _provider_config.get('client_secret', '')
    
    # Support both metadata URL and individual endpoints
    if 'server_metadata_url' in _provider_config:
        oauth_config = {
            'name': provider_name,
            'icon': _provider_config.get('icon', 'fa-key'),
            'token_key': _provider_config.get('token_key', 'access_token'),
            'remote_app': {
                'client_id': client_id,
                'client_secret': client_secret,
                'server_metadata_url': _provider_config['server_metadata_url'],
                'api_base_url': _provider_config.get('api_base_url', _provider_config.get('issuer', '')),
                'client_kwargs': {
                    'scope': _provider_config.get('scope', 'openid email profile groups')
                },
            }
        }
    else:
        # Fallback to individual endpoint configuration
        oauth_config = {
            'name': provider_name,
            'icon': _provider_config.get('icon', 'fa-key'),
            'token_key': _provider_config.get('token_key', 'access_token'),
            'remote_app': {
                'client_id': client_id,
                'client_secret': client_secret,
                'authorize_url': _provider_config.get('authorize_url', ''),
                'access_token_url': _provider_config.get('access_token_url', ''),
                'api_base_url': _provider_config.get('api_base_url', ''),
                'client_kwargs': {
                    'scope': _provider_config.get('scope', 'openid email profile groups')
                },
            }
        }
    
    OAUTH_PROVIDERS.append(oauth_config)
    log.info(f"Configured OAuth provider: {provider_name}")
else:
    log.error("No OIDC provider configuration found!")

# ============================================================================
# CUSTOM OAUTH VIEW
# ============================================================================

class CustomOAuthView(AuthOAuthView):
    """
    Custom OAuth view to handle OIDC authentication flow
    Supports logout with OIDC provider
    """
    
    @expose('/logout/')
    def logout(self):
        """Custom logout to handle OIDC provider logout"""
        try:
            # Get provider configuration
            provider_config = config_loader.get_provider_config()
            
            # Clear Flask session
            logout_user()
            session.clear()
            
            # If OIDC provider has logout URL, redirect there
            if provider_config.get('logout_url'):
                logout_url = provider_config['logout_url']
                post_logout_redirect = request.url_root
                
                # Build logout URL with redirect
                full_logout_url = f"{logout_url}?post_logout_redirect_uri={post_logout_redirect}"
                log.info(f"Redirecting to OIDC provider logout: {full_logout_url}")
                return redirect(full_logout_url)
            
        except Exception as e:
            log.error(f"Error during OIDC logout: {e}")
        
        # Fallback to default logout
        return redirect(self.appbuilder.get_url_for_index)

# ============================================================================
# CUSTOM SECURITY MANAGER
# ============================================================================

class CustomOIDCSecurityManager(FabAirflowSecurityManagerOverride):
    """
    Custom Security Manager for OIDC authentication
    Reads configuration from JSON files and handles user info extraction
    """
    
    # Use custom OAuth view
    authoauthview = CustomOAuthView
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.provider_config = config_loader.get_provider_config()
        self.role_mapping = config_loader.load_role_mapping()
        self.settings = config_loader.load_settings()
        
        log.info("CustomOIDCSecurityManager initialized")
        log.info(f"Provider: {self.provider_config.get('name', 'unknown')}")
        log.info(f"Role mapping configured: {len(self.role_mapping)} mappings")
    
    def oauth_user_info(self, provider: str, response: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract user information from OIDC provider response
        
        Args:
            provider: OAuth provider name
            response: OAuth response containing tokens
            
        Returns:
            Dictionary with user info: username, email, first_name, last_name, role_keys
        """
        if not response:
            log.error("No OAuth response provided")
            return {}
        
        access_token = response.get('access_token')
        if not access_token:
            log.error("No access token found in OAuth response")
            return {}
        
        try:
            # Get user info from OIDC provider
            user_info = self._fetch_user_info(access_token)
            
            if not user_info:
                log.error("Failed to fetch user info from OIDC provider")
                return {}
            
            log.info(f"Received user info for: {user_info.get('email', 'unknown')}")
            
            # Extract groups/roles
            groups = self._extract_groups(user_info, access_token)
            
            # Map OIDC groups to Airflow roles
            role_keys = self._map_groups_to_roles(groups)
            
            # Build user info dictionary
            user_data = {
                'username': self._get_username(user_info),
                'email': user_info.get('email', ''),
                'first_name': user_info.get('given_name', user_info.get('first_name', '')),
                'last_name': user_info.get('family_name', user_info.get('last_name', '')),
                'role_keys': role_keys
            }
            
            log.info(f"Mapped user: {user_data['username']} with roles: {role_keys}")
            return user_data
            
        except Exception as e:
            log.error(f"Error extracting user info: {e}", exc_info=True)
            return {}
    
    def _fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from OIDC provider's userinfo endpoint"""
        userinfo_url = self.provider_config.get('userinfo_url')
        
        if not userinfo_url:
            log.error("userinfo_url not configured in provider configuration")
            return {}
        
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            timeout = self.settings.get('request_timeout', 30)
            response = requests.get(userinfo_url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            return response.json()
            
        except Timeout:
            log.error(f"Timeout fetching user info from {userinfo_url}")
            return {}
        except HTTPError as e:
            log.error(f"HTTP error fetching user info: {e.response.status_code} - {e.response.text}")
            return {}
        except RequestException as e:
            log.error(f"Request error fetching user info: {e}")
            return {}
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse user info JSON: {e}")
            return {}
    
    def _extract_groups(self, user_info: Dict[str, Any], access_token: str) -> List[str]:
        """Extract groups from user info or make additional API call if needed"""
        groups = []
        
        # Try to get groups from user info directly
        group_claim = self.provider_config.get('group_claim', 'groups')
        groups = user_info.get(group_claim, [])
        
        # If groups not in userinfo, try to fetch from groups endpoint
        if not groups and self.provider_config.get('groups_url'):
            groups = self._fetch_groups(access_token)
        
        # Handle both list and string formats
        if isinstance(groups, str):
            groups = [groups]
        
        log.debug(f"Extracted groups: {groups}")
        return groups
    
    def _fetch_groups(self, access_token: str) -> List[str]:
        """Fetch groups from a separate endpoint (e.g., Microsoft Graph API)"""
        groups_url = self.provider_config.get('groups_url')
        
        if not groups_url:
            return []
        
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            timeout = self.settings.get('request_timeout', 30)
            response = requests.get(groups_url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Handle different response formats
            # Microsoft Graph format
            if 'value' in data:
                return [group.get('displayName') for group in data['value'] if 'displayName' in group]
            
            # Direct list format
            if isinstance(data, list):
                return data
            
            return []
            
        except Exception as e:
            log.error(f"Error fetching groups: {e}")
            return []
    
    def _map_groups_to_roles(self, groups: List[str]) -> List[str]:
        """Map OIDC groups to Airflow roles using configured mapping"""
        role_keys = []
        
        for group in groups:
            if group in self.role_mapping:
                mapped_roles = self.role_mapping[group]
                role_keys.extend(mapped_roles)
                log.debug(f"Mapped group '{group}' to roles: {mapped_roles}")
        
        # Remove duplicates
        role_keys = list(set(role_keys))
        
        # If no roles mapped, assign default role
        if not role_keys:
            default_role = self.settings.get('auth_user_registration_role', 'Viewer')
            role_keys = [default_role]
            log.info(f"No groups matched, assigning default role: {default_role}")
        
        return role_keys
    
    def _get_username(self, user_info: Dict[str, Any]) -> str:
        """Extract username from user info based on provider configuration"""
        username_claim = self.provider_config.get('username_claim', 'preferred_username')
        
        # Try configured username claim first
        username = user_info.get(username_claim)
        
        # Fallback options
        if not username:
            username = user_info.get('preferred_username') or \
                      user_info.get('email') or \
                      user_info.get('sub') or \
                      'unknown_user'
        
        return username

# Set the custom security manager
SECURITY_MANAGER_CLASS = CustomOIDCSecurityManager

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Log successful initialization
if OAUTH_PROVIDERS:
    log.info("="*70)
    log.info("OIDC Authentication Configuration Loaded Successfully")
    log.info(f"Provider: {_provider_config.get('name', 'unknown')}")
    log.info(f"Client ID: {_provider_config.get('client_id', 'not configured')[:10]}...")
    log.info(f"Role Mappings: {len(AUTH_ROLES_MAPPING)} configured")
    log.info(f"Auto-registration: {AUTH_USER_REGISTRATION}")
    log.info(f"Default role: {AUTH_USER_REGISTRATION_ROLE}")
    log.info("="*70)
else:
    log.error("="*70)
    log.error("OIDC Configuration Error!")
    log.error("No OAuth providers configured. Check your JSON configuration files.")
    log.error(f"Config directory: {config_loader.config_dir}")
    log.error("="*70)

# ============================================================================
# END OF CONFIGURATION
# ============================================================================