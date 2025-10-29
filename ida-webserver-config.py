# -*- coding: utf-8 -*-
"""
===============================================================================
Airflow 2.10 Webserver Configuration for IDA OIDC Authentication
Compatible with Python 3.12
===============================================================================

This configuration is specifically designed for your firm's internal IDA
authentication system using OIDC protocol.

Location: $AIRFLOW_HOME/webserver_config.py

===============================================================================
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Any
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
# IDA CONFIGURATION LOADER
# ============================================================================

class IDAConfigLoader:
    """
    Loads IDA OIDC configuration from JSON files
    Specifically designed for internal IDA authentication
    """
    
    def __init__(self):
        self.airflow_home = os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow'))
        self.config_dir = Path(self.airflow_home) / 'config'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        log.info(f"IDA Config directory: {self.config_dir}")
    
    def load_json_file(self, filename: str) -> Dict[str, Any]:
        """Load and parse a JSON configuration file"""
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            log.error(f"Configuration file not found: {file_path}")
            raise FileNotFoundError(f"Required configuration file missing: {filename}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                log.info(f"Successfully loaded {filename}")
                return config
        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in {filename}: {e}")
            raise
        except Exception as e:
            log.error(f"Error loading {filename}: {e}")
            raise
    
    def load_client_config(self) -> Dict[str, Any]:
        """Load IDA client configuration"""
        return self.load_json_file('oidc_client.json')
    
    def load_role_mapping(self) -> Dict[str, List[str]]:
        """Load IDA role mapping configuration"""
        config = self.load_json_file('oidc_roles.json')
        return config.get('role_mapping', {})
    
    def load_settings(self) -> Dict[str, Any]:
        """Load additional IDA settings"""
        return self.load_json_file('oidc_settings.json')
    
    def get_ida_provider_config(self) -> Dict[str, Any]:
        """Get IDA provider configuration"""
        client_config = self.load_client_config()
        providers = client_config.get('providers', [])
        
        # Find IDA provider
        for provider in providers:
            if provider.get('type') == 'custom_ida' and provider.get('enabled', False):
                log.info(f"Loaded IDA provider: {provider.get('name')}")
                return provider
        
        # Fallback to first enabled provider
        for provider in providers:
            if provider.get('enabled', False):
                log.warning(f"IDA provider not found, using: {provider.get('name')}")
                return provider
        
        log.error("No enabled OIDC provider found in configuration!")
        raise ValueError("No IDA provider configured")

# Initialize config loader
config_loader = IDAConfigLoader()

# ============================================================================
# BASIC FLASK CONFIGURATION
# ============================================================================

CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None
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
# LOAD IDA CONFIGURATION FROM JSON FILES
# ============================================================================

try:
    # Load configurations
    _client_config = config_loader.load_client_config()
    _role_mapping_config = config_loader.load_role_mapping()
    _settings_config = config_loader.load_settings()
    
    # Get IDA provider configuration
    _ida_config = config_loader.get_ida_provider_config()
    
    log.info("="*70)
    log.info("IDA OIDC Configuration Loaded")
    log.info(f"Provider: {_ida_config.get('name', 'ida')}")
    log.info(f"Issuer: {_ida_config.get('issuer', 'not configured')}")
    log.info(f"Client ID: {_ida_config.get('client_id', 'not configured')[:20]}...")
    log.info("="*70)
    
except Exception as e:
    log.error(f"Failed to load IDA configuration: {e}")
    raise

# ============================================================================
# USER REGISTRATION SETTINGS
# ============================================================================

AUTH_USER_REGISTRATION = _settings_config.get('authentication', {}).get('auth_user_registration', True)
AUTH_USER_REGISTRATION_ROLE = _settings_config.get('authentication', {}).get('auth_user_registration_role', 'Viewer')
AUTH_ROLES_SYNC_AT_LOGIN = _settings_config.get('authentication', {}).get('auth_roles_sync_at_login', True)

# Role mapping from IDA groups to Airflow roles
AUTH_ROLES_MAPPING = _role_mapping_config

# ============================================================================
# SESSION CONFIGURATION
# ============================================================================

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = _settings_config.get('session', {}).get('session_cookie_secure', False)
SESSION_COOKIE_SAMESITE = _settings_config.get('session', {}).get('session_cookie_samesite', 'Lax')

# Session lifetime from settings
_session_hours = _settings_config.get('session', {}).get('session_lifetime_hours', 12)
PERMANENT_SESSION_LIFETIME = timedelta(hours=_session_hours)

REMEMBER_COOKIE_DURATION = timedelta(days=7)
REMEMBER_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE

# ============================================================================
# FLASK APP CONFIGURATION
# ============================================================================

APP_NAME = _settings_config.get('application', {}).get('app_name', 'Airflow')
APP_THEME = _settings_config.get('application', {}).get('app_theme', '')
APP_ICON = _settings_config.get('application', {}).get('app_icon', '/static/pin_100.png')

# ============================================================================
# RATE LIMITING
# ============================================================================

RATELIMIT_ENABLED = _settings_config.get('rate_limiting', {}).get('ratelimit_enabled', True)
RATELIMIT_STORAGE_URI = _settings_config.get('rate_limiting', {}).get('ratelimit_storage_uri', 'memory://')
RATELIMIT_STRATEGY = _settings_config.get('rate_limiting', {}).get('ratelimit_strategy', 'moving-window')
RATELIMIT_DEFAULT = _settings_config.get('rate_limiting', {}).get('ratelimit_default', '200 per day, 50 per hour')

# ============================================================================
# BUILD OAUTH PROVIDER FOR IDA
# ============================================================================

# Extract IDA configuration
_ida_name = _ida_config.get('name', 'ida')
_ida_client_id = _ida_config.get('client_id', '')
_ida_client_secret = _ida_config.get('client_secret', '')
_ida_scope = _ida_config.get('scope', 'openid email profile groups')
_ida_icon = _ida_config.get('icon', 'fa-building')
_ida_display_name = _ida_config.get('display_name', 'IDA Login')

# Build OAuth provider configuration
OAUTH_PROVIDERS = []

if _ida_config.get('server_metadata_url'):
    # Use OIDC discovery
    oauth_config = {
        'name': _ida_name,
        'icon': _ida_icon,
        'token_key': _ida_config.get('token_key', 'access_token'),
        'remote_app': {
            'client_id': _ida_client_id,
            'client_secret': _ida_client_secret,
            'server_metadata_url': _ida_config['server_metadata_url'],
            'api_base_url': _ida_config.get('api_base_url', _ida_config.get('issuer', '')),
            'client_kwargs': {
                'scope': _ida_scope,
                'token_endpoint_auth_method': _ida_config.get('token_endpoint_auth_method', 'client_secret_post'),
            },
        }
    }
    
    # Add custom headers if configured
    if _ida_config.get('custom_headers'):
        oauth_config['remote_app']['client_kwargs']['headers'] = _ida_config['custom_headers']
    
    # Add custom authorize parameters
    if _ida_config.get('custom_authorize_params'):
        oauth_config['remote_app']['authorize_params'] = _ida_config['custom_authorize_params']
    
else:
    # Manual endpoint configuration
    oauth_config = {
        'name': _ida_name,
        'icon': _ida_icon,
        'token_key': _ida_config.get('token_key', 'access_token'),
        'remote_app': {
            'client_id': _ida_client_id,
            'client_secret': _ida_client_secret,
            'authorize_url': _ida_config.get('authorize_url', ''),
            'access_token_url': _ida_config.get('access_token_url', ''),
            'api_base_url': _ida_config.get('api_base_url', ''),
            'client_kwargs': {
                'scope': _ida_scope,
            },
        }
    }

OAUTH_PROVIDERS.append(oauth_config)
log.info(f"Configured OAuth provider: {_ida_name}")

# ============================================================================
# CUSTOM OAUTH VIEW FOR IDA
# ============================================================================

class IDAOAuthView(AuthOAuthView):
    """
    Custom OAuth view for IDA authentication
    Handles IDA-specific logout flow
    """
    
    @expose('/logout/')
    def logout(self):
        """Custom logout with IDA provider logout"""
        try:
            # Get IDA configuration
            ida_config = config_loader.get_ida_provider_config()
            
            # Clear Flask session
            logout_user()
            
            # Store user info for logging before clearing session
            username = session.get('user', {}).get('username', 'unknown')
            log.info(f"User logout initiated: {username}")
            
            session.clear()
            
            # If IDA has logout URL, redirect there
            if ida_config.get('logout_url'):
                logout_url = ida_config['logout_url']
                
                # Build post-logout redirect
                post_logout_redirect = request.url_root
                
                # Check if custom post-logout redirect is configured
                client_config = config_loader.load_client_config()
                post_logout_uris = client_config.get('post_logout_redirect_uris', [])
                if post_logout_uris:
                    # Use first matching post-logout URI
                    for uri in post_logout_uris:
                        if request.url_root.rstrip('/') in uri:
                            post_logout_redirect = uri
                            break
                
                # Build full logout URL
                full_logout_url = f"{logout_url}?post_logout_redirect_uri={post_logout_redirect}"
                
                log.info(f"Redirecting to IDA logout: {full_logout_url}")
                flash("You have been logged out successfully", "info")
                return redirect(full_logout_url)
            
        except Exception as e:
            log.error(f"Error during IDA logout: {e}", exc_info=True)
            flash("Logout completed with warnings", "warning")
        
        # Fallback to default logout
        return redirect(self.appbuilder.get_url_for_index)

# ============================================================================
# CUSTOM SECURITY MANAGER FOR IDA
# ============================================================================

class IDASecurityManager(FabAirflowSecurityManagerOverride):
    """
    Custom Security Manager for IDA OIDC authentication
    Handles IDA-specific user info extraction and role mapping
    """
    
    # Use custom OAuth view
    authoauthview = IDAOAuthView
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        
        try:
            self.ida_config = config_loader.get_ida_provider_config()
            self.role_mapping = config_loader.load_role_mapping()
            self.settings = config_loader.load_settings()
            
            log.info("IDASecurityManager initialized successfully")
            log.info(f"IDA Provider: {self.ida_config.get('name')}")
            log.info(f"Role mappings configured: {len(self.role_mapping)}")
            
        except Exception as e:
            log.error(f"Failed to initialize IDASecurityManager: {e}")
            raise
    
    def oauth_user_info(self, provider: str, response: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract user information from IDA OAuth response
        
        Args:
            provider: OAuth provider name (should be 'ida')
            response: OAuth response containing tokens
            
        Returns:
            Dictionary with user info for Airflow
        """
        if not response:
            log.error("No OAuth response provided")
            return {}
        
        access_token = response.get('access_token')
        if not access_token:
            log.error("No access token found in OAuth response")
            return {}
        
        try:
            log.info(f"Processing OAuth response for provider: {provider}")
            
            # Fetch user info from IDA
            user_info = self._fetch_ida_userinfo(access_token)
            
            if not user_info:
                log.error("Failed to fetch user info from IDA")
                return {}
            
            # Log successful fetch (without sensitive data)
            log.info(f"Fetched user info for: {user_info.get('email', 'unknown')}")
            
            # Extract groups/roles from IDA
            groups = self._extract_ida_groups(user_info, access_token)
            
            # Map IDA groups to Airflow roles
            roles = self._map_ida_groups_to_roles(groups)
            
            # Apply custom role rules if configured
            roles = self._apply_custom_rules(user_info, groups, roles)
            
            # If no roles, assign default
            if not roles:
                default_role = self.settings.get('authentication', {}).get(
                    'auth_user_registration_role', 'Viewer'
                )
                roles = [default_role]
                log.info(f"No groups matched, assigning default role: {default_role}")
            
            # Build user dictionary
            user_dict = self._build_ida_user_dict(user_info, roles)
            
            log.info(f"User authenticated: {user_dict['username']} with roles: {roles}")
            
            # Store additional attributes in session if configured
            if self.ida_config.get('fetch_additional_attributes'):
                self._store_additional_attributes(user_info)
            
            return user_dict
            
        except Exception as e:
            log.error(f"Error in oauth_user_info: {e}", exc_info=True)
            return {}
    
    def _fetch_ida_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from IDA userinfo endpoint"""
        userinfo_url = self.ida_config.get('userinfo_url')
        
        if not userinfo_url:
            log.error("userinfo_url not configured for IDA")
            return {}
        
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            # Add custom headers if configured
            if self.ida_config.get('custom_headers'):
                headers.update(self.ida_config['custom_headers'])
            
            timeout = self.ida_config.get('timeout_seconds', 30)
            verify_ssl = self.ida_config.get('verify_ssl', True)
            
            # Handle custom CA bundle
            ca_bundle = self.ida_config.get('ca_bundle_path')
            if ca_bundle and os.path.exists(ca_bundle):
                verify_ssl = ca_bundle
            
            response = requests.get(
                userinfo_url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl
            )
            response.raise_for_status()
            
            userinfo = response.json()
            log.debug(f"Successfully fetched userinfo from IDA")
            return userinfo
            
        except Timeout:
            log.error(f"Timeout fetching user info from IDA: {userinfo_url}")
            return {}
        except HTTPError as e:
            log.error(f"HTTP error fetching user info from IDA: {e.response.status_code}")
            log.error(f"Response: {e.response.text}")
            return {}
        except RequestException as e:
            log.error(f"Request error fetching user info from IDA: {e}")
            return {}
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse userinfo JSON from IDA: {e}")
            return {}
    
    def _extract_ida_groups(self, user_info: Dict[str, Any], access_token: str) -> List[str]:
        """Extract groups from IDA user info"""
        groups = []
        
        # Get group claim name from config
        group_claim = self.ida_config.get('group_claim', 'groups')
        groups = user_info.get(group_claim, [])
        
        # Also check roles claim if configured
        role_claim = self.ida_config.get('role_claim')
        if role_claim:
            roles = user_info.get(role_claim, [])
            if isinstance(roles, list):
                groups.extend(roles)
            elif isinstance(roles, str):
                groups.append(roles)
        
        # Handle string format
        if isinstance(groups, str):
            groups = [groups]
        
        # Normalize group names if configured
        if self.settings.get('group_extraction', {}).get('ida', {}).get('normalize_names', False):
            groups = [g.upper() for g in groups]
        
        log.debug(f"Extracted groups from IDA: {groups}")
        return groups
    
    def _map_ida_groups_to_roles(self, groups: List[str]) -> List[str]:
        """Map IDA groups to Airflow roles"""
        roles = set()
        
        # Convert to uppercase for case-insensitive matching if configured
        case_sensitive = self.settings.get('group_extraction', {}).get('ida', {}).get('case_sensitive', False)
        
        for group in groups:
            # Normalize for matching
            match_group = group if case_sensitive else group.upper()
            match_mapping = self.role_mapping if case_sensitive else {
                k.upper(): v for k, v in self.role_mapping.items()
            }
            
            if match_group in match_mapping:
                mapped_roles = match_mapping[match_group]
                roles.update(mapped_roles)
                log.debug(f"Mapped IDA group '{group}' to roles: {mapped_roles}")
        
        return list(roles)
    
    def _apply_custom_rules(self, user_info: Dict[str, Any], groups: List[str], current_roles: List[str]) -> List[str]:
        """Apply custom role rules from configuration"""
        roles_config = config_loader.load_role_mapping()
        custom_rules = roles_config.get('custom_role_rules', {}).get('rules', [])
        
        for rule in custom_rules:
            rule_name = rule.get('name')
            condition = rule.get('condition', {})
            assign_roles = rule.get('assign_roles', [])
            
            # Check if condition matches
            if 'any_group' in condition:
                required_groups = condition['any_group']
                if any(g in groups for g in required_groups):
                    log.info(f"Applied custom rule '{rule_name}': adding roles {assign_roles}")
                    current_roles.extend(assign_roles)
        
        # Remove duplicates
        return list(set(current_roles))
    
    def _build_ida_user_dict(self, user_info: Dict[str, Any], roles: List[str]) -> Dict[str, Any]:
        """Build complete user dictionary for Airflow from IDA userinfo"""
        # Get claim names from config
        username_claim = self.ida_config.get('username_claim', 'preferred_username')
        email_claim = self.ida_config.get('email_claim', 'email')
        first_name_claim = self.ida_config.get('first_name_claim', 'given_name')
        last_name_claim = self.ida_config.get('last_name_claim', 'family_name')
        
        # Extract username
        username = user_info.get(username_claim)
        if not username:
            username = user_info.get('preferred_username') or \
                      user_info.get('email') or \
                      user_info.get('sub') or \
                      f"user_{hash(str(user_info))}"
        
        return {
            'username': username,
            'email': user_info.get(email_claim, ''),
            'first_name': user_info.get(first_name_claim, ''),
            'last_name': user_info.get(last_name_claim, ''),
            'role_keys': roles
        }
    
    def _store_additional_attributes(self, user_info: Dict[str, Any]):
        """Store additional IDA attributes in session"""
        additional_attrs = self.ida_config.get('additional_attributes', [])
        
        if additional_attrs:
            session['ida_attributes'] = {}
            for attr in additional_attrs:
                if attr in user_info:
                    session['ida_attributes'][attr] = user_info[attr]
            
            log.debug(f"Stored additional IDA attributes: {list(session['ida_attributes'].keys())}")

# Set the custom security manager
SECURITY_MANAGER_CLASS = IDASecurityManager

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

if OAUTH_PROVIDERS:
    log.info("="*70)
    log.info("IDA OIDC Authentication Configuration Complete")
    log.info(f"Provider Name: {_ida_name}")
    log.info(f"Display Name: {_ida_display_name}")
    log.info(f"Issuer: {_ida_config.get('issuer', 'not configured')}")
    log.info(f"Auto-registration: {AUTH_USER_REGISTRATION}")
    log.info(f"Default role: {AUTH_USER_REGISTRATION_ROLE}")
    log.info(f"Role mappings: {len(AUTH_ROLES_MAPPING)} configured")
    log.info("="*70)
else:
    log.error("="*70)
    log.error("IDA OIDC Configuration Error!")
    log.error("No OAuth providers configured")
    log.error("="*70)

# ============================================================================
# END OF CONFIGURATION
# ============================================================================