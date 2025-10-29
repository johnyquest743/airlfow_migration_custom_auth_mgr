#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
Custom OIDC Authentication Module for Airflow 2.10
Compatible with Python 3.12
===============================================================================

This module provides a complete OIDC authentication implementation that:
- Loads configuration from JSON files
- Supports multiple OIDC providers
- Handles user info extraction and role mapping
- Uses authlib for OAuth2/OIDC flows

Location: $AIRFLOW_HOME/plugins/custom_oidc_auth.py
or can be imported in webserver_config.py

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
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
import hashlib

# Third-party imports
try:
    import requests
    from requests.exceptions import RequestException, Timeout, HTTPError, ConnectionError
except ImportError:
    raise ImportError("requests is required: pip install requests")

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.oauth2.rfc6749 import OAuth2Token
    from authlib.jose import jwt, JsonWebKey
    from authlib.jose.errors import JoseError
except ImportError:
    raise ImportError("authlib is required: pip install authlib")

# Flask imports
try:
    from flask import session, redirect, url_for, request, flash
    from flask_appbuilder.security.views import AuthOAuthView
    from flask_login import logout_user
except ImportError:
    raise ImportError("Flask and Flask-AppBuilder required")

# Airflow imports
try:
    from airflow.configuration import conf
    from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride
except ImportError:
    raise ImportError("Airflow packages required")

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ============================================================================
# CONFIGURATION LOADER
# ============================================================================

class OIDCConfigurationManager:
    """
    Manages OIDC configuration from JSON files
    Supports caching and validation
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration manager
        
        Args:
            config_dir: Path to configuration directory. 
                       Defaults to $AIRFLOW_HOME/config
        """
        if config_dir is None:
            airflow_home = os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow'))
            config_dir = Path(airflow_home) / 'config'
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self._client_config: Optional[Dict] = None
        self._roles_config: Optional[Dict] = None
        self._settings_config: Optional[Dict] = None
        self._cache_timestamp: Dict[str, datetime] = {}
        
        logger.info(f"OIDCConfigurationManager initialized with config_dir: {self.config_dir}")
    
    def load_json(self, filename: str, force_reload: bool = False) -> Dict[str, Any]:
        """
        Load and cache JSON configuration file
        
        Args:
            filename: Name of JSON file to load
            force_reload: Force reload even if cached
            
        Returns:
            Dictionary containing configuration
        """
        file_path = self.config_dir / filename
        
        # Check cache
        cache_key = filename
        if not force_reload and cache_key in self._cache_timestamp:
            # Check if file has been modified
            if file_path.exists():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime <= self._cache_timestamp[cache_key]:
                    logger.debug(f"Using cached config for {filename}")
                    return self._get_cached_config(filename)
        
        # Load from file
        if not file_path.exists():
            logger.warning(f"Configuration file not found: {file_path}")
            return {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Update cache
            self._cache_timestamp[cache_key] = datetime.now()
            self._update_cache(filename, config)
            
            logger.info(f"Loaded configuration from {filename}")
            return config
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {filename}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
            return {}
    
    def _get_cached_config(self, filename: str) -> Dict[str, Any]:
        """Get configuration from cache"""
        if filename == 'oidc_client.json':
            return self._client_config or {}
        elif filename == 'oidc_roles.json':
            return self._roles_config or {}
        elif filename == 'oidc_settings.json':
            return self._settings_config or {}
        return {}
    
    def _update_cache(self, filename: str, config: Dict[str, Any]):
        """Update configuration cache"""
        if filename == 'oidc_client.json':
            self._client_config = config
        elif filename == 'oidc_roles.json':
            self._roles_config = config
        elif filename == 'oidc_settings.json':
            self._settings_config = config
    
    def get_client_config(self, force_reload: bool = False) -> Dict[str, Any]:
        """Load client configuration"""
        return self.load_json('oidc_client.json', force_reload)
    
    def get_roles_config(self, force_reload: bool = False) -> Dict[str, Any]:
        """Load roles configuration"""
        return self.load_json('oidc_roles.json', force_reload)
    
    def get_settings_config(self, force_reload: bool = False) -> Dict[str, Any]:
        """Load settings configuration"""
        return self.load_json('oidc_settings.json', force_reload)
    
    def get_active_provider(self) -> Optional[Dict[str, Any]]:
        """Get the active OIDC provider configuration"""
        client_config = self.get_client_config()
        providers = client_config.get('providers', [])
        
        # Find first enabled provider
        for provider in providers:
            if provider.get('enabled', False):
                logger.info(f"Active provider: {provider.get('name')}")
                return provider
        
        # Fallback to first provider
        if providers:
            logger.warning("No enabled provider found, using first provider")
            return providers[0]
        
        logger.error("No OIDC providers configured")
        return None
    
    def validate_configuration(self) -> Tuple[bool, List[str]]:
        """
        Validate OIDC configuration
        
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        # Check client config
        client_config = self.get_client_config()
        if not client_config:
            errors.append("Missing oidc_client.json")
        else:
            providers = client_config.get('providers', [])
            if not providers:
                errors.append("No providers configured in oidc_client.json")
            else:
                for provider in providers:
                    if provider.get('enabled', False):
                        required_fields = ['name', 'client_id', 'client_secret']
                        for field in required_fields:
                            if not provider.get(field):
                                errors.append(f"Provider '{provider.get('name')}' missing '{field}'")
        
        # Check roles config
        roles_config = self.get_roles_config()
        if not roles_config:
            errors.append("Missing oidc_roles.json")
        elif not roles_config.get('role_mapping'):
            errors.append("No role_mapping defined in oidc_roles.json")
        
        # Check settings config
        settings_config = self.get_settings_config()
        if not settings_config:
            errors.append("Missing oidc_settings.json")
        
        is_valid = len(errors) == 0
        return is_valid, errors

# ============================================================================
# OIDC TOKEN HANDLER
# ============================================================================

class OIDCTokenHandler:
    """Handles OIDC token validation, refresh, and management"""
    
    def __init__(self, provider_config: Dict[str, Any]):
        self.provider_config = provider_config
        self.jwks_cache: Optional[Dict] = None
        self.jwks_cache_time: Optional[datetime] = None
        self.cache_duration = timedelta(hours=1)
    
    def validate_token(self, token: str, token_type: str = 'access') -> Tuple[bool, Optional[Dict]]:
        """
        Validate JWT token
        
        Args:
            token: JWT token string
            token_type: Type of token ('access' or 'id')
            
        Returns:
            Tuple of (is_valid, decoded_payload)
        """
        try:
            # Get JWKS for validation
            jwks = self._get_jwks()
            if not jwks:
                logger.error("Unable to fetch JWKS for token validation")
                return False, None
            
            # Decode and validate token
            claims = jwt.decode(
                token,
                jwks,
                claims_options={
                    'iss': {'essential': True, 'value': self.provider_config.get('issuer')},
                    'aud': {'essential': True} if token_type == 'id' else {'essential': False},
                }
            )
            
            claims.validate()
            logger.debug(f"{token_type.capitalize()} token validated successfully")
            return True, dict(claims)
            
        except JoseError as e:
            logger.error(f"Token validation failed: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}")
            return False, None
    
    def _get_jwks(self) -> Optional[JsonWebKey]:
        """Fetch and cache JWKS from provider"""
        # Check cache
        if self.jwks_cache and self.jwks_cache_time:
            if datetime.now() - self.jwks_cache_time < self.cache_duration:
                return self.jwks_cache
        
        # Fetch JWKS
        jwks_uri = self.provider_config.get('jwks_uri')
        if not jwks_uri:
            # Try to get from metadata
            metadata_url = self.provider_config.get('server_metadata_url')
            if metadata_url:
                try:
                    response = requests.get(metadata_url, timeout=10)
                    response.raise_for_status()
                    metadata = response.json()
                    jwks_uri = metadata.get('jwks_uri')
                except Exception as e:
                    logger.error(f"Failed to fetch metadata: {e}")
                    return None
        
        if not jwks_uri:
            logger.error("JWKS URI not available")
            return None
        
        try:
            response = requests.get(jwks_uri, timeout=10)
            response.raise_for_status()
            jwks_data = response.json()
            
            # Create JsonWebKey
            self.jwks_cache = JsonWebKey.import_key_set(jwks_data)
            self.jwks_cache_time = datetime.now()
            
            logger.debug("JWKS fetched and cached successfully")
            return self.jwks_cache
            
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            return None
    
    def refresh_token(self, refresh_token: str) -> Optional[OAuth2Token]:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Refresh token string
            
        Returns:
            New OAuth2Token or None if refresh failed
        """
        token_url = self.provider_config.get('access_token_url')
        client_id = self.provider_config.get('client_id')
        client_secret = self.provider_config.get('client_secret')
        
        if not all([token_url, client_id, client_secret, refresh_token]):
            logger.error("Missing required parameters for token refresh")
            return None
        
        try:
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': client_id,
                'client_secret': client_secret
            }
            
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            logger.info("Token refreshed successfully")
            return OAuth2Token(token_data)
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None

# ============================================================================
# USER INFO EXTRACTOR
# ============================================================================

class OIDCUserInfoExtractor:
    """Extracts and processes user information from OIDC providers"""
    
    def __init__(self, provider_config: Dict[str, Any], role_mapping: Dict[str, List[str]]):
        self.provider_config = provider_config
        self.role_mapping = role_mapping
        self.provider_type = provider_config.get('type', 'generic')
    
    def fetch_userinfo(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Fetch user info from OIDC provider
        
        Args:
            access_token: Access token string
            
        Returns:
            User info dictionary or None
        """
        userinfo_url = self.provider_config.get('userinfo_url')
        
        if not userinfo_url:
            logger.error("userinfo_url not configured")
            return None
        
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            response = requests.get(userinfo_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            userinfo = response.json()
            logger.info(f"Fetched userinfo for: {userinfo.get('email', 'unknown')}")
            return userinfo
            
        except HTTPError as e:
            logger.error(f"HTTP error fetching userinfo: {e.response.status_code}")
            return None
        except Timeout:
            logger.error("Timeout fetching userinfo")
            return None
        except Exception as e:
            logger.error(f"Error fetching userinfo: {e}")
            return None
    
    def extract_groups(self, userinfo: Dict[str, Any], access_token: str) -> List[str]:
        """
        Extract groups from userinfo or additional API calls
        
        Args:
            userinfo: User info dictionary
            access_token: Access token for additional API calls
            
        Returns:
            List of group names
        """
        group_claim = self.provider_config.get('group_claim', 'groups')
        groups = userinfo.get(group_claim, [])
        
        # Handle string groups
        if isinstance(groups, str):
            groups = [groups]
        
        # Provider-specific group extraction
        if self.provider_type == 'azure_ad' and not groups:
            groups = self._fetch_azure_groups(access_token)
        elif self.provider_type == 'okta' and not groups:
            groups = self._fetch_okta_groups(access_token)
        
        logger.debug(f"Extracted groups: {groups}")
        return groups
    
    def _fetch_azure_groups(self, access_token: str) -> List[str]:
        """Fetch groups from Microsoft Graph API"""
        groups_url = self.provider_config.get('groups_url', 
                                              'https://graph.microsoft.com/v1.0/me/memberOf')
        
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            response = requests.get(groups_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            groups = [g.get('displayName') for g in data.get('value', []) 
                     if 'displayName' in g]
            
            logger.debug(f"Fetched {len(groups)} groups from Azure AD")
            return groups
            
        except Exception as e:
            logger.error(f"Error fetching Azure groups: {e}")
            return []
    
    def _fetch_okta_groups(self, access_token: str) -> List[str]:
        """Fetch groups from Okta API"""
        # Okta usually includes groups in the token claims
        # This is a placeholder for custom implementation if needed
        return []
    
    def map_groups_to_roles(self, groups: List[str]) -> List[str]:
        """
        Map OIDC groups to Airflow roles
        
        Args:
            groups: List of group names from OIDC provider
            
        Returns:
            List of Airflow role names
        """
        roles = set()
        
        for group in groups:
            if group in self.role_mapping:
                mapped_roles = self.role_mapping[group]
                roles.update(mapped_roles)
                logger.debug(f"Mapped group '{group}' to roles: {mapped_roles}")
        
        role_list = list(roles)
        
        if not role_list:
            logger.warning("No groups matched role mapping, using default role")
        
        return role_list
    
    def extract_username(self, userinfo: Dict[str, Any]) -> str:
        """Extract username from userinfo"""
        username_claim = self.provider_config.get('username_claim', 'preferred_username')
        
        username = userinfo.get(username_claim)
        if not username:
            username = userinfo.get('preferred_username') or \
                      userinfo.get('email') or \
                      userinfo.get('sub') or \
                      f"user_{hash(str(userinfo))}"
        
        return username
    
    def build_user_dict(self, userinfo: Dict[str, Any], roles: List[str]) -> Dict[str, Any]:
        """
        Build complete user dictionary for Airflow
        
        Args:
            userinfo: User info from OIDC provider
            roles: Mapped Airflow roles
            
        Returns:
            User dictionary
        """
        return {
            'username': self.extract_username(userinfo),
            'email': userinfo.get('email', ''),
            'first_name': userinfo.get('given_name', userinfo.get('first_name', '')),
            'last_name': userinfo.get('family_name', userinfo.get('last_name', '')),
            'role_keys': roles
        }

# ============================================================================
# CUSTOM SECURITY MANAGER
# ============================================================================

class CustomOIDCSecurityManager(FabAirflowSecurityManagerOverride):
    """
    Complete custom security manager for OIDC authentication
    Integrates all components: config loader, token handler, user info extractor
    """
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        
        # Initialize components
        self.config_manager = OIDCConfigurationManager()
        self.provider_config = self.config_manager.get_active_provider()
        
        if not self.provider_config:
            logger.error("No active OIDC provider configured!")
            return
        
        self.token_handler = OIDCTokenHandler(self.provider_config)
        
        roles_config = self.config_manager.get_roles_config()
        self.role_mapping = roles_config.get('role_mapping', {})
        
        self.user_extractor = OIDCUserInfoExtractor(
            self.provider_config,
            self.role_mapping
        )
        
        self.settings = self.config_manager.get_settings_config()
        
        logger.info("CustomOIDCSecurityManager initialized successfully")
        logger.info(f"Provider: {self.provider_config.get('name')}")
        logger.info(f"Role mappings: {len(self.role_mapping)}")
    
    def oauth_user_info(self, provider: str, response: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract user information from OAuth response
        
        This is the main entry point called by Flask-AppBuilder during OAuth login
        
        Args:
            provider: OAuth provider name
            response: OAuth response containing tokens
            
        Returns:
            User info dictionary for Airflow
        """
        if not response:
            logger.error("No OAuth response provided")
            return {}
        
        access_token = response.get('access_token')
        if not access_token:
            logger.error("No access token in OAuth response")
            return {}
        
        try:
            # Validate token if enabled
            if self.settings.get('advanced', {}).get('jwt_validation_enabled', False):
                is_valid, claims = self.token_handler.validate_token(access_token)
                if not is_valid:
                    logger.error("Token validation failed")
                    return {}
            
            # Fetch user info
            userinfo = self.user_extractor.fetch_userinfo(access_token)
            if not userinfo:
                logger.error("Failed to fetch user info")
                return {}
            
            # Extract groups
            groups = self.user_extractor.extract_groups(userinfo, access_token)
            
            # Map groups to roles
            roles = self.user_extractor.map_groups_to_roles(groups)
            
            # If no roles, assign default
            if not roles:
                default_role = self.settings.get('authentication', {}).get(
                    'auth_user_registration_role', 'Viewer'
                )
                roles = [default_role]
            
            # Build user dictionary
            user_dict = self.user_extractor.build_user_dict(userinfo, roles)
            
            logger.info(f"User authenticated: {user_dict['username']} with roles: {roles}")
            return user_dict
            
        except Exception as e:
            logger.error(f"Error in oauth_user_info: {e}", exc_info=True)
            return {}

# ============================================================================
# CUSTOM OAUTH VIEW
# ============================================================================

class CustomOAuthView(AuthOAuthView):
    """Custom OAuth view with enhanced logout"""
    
    @expose('/logout/')
    def logout(self):
        """Enhanced logout with OIDC provider logout"""
        try:
            config_manager = OIDCConfigurationManager()
            provider_config = config_manager.get_active_provider()
            
            logout_user()
            session.clear()
            
            if provider_config and provider_config.get('logout_url'):
                logout_url = provider_config['logout_url']
                post_logout_redirect = request.url_root
                
                full_logout_url = f"{logout_url}?post_logout_redirect_uri={post_logout_redirect}"
                logger.info(f"Redirecting to OIDC logout: {full_logout_url}")
                return redirect(full_logout_url)
                
        except Exception as e:
            logger.error(f"Error during logout: {e}")
        
        return redirect(self.appbuilder.get_url_for_index)

# ============================================================================
# CONFIGURATION VALIDATION UTILITY
# ============================================================================

def validate_oidc_configuration() -> bool:
    """
    Validate OIDC configuration
    
    Returns:
        True if configuration is valid
    """
    print("="*70)
    print("OIDC Configuration Validation")
    print("="*70)
    
    config_manager = OIDCConfigurationManager()
    is_valid, errors = config_manager.validate_configuration()
    
    if is_valid:
        print("✓ Configuration is valid!")
        provider = config_manager.get_active_provider()
        if provider:
            print(f"\nActive Provider: {provider.get('name')}")
            print(f"Client ID: {provider.get('client_id', 'NOT SET')[:20]}...")
            print(f"Issuer: {provider.get('issuer', 'NOT SET')}")
    else:
        print("✗ Configuration has errors:")
        for i, error in enumerate(errors, 1):
            print(f"  {i}. {error}")
    
    print("="*70)
    return is_valid

# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == '__main__':
    validate_oidc_configuration()