"""
Custom OIDC Authentication Manager for Airflow 2.10+

This implementation provides OAuth2/OIDC authentication for Airflow
supporting providers like Okta, Auth0, Keycloak, Azure AD, Google, etc.
"""

import logging
from datetime import timedelta
from typing import Any, Optional, Dict
from urllib.parse import urlencode

from flask import redirect, request, session, url_for, flash
from flask_login import login_user, logout_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import gen_salt

from airflow.configuration import conf
from airflow.providers.fab.auth_manager.fab_auth_manager import FabAuthManager
from airflow.www.security import AirflowSecurityManager

log = logging.getLogger(__name__)


class OIDCSecurityManager(AirflowSecurityManager):
    """
    Custom security manager for OIDC authentication
    """
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        
        # Initialize OAuth client
        self.oauth = OAuth(appbuilder.app)
        self._register_oidc_provider()
        
        log.info("OIDCSecurityManager initialized")
    
    def _register_oidc_provider(self):
        """Register OIDC provider with OAuth client"""
        
        # Get OIDC configuration
        oidc_config = {
            'client_id': conf.get('oidc', 'client_id'),
            'client_secret': conf.get('oidc', 'client_secret'),
            'server_metadata_url': conf.get('oidc', 'server_metadata_url', fallback=None),
            'authorize_url': conf.get('oidc', 'authorize_url', fallback=None),
            'access_token_url': conf.get('oidc', 'access_token_url', fallback=None),
            'userinfo_url': conf.get('oidc', 'userinfo_url', fallback=None),
            'jwks_uri': conf.get('oidc', 'jwks_uri', fallback=None),
            'api_base_url': conf.get('oidc', 'api_base_url', fallback=''),
        }
        
        # Build client_kwargs
        client_kwargs = {
            'scope': conf.get('oidc', 'scope', fallback='openid email profile'),
        }
        
        # Register OAuth client with custom redirect_uri handling
        if oidc_config['server_metadata_url']:
            # Use discovery endpoint
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=oidc_config['client_id'],
                client_secret=oidc_config['client_secret'],
                server_metadata_url=oidc_config['server_metadata_url'],
                api_base_url=oidc_config['api_base_url'],
                client_kwargs=client_kwargs,
                # Override default redirect_uri
                redirect_uri=conf.get('oidc', 'redirect_uri', fallback=None),
            )
        else:
            # Manual configuration
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=oidc_config['client_id'],
                client_secret=oidc_config['client_secret'],
                authorize_url=oidc_config['authorize_url'],
                access_token_url=oidc_config['access_token_url'],
                api_base_url=oidc_config['api_base_url'],
                userinfo_endpoint=oidc_config['userinfo_url'],
                jwks_uri=oidc_config['jwks_uri'],
                client_kwargs=client_kwargs,
                redirect_uri=conf.get('oidc', 'redirect_uri', fallback=None),
            )
        
        # Configure OAuth provider info for FAB
        self.oauth_providers = [{
            'name': 'oidc',
            'icon': 'fa-openid',
            'token_key': 'access_token',
            'remote_app': self.oidc_client
        }]
        
        log.info("OIDC provider registered successfully")
    
    def oauth_user_info(self, provider, response):
        """
        Extract user info from OAuth provider response
        Called by Flask-AppBuilder during OAuth flow
        """
        if provider == 'oidc':
            try:
                # Get user info from response
                if 'userinfo' in response:
                    return response['userinfo']
                
                # Parse ID token if available
                id_token = response.get('id_token')
                if id_token:
                    user_info = self.oidc_client.parse_id_token(response)
                    return user_info
                
                # Fetch from userinfo endpoint
                user_info = self.oidc_client.userinfo(token=response)
                return user_info
                
            except Exception as e:
                log.error(f"Error getting OAuth user info: {e}", exc_info=True)
                return None
        
        return None
    
    def auth_user_oauth(self, userinfo):
        """
        Authenticate user via OAuth/OIDC
        Called by Flask-AppBuilder after oauth_user_info
        
        Args:
            userinfo: User information from OIDC provider
        
        Returns:
            User object or None
        """
        try:
            # Extract user information
            email = userinfo.get('email')
            if not email:
                log.error("Email not provided by OIDC provider")
                return None
            
            username = userinfo.get('preferred_username') or email.split('@')[0]
            first_name = userinfo.get('given_name', '')
            last_name = userinfo.get('family_name', '')
            
            # Find or create user
            user = self.find_user(email=email)
            
            if not user:
                log.info(f"Creating new user: {email}")
                
                # Get default role
                default_role_name = conf.get('oidc', 'default_role', fallback='Viewer')
                
                # Map OIDC groups/roles to Airflow roles
                airflow_role = self._map_oidc_roles_to_airflow(userinfo, default_role_name)
                
                # Create user
                user = self.add_user(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    role=self.find_role(airflow_role),
                    password=gen_salt(48)  # Random password (not used)
                )
                
                if user:
                    log.info(f"User created successfully: {email}")
                else:
                    log.error(f"Failed to create user: {email}")
                
            else:
                log.info(f"User found: {email}")
                
                # Update user information
                user.first_name = first_name
                user.last_name = last_name
                
                # Update roles based on current OIDC groups
                self._update_user_roles(user, userinfo)
                
                self.update_user(user)
            
            # Store user info in session for later use
            session['oidc_userinfo'] = userinfo
            
            return user
        
        except Exception as e:
            log.error(f"Error authenticating OAuth user: {e}", exc_info=True)
            return None
    
    def _map_oidc_roles_to_airflow(self, user_info: Dict, default_role: str) -> str:
        """
        Map OIDC groups/roles to Airflow roles
        
        Args:
            user_info: User information from OIDC provider
            default_role: Default Airflow role
        
        Returns:
            Airflow role name
        """
        try:
            # Get role mapping configuration (JSON string)
            role_mapping_str = conf.get('oidc', 'role_mapping', fallback='{}')
            
            # Parse role mapping safely
            import json
            role_mapping = json.loads(role_mapping_str)
            
            # Get user's groups from OIDC token
            groups = user_info.get('groups', [])
            roles = user_info.get('roles', [])
            
            # Check role mapping
            for oidc_group in groups + roles:
                if oidc_group in role_mapping:
                    mapped_role = role_mapping[oidc_group]
                    log.info(f"Mapped OIDC group '{oidc_group}' to Airflow role '{mapped_role}'")
                    return mapped_role
            
            # Return default role
            log.info(f"No role mapping found, using default role: {default_role}")
            return default_role
        
        except Exception as e:
            log.error(f"Error mapping roles: {e}", exc_info=True)
            return default_role
    
    def _update_user_roles(self, user: Any, user_info: Dict):
        """Update user roles based on OIDC groups"""
        try:
            # Get current role from OIDC mapping
            default_role = conf.get('oidc', 'default_role', fallback='Viewer')
            new_role_name = self._map_oidc_roles_to_airflow(user_info, default_role)
            
            # Update role if changed
            new_role = self.find_role(new_role_name)
            if new_role and user.roles:
                current_role = user.roles[0] if user.roles else None
                if current_role != new_role:
                    user.roles = [new_role]
                    log.info(f"Updated user {user.email} role to {new_role_name}")
        
        except Exception as e:
            log.error(f"Error updating user roles: {e}", exc_info=True)


class OIDCAuthManager(FabAuthManager):
    """
    OIDC Authentication Manager for Airflow 2.10+
    
    Supports multiple OIDC providers:
    - Okta, Auth0, Keycloak, Azure AD, Google, etc.
    """
    
    def __init__(self, appbuilder):
        """Initialize OIDC auth manager"""
        super().__init__(appbuilder)
        
        # Configure session
        self._configure_session()
        
        log.info("OIDCAuthManager initialized successfully")
    
    def _configure_session(self):
        """Configure Flask session with proper settings"""
        app = self.appbuilder.app
        
        app.config.update({
            'SESSION_PERMANENT': True,
            'PERMANENT_SESSION_LIFETIME': timedelta(
                minutes=conf.getint('webserver', 'session_lifetime_minutes', fallback=43200)
            ),
            'SESSION_COOKIE_NAME': 'airflow_session',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SECURE': conf.getboolean('webserver', 'cookie_secure', fallback=False),
            'SESSION_COOKIE_SAMESITE': conf.get('webserver', 'cookie_samesite', fallback='Lax'),
        })
        
        log.info("Session configuration completed")
    
    def get_security_manager_override_class(self):
        """
        Return custom security manager class
        This is the key method for Airflow 2.10+
        """
        return OIDCSecurityManager
