"""
OIDC Authentication Manager with Custom Redirect URI for Airflow 2.10+

This version supports custom redirect URIs instead of the default /oauth-authorized/oidc
"""

import logging
from datetime import timedelta
from typing import Any, Dict
from urllib.parse import urlencode, urlparse

from flask import redirect, request, session, url_for, flash, Blueprint
from flask_login import login_user, current_user
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc6749 import OAuth2Token
from werkzeug.security import gen_salt

from airflow.configuration import conf
from airflow.providers.fab.auth_manager.fab_auth_manager import FabAuthManager
from airflow.www.security import AirflowSecurityManager
from airflow.www.fab_security.views import AuthOAuthView

log = logging.getLogger(__name__)


class CustomAuthOAuthView(AuthOAuthView):
    """
    Custom OAuth view with auto-redirect and custom callback URL support
    """
    
    @property
    def auto_redirect(self):
        """Enable auto-redirect to OIDC provider"""
        return conf.getboolean('oidc', 'auto_redirect', fallback=True)
    
    def login(self):
        """
        Override login to auto-redirect to OIDC provider
        """
        # If user is already authenticated, redirect to index
        if current_user and current_user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        
        # Check if auto-redirect is enabled
        if self.auto_redirect:
            log.info("Auto-redirecting to OIDC provider")
            return redirect(url_for('AuthOAuthView.oauth_authorize', provider='oidc'))
        
        # Otherwise, show default login page with button
        return super().login()
    
    def oauth_authorize(self, provider):
        """
        Override OAuth authorize to use custom redirect URI
        """
        log.info(f"OAuth authorize for provider: {provider}")
        
        if provider not in self.appbuilder.sm.oauth_remotes:
            flash(f"Provider {provider} not found", "warning")
            return redirect(self.appbuilder.get_url_for_login)
        
        try:
            # Get custom redirect URI from config
            custom_redirect_uri = conf.get('oidc', 'custom_redirect_uri', fallback=None)
            
            if custom_redirect_uri:
                log.info(f"Using custom redirect URI: {custom_redirect_uri}")
                redirect_uri = custom_redirect_uri
            else:
                # Use default FAB callback
                redirect_uri = url_for(
                    'AuthOAuthView.oauth_authorized',
                    provider=provider,
                    _external=True
                )
                log.info(f"Using default redirect URI: {redirect_uri}")
            
            # Store state for CSRF protection
            state = gen_salt(48)
            session[f'oauth_state_{provider}'] = state
            
            # Store provider and next URL
            session['oauth_provider'] = provider
            next_url = request.args.get('next') or self.appbuilder.get_url_for_index
            session['next_url'] = next_url
            
            # Get OAuth remote app
            remote = self.appbuilder.sm.oauth_remotes[provider]
            
            # Generate nonce for OIDC
            nonce = gen_salt(48)
            session[f'oauth_nonce_{provider}'] = nonce
            
            # Authorize redirect with custom URI
            return remote.authorize_redirect(
                redirect_uri=redirect_uri,
                state=state,
                nonce=nonce
            )
            
        except Exception as e:
            log.error(f"Error in oauth_authorize: {e}", exc_info=True)
            flash(f"Authentication error: {str(e)}", "error")
            return redirect(self.appbuilder.get_url_for_login)
    
    def oauth_authorized(self, provider):
        """
        Override OAuth callback handler to support custom redirect URI
        This handles the default /oauth-authorized/<provider> route
        """
        return self._handle_oauth_callback(provider)
    
    def _handle_oauth_callback(self, provider):
        """
        Common callback handler for both default and custom redirect URIs
        """
        log.info(f"OAuth callback received for provider: {provider}")
        
        try:
            # Verify state for CSRF protection
            state = request.args.get('state')
            stored_state = session.get(f'oauth_state_{provider}')
            
            if not state or state != stored_state:
                log.error("State mismatch - possible CSRF attack")
                flash("Authentication failed: Invalid state", "error")
                return redirect(self.appbuilder.get_url_for_login)
            
            # Get OAuth remote app
            remote = self.appbuilder.sm.oauth_remotes[provider]
            
            # Exchange authorization code for token
            token = remote.authorize_access_token()
            
            if not token:
                log.error("Failed to obtain access token")
                flash("Authentication failed: Could not obtain token", "error")
                return redirect(self.appbuilder.get_url_for_login)
            
            # Get user info
            nonce = session.get(f'oauth_nonce_{provider}')
            user_info = self.appbuilder.sm.oauth_user_info(provider, token)
            
            if not user_info:
                log.error("Failed to get user info")
                flash("Authentication failed: Could not get user info", "error")
                return redirect(self.appbuilder.get_url_for_login)
            
            log.info(f"User info retrieved: {user_info.get('email')}")
            
            # Authenticate user
            user = self.appbuilder.sm.auth_user_oauth(user_info)
            
            if not user:
                log.error("User authentication failed")
                flash("Authentication failed", "error")
                return redirect(self.appbuilder.get_url_for_login)
            
            # Login user
            login_user(user, remember=False)
            session.permanent = True
            
            # Store tokens
            session['oauth_token'] = token
            session['oauth_user_info'] = user_info
            
            log.info(f"User {user.username} logged in successfully")
            
            # Get next URL and redirect
            next_url = session.pop('next_url', self.appbuilder.get_url_for_index)
            
            # Cleanup
            session.pop(f'oauth_state_{provider}', None)
            session.pop(f'oauth_nonce_{provider}', None)
            session.pop('oauth_provider', None)
            
            return redirect(next_url)
            
        except Exception as e:
            log.error(f"Error in OAuth callback: {e}", exc_info=True)
            flash(f"Authentication error: {str(e)}", "error")
            return redirect(self.appbuilder.get_url_for_login)


class OIDCSecurityManager(AirflowSecurityManager):
    """
    Custom security manager for OIDC authentication with custom redirect URI support
    """
    
    # Use custom OAuth view
    authoauthview = CustomAuthOAuthView
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        
        # Initialize OAuth client
        self.oauth = OAuth(appbuilder.app)
        self._register_oidc_provider()
        
        # Register custom callback route if configured
        self._register_custom_callback_route()
        
        log.info("OIDCSecurityManager initialized with custom redirect URI support")
    
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
        
        # Register OAuth client
        if oidc_config['server_metadata_url']:
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=oidc_config['client_id'],
                client_secret=oidc_config['client_secret'],
                server_metadata_url=oidc_config['server_metadata_url'],
                api_base_url=oidc_config['api_base_url'],
                client_kwargs=client_kwargs,
            )
        else:
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
            )
        
        # Store OAuth remote for access
        self.oauth_remotes = {
            'oidc': self.oidc_client
        }
        
        # Configure OAuth provider info for FAB
        self.oauth_providers = [{
            'name': 'oidc',
            'icon': 'fa-openid',
            'token_key': 'access_token',
            'remote_app': self.oidc_client
        }]
        
        log.info("OIDC provider registered successfully")
    
    def _register_custom_callback_route(self):
        """Register custom callback route if configured"""
        
        custom_redirect_uri = conf.get('oidc', 'custom_redirect_uri', fallback=None)
        
        if not custom_redirect_uri:
            log.info("No custom redirect URI configured, using default")
            return
        
        # Parse the custom redirect URI to get the path
        parsed = urlparse(custom_redirect_uri)
        custom_path = parsed.path
        
        log.info(f"Registering custom callback route: {custom_path}")
        
        # Create blueprint for custom callback
        custom_callback_bp = Blueprint(
            'oidc_custom_callback',
            __name__,
            url_prefix=''
        )
        
        @custom_callback_bp.route(custom_path)
        def custom_oidc_callback():
            """Handle custom OIDC callback"""
            log.info(f"Custom callback route triggered: {custom_path}")
            
            # Use the same handler as the default OAuth callback
            auth_view = self.appbuilder.security_manager_class.authoauthview(self.appbuilder)
            return auth_view._handle_oauth_callback('oidc')
        
        # Register blueprint
        self.appbuilder.app.register_blueprint(custom_callback_bp)
        log.info(f"Custom callback route registered: {custom_path}")
    
    def oauth_user_info(self, provider, response):
        """
        Extract user info from OAuth provider response
        """
        if provider == 'oidc':
            try:
                # Get nonce from session
                nonce = session.get(f'oauth_nonce_{provider}')
                
                # Get user info from response
                if 'userinfo' in response:
                    return response['userinfo']
                
                # Parse ID token if available
                id_token = response.get('id_token')
                if id_token:
                    user_info = self.oidc_client.parse_id_token(response, nonce=nonce)
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
                
                default_role_name = conf.get('oidc', 'default_role', fallback='Viewer')
                airflow_role = self._map_oidc_roles_to_airflow(userinfo, default_role_name)
                
                user = self.add_user(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    role=self.find_role(airflow_role),
                    password=gen_salt(48)
                )
                
                if user:
                    log.info(f"User created successfully: {email}")
                else:
                    log.error(f"Failed to create user: {email}")
                
            else:
                log.info(f"User found: {email}")
                user.first_name = first_name
                user.last_name = last_name
                self._update_user_roles(user, userinfo)
                self.update_user(user)
            
            session['oidc_userinfo'] = userinfo
            return user
        
        except Exception as e:
            log.error(f"Error authenticating OAuth user: {e}", exc_info=True)
            return None
    
    def _map_oidc_roles_to_airflow(self, user_info: Dict, default_role: str) -> str:
        """Map OIDC groups/roles to Airflow roles"""
        try:
            role_mapping_str = conf.get('oidc', 'role_mapping', fallback='{}')
            
            import json
            role_mapping = json.loads(role_mapping_str)
            
            groups = user_info.get('groups', [])
            roles = user_info.get('roles', [])
            
            for oidc_group in groups + roles:
                if oidc_group in role_mapping:
                    mapped_role = role_mapping[oidc_group]
                    log.info(f"Mapped OIDC group '{oidc_group}' to Airflow role '{mapped_role}'")
                    return mapped_role
            
            log.info(f"No role mapping found, using default role: {default_role}")
            return default_role
        
        except Exception as e:
            log.error(f"Error mapping roles: {e}", exc_info=True)
            return default_role
    
    def _update_user_roles(self, user: Any, user_info: Dict):
        """Update user roles based on OIDC groups"""
        try:
            default_role = conf.get('oidc', 'default_role', fallback='Viewer')
            new_role_name = self._map_oidc_roles_to_airflow(user_info, default_role)
            
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
    OIDC Authentication Manager for Airflow 2.10+ with custom redirect URI support
    """
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self._configure_session()
        log.info("OIDCAuthManager initialized with custom redirect URI support")
    
    def _configure_session(self):
        """Configure Flask session"""
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
        """Return custom security manager class"""
        return OIDCSecurityManager
