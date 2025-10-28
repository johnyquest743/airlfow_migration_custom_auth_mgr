"""
Custom OIDC Authentication Manager for Airflow 2.10+

This implementation provides OAuth2/OIDC authentication for Airflow
supporting providers like Okta, Auth0, Keycloak, Azure AD, Google, etc.
"""

import logging
import secrets
from datetime import timedelta
from typing import Any, Optional, Dict
from urllib.parse import urlencode, quote

from flask import (
    redirect, request, session, url_for, flash, 
    make_response, Blueprint
)
from flask_login import login_user, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
from werkzeug.security import gen_salt

from airflow.configuration import conf
from airflow.providers.fab.auth_manager.fab_auth_manager import FabAuthManager
from airflow.www.security import AirflowSecurityManager
from airflow.exceptions import AirflowException

log = logging.getLogger(__name__)


class OIDCAuthManager(FabAuthManager):
    """
    OIDC Authentication Manager for Airflow 2.10+
    
    Supports multiple OIDC providers:
    - Okta
    - Auth0
    - Keycloak
    - Azure AD
    - Google
    - Generic OIDC providers
    """
    
    def __init__(self, appbuilder):
        """Initialize OIDC auth manager"""
        super().__init__(appbuilder)
        
        # Initialize OAuth client
        self.oauth = OAuth(self.appbuilder.app)
        
        # Configure session
        self._configure_session()
        
        # Register OIDC provider
        self._register_oidc_provider()
        
        # Register routes
        self._register_routes()
        
        log.info("OIDCAuthManager initialized successfully")
    
    def _configure_session(self):
        """Configure Flask session with proper settings"""
        app = self.appbuilder.app
        
        app.config.update({
            # Session configuration
            'SESSION_TYPE': 'sqlalchemy',
            'SESSION_SQLALCHEMY': app.extensions.get('sqlalchemy', {}).db,
            'SESSION_PERMANENT': True,
            'PERMANENT_SESSION_LIFETIME': timedelta(
                minutes=conf.getint('webserver', 'session_lifetime_minutes', fallback=43200)
            ),
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_PREFIX': 'airflow_oidc_session:',
            'SESSION_COOKIE_NAME': 'airflow_session',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SECURE': conf.getboolean('webserver', 'cookie_secure', fallback=False),
            'SESSION_COOKIE_SAMESITE': conf.get('webserver', 'cookie_samesite', fallback='Lax'),
            'SESSION_REFRESH_EACH_REQUEST': True,
        })
        
        # Initialize Flask-Session
        if 'session' not in app.extensions:
            from flask_session import Session
            Session(app)
        
        log.info("Session configuration completed")
    
    def _register_oidc_provider(self):
        """Register OIDC provider with OAuth client"""
        
        # Get OIDC configuration from airflow.cfg or environment
        oidc_config = {
            'client_id': conf.get('oidc', 'client_id'),
            'client_secret': conf.get('oidc', 'client_secret'),
            'server_metadata_url': conf.get('oidc', 'server_metadata_url', fallback=None),
            'authorize_url': conf.get('oidc', 'authorize_url', fallback=None),
            'access_token_url': conf.get('oidc', 'access_token_url', fallback=None),
            'userinfo_url': conf.get('oidc', 'userinfo_url', fallback=None),
            'jwks_uri': conf.get('oidc', 'jwks_uri', fallback=None),
            'client_kwargs': {
                'scope': conf.get('oidc', 'scope', fallback='openid email profile'),
            }
        }
        
        # Register OAuth client
        if oidc_config['server_metadata_url']:
            # Use discovery endpoint
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=oidc_config['client_id'],
                client_secret=oidc_config['client_secret'],
                server_metadata_url=oidc_config['server_metadata_url'],
                client_kwargs=oidc_config['client_kwargs']
            )
        else:
            # Manual configuration
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=oidc_config['client_id'],
                client_secret=oidc_config['client_secret'],
                authorize_url=oidc_config['authorize_url'],
                access_token_url=oidc_config['access_token_url'],
                userinfo_endpoint=oidc_config['userinfo_url'],
                jwks_uri=oidc_config['jwks_uri'],
                client_kwargs=oidc_config['client_kwargs']
            )
        
        log.info("OIDC provider registered successfully")
    
    def _register_routes(self):
        """Register OIDC authentication routes"""
        
        # Create blueprint for OIDC routes
        oidc_bp = Blueprint('oidc', __name__, url_prefix='/oidc')
        
        @oidc_bp.route('/login')
        def login():
            """Initiate OIDC login flow"""
            try:
                # Generate state for CSRF protection
                state = gen_salt(48)
                session['oidc_state'] = state
                
                # Generate nonce for replay protection
                nonce = gen_salt(48)
                session['oidc_nonce'] = nonce
                
                # Store original URL to redirect after login
                session['next_url'] = request.args.get('next') or url_for('Airflow.index')
                
                # Build redirect URI
                redirect_uri = url_for('oidc.callback', _external=True)
                
                log.info(f"Initiating OIDC login, redirect_uri: {redirect_uri}")
                
                # Redirect to OIDC provider
                return self.oidc_client.authorize_redirect(
                    redirect_uri=redirect_uri,
                    state=state,
                    nonce=nonce
                )
            
            except Exception as e:
                log.error(f"Error initiating OIDC login: {e}", exc_info=True)
                flash(f"Authentication error: {str(e)}", 'error')
                return redirect(url_for('Airflow.index'))
        
        @oidc_bp.route('/callback')
        def callback():
            """Handle OIDC callback"""
            try:
                # Verify state (CSRF protection)
                state = request.args.get('state')
                if not state or state != session.get('oidc_state'):
                    log.error("State mismatch - possible CSRF attack")
                    flash('Authentication failed: Invalid state', 'error')
                    return redirect(url_for('Airflow.index'))
                
                # Exchange authorization code for tokens
                token = self.oidc_client.authorize_access_token()
                
                if not token:
                    log.error("Failed to obtain access token")
                    flash('Authentication failed: Could not obtain token', 'error')
                    return redirect(url_for('Airflow.index'))
                
                # Parse ID token
                nonce = session.get('oidc_nonce')
                id_token = token.get('id_token')
                
                if id_token:
                    # Verify and parse ID token
                    user_info = self.oidc_client.parse_id_token(token, nonce=nonce)
                else:
                    # Fetch user info from userinfo endpoint
                    user_info = self.oidc_client.userinfo(token=token)
                
                log.info(f"User info retrieved: {user_info.get('email')}")
                
                # Process user and create/update in Airflow
                user = self._process_oidc_user(user_info, token)
                
                if not user:
                    log.error("Failed to process user")
                    flash('Authentication failed: Could not create user', 'error')
                    return redirect(url_for('Airflow.index'))
                
                # Login user
                session.permanent = True
                login_user(user, remember=False)
                
                # Store tokens in session for API calls
                session['oidc_token'] = token
                session['user_info'] = user_info
                session.modified = True
                
                log.info(f"User {user.username} logged in successfully via OIDC")
                
                # Redirect to original URL
                next_url = session.pop('next_url', url_for('Airflow.index'))
                
                # Cleanup
                session.pop('oidc_state', None)
                session.pop('oidc_nonce', None)
                
                return redirect(next_url)
            
            except Exception as e:
                log.error(f"Error in OIDC callback: {e}", exc_info=True)
                flash(f"Authentication error: {str(e)}", 'error')
                return redirect(url_for('Airflow.index'))
        
        @oidc_bp.route('/logout')
        def logout():
            """Handle OIDC logout"""
            try:
                # Get OIDC logout URL if available
                end_session_endpoint = conf.get('oidc', 'end_session_endpoint', fallback=None)
                
                # Logout from Airflow
                logout_user()
                
                # Clear session
                session.clear()
                
                log.info("User logged out successfully")
                
                # Redirect to OIDC provider logout if configured
                if end_session_endpoint:
                    post_logout_redirect_uri = url_for('Airflow.index', _external=True)
                    logout_url = f"{end_session_endpoint}?{urlencode({'post_logout_redirect_uri': post_logout_redirect_uri})}"
                    return redirect(logout_url)
                
                # Otherwise redirect to Airflow index
                flash('You have been logged out', 'info')
                return redirect(url_for('Airflow.index'))
            
            except Exception as e:
                log.error(f"Error during logout: {e}", exc_info=True)
                return redirect(url_for('Airflow.index'))
        
        # Register blueprint
        self.appbuilder.app.register_blueprint(oidc_bp)
        log.info("OIDC routes registered successfully")
    
    def _process_oidc_user(self, user_info: Dict, token: Dict) -> Any:
        """
        Process OIDC user info and create/update user in Airflow
        
        Args:
            user_info: User information from OIDC provider
            token: OAuth token information
        
        Returns:
            User object or None
        """
        try:
            # Extract user information
            email = user_info.get('email')
            username = user_info.get('preferred_username') or email.split('@')[0]
            first_name = user_info.get('given_name', '')
            last_name = user_info.get('family_name', '')
            
            if not email:
                log.error("Email not provided by OIDC provider")
                return None
            
            # Get security manager
            security_manager = self.appbuilder.sm
            
            # Find or create user
            user = security_manager.find_user(email=email)
            
            if not user:
                log.info(f"Creating new user: {email}")
                
                # Get role mapping configuration
                default_role_name = conf.get('oidc', 'default_role', fallback='Viewer')
                
                # Map OIDC groups/roles to Airflow roles
                airflow_role = self._map_oidc_roles_to_airflow(user_info, default_role_name)
                
                # Create user
                user = security_manager.add_user(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    role=security_manager.find_role(airflow_role),
                    password=gen_salt(48)  # Random password (not used)
                )
                
                if not user:
                    log.error(f"Failed to create user: {email}")
                    return None
                
                log.info(f"User created successfully: {email}")
            else:
                log.info(f"User found: {email}")
                
                # Update user information
                user.first_name = first_name
                user.last_name = last_name
                
                # Update roles based on current OIDC groups
                self._update_user_roles(user, user_info)
                
                security_manager.update_user(user)
            
            return user
        
        except Exception as e:
            log.error(f"Error processing OIDC user: {e}", exc_info=True)
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
            # Get role mapping configuration
            role_mapping_str = conf.get('oidc', 'role_mapping', fallback='{}')
            role_mapping = eval(role_mapping_str)  # Be careful with eval in production
            
            # Get user's groups from OIDC token
            groups = user_info.get('groups', [])
            roles = user_info.get('roles', [])
            
            # Check role mapping
            for oidc_group in groups + roles:
                if oidc_group in role_mapping:
                    return role_mapping[oidc_group]
            
            # Return default role
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
            
            # Get security manager
            security_manager = self.appbuilder.sm
            
            # Update role if changed
            new_role = security_manager.find_role(new_role_name)
            if new_role and user.roles:
                current_role = user.roles[0] if user.roles else None
                if current_role != new_role:
                    user.roles = [new_role]
                    log.info(f"Updated user {user.email} role to {new_role_name}")
        
        except Exception as e:
            log.error(f"Error updating user roles: {e}", exc_info=True)


class OIDCSecurityManager(AirflowSecurityManager):
    """
    Custom security manager for OIDC authentication
    Handles authentication views and user management
    """
    
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        log.info("OIDCSecurityManager initialized")
    
    def oauth_user_info(self, provider, response):
        """
        Get user info from OAuth provider response
        This is called by Flask-AppBuilder for OAuth flows
        """
        if provider == 'oidc':
            return response
        return None
