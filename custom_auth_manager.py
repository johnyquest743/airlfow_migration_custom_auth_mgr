"""
Custom Authentication Manager for Airflow 2.10+
Implements the BaseAuthManager interface with proper session handling
"""

from datetime import timedelta
from typing import Any, Optional
from flask import session, Flask
from flask_login import login_user, logout_user
from airflow.auth.managers.base_auth_manager import BaseAuthManager
from airflow.providers.fab.auth_manager.fab_auth_manager import FabAuthManager
from airflow.www.security import AirflowSecurityManager
import logging

log = logging.getLogger(__name__)


class CustomAuthManager(FabAuthManager):
    """
    Custom authentication manager extending FabAuthManager
    
    This approach extends FabAuthManager to maintain compatibility
    while adding custom authentication logic.
    """
    
    def __init__(self, appbuilder):
        """Initialize custom auth manager"""
        super().__init__(appbuilder)
        self._configure_session()
        log.info("CustomAuthManager initialized")
    
    def _configure_session(self):
        """Configure Flask session with proper settings"""
        app = self.appbuilder.app
        
        # Critical session configuration
        app.config.update({
            # Session type - store in database
            'SESSION_TYPE': 'sqlalchemy',
            
            # Use Airflow's database
            'SESSION_SQLALCHEMY': app.extensions.get('sqlalchemy', {}).db if 'sqlalchemy' in app.extensions else None,
            
            # Make sessions permanent with explicit lifetime
            'SESSION_PERMANENT': True,
            'PERMANENT_SESSION_LIFETIME': timedelta(days=30),
            
            # Security settings
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_PREFIX': 'airflow_session:',
            'SESSION_COOKIE_NAME': 'airflow_session',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SECURE': False,  # Set True for HTTPS
            'SESSION_COOKIE_SAMESITE': 'Lax',
            
            # Refresh session expiry on each request
            'SESSION_REFRESH_EACH_REQUEST': True,
        })
        
        # Initialize Flask-Session if not already done
        if 'session' not in app.extensions:
            from flask_session import Session
            Session(app)
        
        log.info("Session configuration completed")
    
    def get_user_name(self) -> str:
        """Get the username of the logged-in user"""
        user = self.get_user()
        return user.username if user else "anonymous"
    
    def is_logged_in(self) -> bool:
        """Check if user is authenticated"""
        return self.get_user() is not None
    
    def is_authorized_dag(
        self,
        method: str,
        access_entity: Optional[Any] = None,
        user: Optional[Any] = None,
    ) -> bool:
        """
        Check if user is authorized to access DAG
        
        Override this method for custom DAG-level authorization
        """
        # Custom authorization logic here
        # For example, check user roles or external authorization service
        
        # Default to parent implementation
        return super().is_authorized_dag(method, access_entity, user)
    
    def is_authorized_view(
        self,
        access_view: Optional[str] = None,
        user: Optional[Any] = None,
    ) -> bool:
        """
        Check if user is authorized to access view
        
        Override this method for custom view-level authorization
        """
        # Custom authorization logic here
        
        # Default to parent implementation
        return super().is_authorized_view(access_view, user)


class CustomSecurityManager(AirflowSecurityManager):
    """
    Custom security manager for authentication logic
    
    This is used in conjunction with CustomAuthManager for
    authentication flows (login, logout, etc.)
    """
    
    def authenticate_user(self, username: str, password: str):
        """
        Custom user authentication logic
        
        Override this method to implement custom authentication
        (LDAP, OAuth, custom database, etc.)
        """
        log.info(f"Authenticating user: {username}")
        
        # Example: Custom authentication logic
        # Option 1: Use default FAB authentication
        user = super().auth_user_db(username, password)
        
        # Option 2: Custom authentication (e.g., external API)
        # user = self._authenticate_external_api(username, password)
        
        # Option 3: LDAP authentication
        # user = self._authenticate_ldap(username, password)
        
        if user:
            log.info(f"User {username} authenticated successfully")
            
            # Set session as permanent to ensure expiry is set
            session.permanent = True
            session.modified = True
            
            return user
        else:
            log.warning(f"Authentication failed for user: {username}")
            return None
    
    def _authenticate_external_api(self, username: str, password: str):
        """
        Example: Authenticate against external API
        """
        try:
            # Your custom authentication logic
            # response = requests.post('https://your-auth-api.com/login', ...)
            
            # If authentication successful, get or create user in Airflow
            # user = self.find_user(username=username)
            # if not user:
            #     user = self.add_user(
            #         username=username,
            #         first_name="First",
            #         last_name="Last",
            #         email=f"{username}@example.com",
            #         role=self.find_role("Viewer")
            #     )
            # return user
            
            pass
        except Exception as e:
            log.error(f"External authentication error: {e}")
            return None
    
    def _authenticate_ldap(self, username: str, password: str):
        """
        Example: Authenticate against LDAP
        """
        try:
            # Your LDAP authentication logic
            # import ldap
            # conn = ldap.initialize('ldap://your-ldap-server')
            # conn.simple_bind_s(f'uid={username},ou=users,dc=example,dc=com', password)
            
            # If successful, get or create user
            # user = self.find_user(username=username)
            # if not user:
            #     user = self.add_user(...)
            # return user
            
            pass
        except Exception as e:
            log.error(f"LDAP authentication error: {e}")
            return None
    
    def before_request(self):
        """
        Called before each request
        
        Use this to validate session, refresh tokens, etc.
        """
        # Ensure session has proper expiry
        if self.is_user_authenticated() and session.get('_permanent'):
            session.modified = True
        
        # Call parent implementation
        super().before_request()


# Configuration for airflow.cfg
"""
[core]
auth_manager = your_package.custom_auth_manager.CustomAuthManager

[webserver]
# Session configuration (these complement the Python config above)
secret_key = your-very-secure-secret-key-here-change-this
session_backend = database
session_lifetime_minutes = 43200  # 30 days

# Cookie settings
cookie_secure = False  # Set True for HTTPS
cookie_samesite = Lax

# Security
expose_config = False
x_frame_enabled = True
enable_csrf = True

[database]
sql_alchemy_conn = postgresql+psycopg2://user:pass@localhost/airflow
"""


# Alternative: Standalone Custom Auth Manager (not extending FabAuthManager)
class StandaloneCustomAuthManager(BaseAuthManager):
    """
    Completely custom authentication manager
    
    Implement this if you want full control without FAB dependencies
    Note: This requires implementing ALL abstract methods from BaseAuthManager
    """
    
    def __init__(self, appbuilder):
        self.appbuilder = appbuilder
        self.app = appbuilder.app
        self._configure_session()
        self._setup_security()
    
    def _configure_session(self):
        """Configure session management"""
        self.app.config.update({
            'SESSION_TYPE': 'sqlalchemy',
            'SESSION_PERMANENT': True,
            'PERMANENT_SESSION_LIFETIME': timedelta(days=30),
            'SESSION_USE_SIGNER': True,
            'SESSION_REFRESH_EACH_REQUEST': True,
        })
        
        from flask_session import Session
        Session(self.app)
    
    def _setup_security(self):
        """Setup security components"""
        # Initialize your custom security manager
        # self.security_manager = YourCustomSecurityManager(self.appbuilder)
        pass
    
    def get_user_name(self) -> str:
        """Return the username associated with the context"""
        # Implement your logic
        raise NotImplementedError()
    
    def get_user(self) -> Any:
        """Return the user associated with the context"""
        # Implement your logic
        raise NotImplementedError()
    
    def is_logged_in(self) -> bool:
        """Return whether the user is logged in"""
        # Implement your logic
        raise NotImplementedError()
    
    def is_authorized_dag(
        self,
        method: str,
        access_entity: Optional[Any] = None,
        user: Optional[Any] = None,
    ) -> bool:
        """Check if user is authorized for DAG operation"""
        # Implement your authorization logic
        raise NotImplementedError()
    
    def is_authorized_view(
        self,
        access_view: Optional[str] = None,
        user: Optional[Any] = None,
    ) -> bool:
        """Check if user is authorized for view"""
        # Implement your authorization logic
        raise NotImplementedError()
    
    # ... implement all other abstract methods from BaseAuthManager
