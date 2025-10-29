#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
IDA OIDC Authentication Test Script
For Airflow 2.10 - Python 3.12
===============================================================================

This script tests IDA OIDC integration without starting Airflow.
It validates configuration and tests connectivity to IDA endpoints.

Usage:
    python test_ida_auth.py
    python test_ida_auth.py --verbose
    python test_ida_auth.py --test-endpoints

===============================================================================
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, List
from datetime import datetime

# Third-party imports
try:
    import requests
    from requests.exceptions import RequestException, Timeout, HTTPError
except ImportError:
    print("Error: requests library not found")
    print("Install with: pip install requests")
    sys.exit(1)

try:
    from authlib.jose import jwt
except ImportError:
    print("Warning: authlib not found - JWT validation will be skipped")
    print("Install with: pip install authlib")
    jwt = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# IDA Configuration Tester
# ============================================================================

class IDAAuthenticationTester:
    """Test IDA OIDC authentication configuration and connectivity"""
    
    def __init__(self, airflow_home: str = None, verbose: bool = False):
        self.airflow_home = Path(airflow_home or os.getenv('AIRFLOW_HOME', os.path.expanduser('~/airflow')))
        self.config_dir = self.airflow_home / 'config'
        self.verbose = verbose
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        logger.info(f"Testing IDA configuration in: {self.config_dir}")
    
    def load_json(self, filename: str) -> Dict[str, Any]:
        """Load JSON configuration file"""
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            self.errors.append(f"File not found: {file_path}")
            return {}
        
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON in {filename}: {e}")
            return {}
        except Exception as e:
            self.errors.append(f"Error reading {filename}: {e}")
            return {}
    
    def test_file_structure(self) -> bool:
        """Test if all required files exist"""
        print("\n" + "="*70)
        print("Test 1: File Structure")
        print("="*70)
        
        required_files = {
            'oidc_client.json': 'IDA client configuration',
            'oidc_roles.json': 'Role mapping configuration',
            'oidc_settings.json': 'Additional settings'
        }
        
        all_exist = True
        for filename, description in required_files.items():
            file_path = self.config_dir / filename
            if file_path.exists():
                print(f"✓ {filename}: {description}")
                
                # Check if readable
                try:
                    with open(file_path) as f:
                        data = json.load(f)
                    print(f"  - Valid JSON with {len(data)} top-level keys")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    all_exist = False
            else:
                print(f"✗ Missing: {filename}")
                all_exist = False
        
        return all_exist
    
    def test_ida_configuration(self) -> Tuple[bool, Dict[str, Any]]:
        """Test IDA provider configuration"""
        print("\n" + "="*70)
        print("Test 2: IDA Provider Configuration")
        print("="*70)
        
        client_config = self.load_json('oidc_client.json')
        if not client_config:
            print("✗ Failed to load client configuration")
            return False, {}
        
        providers = client_config.get('providers', [])
        if not providers:
            print("✗ No providers configured")
            return False, {}
        
        # Find IDA provider
        ida_provider = None
        for provider in providers:
            if provider.get('type') == 'custom_ida':
                ida_provider = provider
                break
        
        if not ida_provider:
            print("✗ IDA provider not found")
            print("  Expected provider with type='custom_ida'")
            return False, {}
        
        print(f"✓ IDA provider found: {ida_provider.get('name', 'ida')}")
        
        # Validate required fields
        required_fields = [
            ('client_id', 'Client ID'),
            ('client_secret', 'Client Secret'),
            ('issuer', 'Issuer URL'),
        ]
        
        all_valid = True
        for field, description in required_fields:
            value = ida_provider.get(field)
            if value and not value.startswith('REPLACE'):
                print(f"✓ {description}: {value[:30]}..." if len(str(value)) > 30 else f"✓ {description}: {value}")
            else:
                print(f"✗ {description}: NOT SET or placeholder")
                all_valid = False
        
        # Check endpoints
        endpoints = [
            ('authorize_url', 'Authorization URL'),
            ('access_token_url', 'Token URL'),
            ('userinfo_url', 'UserInfo URL'),
        ]
        
        for field, description in endpoints:
            value = ida_provider.get(field)
            if value:
                print(f"✓ {description}: {value}")
            else:
                print(f"⚠ {description}: Not configured")
                self.warnings.append(f"{description} not configured")
        
        return all_valid, ida_provider
    
    def test_metadata_endpoint(self, ida_config: Dict[str, Any]) -> bool:
        """Test IDA metadata/discovery endpoint"""
        print("\n" + "="*70)
        print("Test 3: IDA Metadata Endpoint")
        print("="*70)
        
        metadata_url = ida_config.get('server_metadata_url')
        if not metadata_url:
            print("⚠ Metadata URL not configured, skipping")
            return True
        
        print(f"Testing: {metadata_url}")
        
        try:
            verify_ssl = ida_config.get('verify_ssl', True)
            ca_bundle = ida_config.get('ca_bundle_path')
            
            if ca_bundle and Path(ca_bundle).exists():
                verify_ssl = ca_bundle
                print(f"Using CA bundle: {ca_bundle}")
            
            timeout = ida_config.get('timeout_seconds', 10)
            
            response = requests.get(
                metadata_url,
                timeout=timeout,
                verify=verify_ssl
            )
            
            response.raise_for_status()
            metadata = response.json()
            
            print(f"✓ Metadata endpoint accessible")
            print(f"  Issuer: {metadata.get('issuer')}")
            print(f"  Authorization: {metadata.get('authorization_endpoint')}")
            print(f"  Token: {metadata.get('token_endpoint')}")
            print(f"  UserInfo: {metadata.get('userinfo_endpoint')}")
            print(f"  JWKS: {metadata.get('jwks_uri')}")
            
            # Verify scopes supported
            scopes_supported = metadata.get('scopes_supported', [])
            requested_scopes = ida_config.get('scope', '').split()
            
            print(f"\n  Requested scopes: {requested_scopes}")
            print(f"  Supported scopes: {scopes_supported}")
            
            for scope in requested_scopes:
                if scope not in scopes_supported:
                    print(f"  ⚠ Scope '{scope}' may not be supported")
                    self.warnings.append(f"Scope '{scope}' not in supported scopes")
            
            return True
            
        except Timeout:
            print(f"✗ Timeout connecting to metadata endpoint")
            self.errors.append("Metadata endpoint timeout")
            return False
        except HTTPError as e:
            print(f"✗ HTTP Error {e.response.status_code}: {e.response.text[:100]}")
            self.errors.append(f"Metadata endpoint HTTP error: {e.response.status_code}")
            return False
        except RequestException as e:
            print(f"✗ Connection error: {e}")
            self.errors.append(f"Cannot connect to metadata endpoint: {e}")
            return False
        except json.JSONDecodeError:
            print(f"✗ Invalid JSON response")
            self.errors.append("Metadata endpoint returned invalid JSON")
            return False
    
    def test_role_mapping(self) -> bool:
        """Test role mapping configuration"""
        print("\n" + "="*70)
        print("Test 4: Role Mapping Configuration")
        print("="*70)
        
        roles_config = self.load_json('oidc_roles.json')
        if not roles_config:
            print("✗ Failed to load role mapping")
            return False
        
        role_mapping = roles_config.get('role_mapping', {})
        if not role_mapping:
            print("✗ No role mappings configured")
            return False
        
        print(f"✓ {len(role_mapping)} role mappings configured:")
        
        airflow_roles = ['Admin', 'Op', 'User', 'Viewer']
        role_usage = {role: [] for role in airflow_roles}
        
        for ida_group, airflow_roles_list in list(role_mapping.items())[:10]:  # Show first 10
            print(f"  {ida_group} → {airflow_roles_list}")
            for role in airflow_roles_list:
                if role in role_usage:
                    role_usage[role].append(ida_group)
        
        if len(role_mapping) > 10:
            print(f"  ... and {len(role_mapping) - 10} more")
        
        # Check coverage
        print(f"\nAirflow Role Coverage:")
        for role, groups in role_usage.items():
            if groups:
                print(f"  ✓ {role}: {len(groups)} IDA group(s)")
            else:
                print(f"  ⚠ {role}: No IDA groups mapped")
                self.warnings.append(f"No groups mapped to '{role}' role")
        
        return True
    
    def test_network_connectivity(self, ida_config: Dict[str, Any]) -> bool:
        """Test network connectivity to IDA"""
        print("\n" + "="*70)
        print("Test 5: Network Connectivity")
        print("="*70)
        
        issuer = ida_config.get('issuer')
        if not issuer:
            print("⚠ Issuer URL not configured")
            return True
        
        print(f"Testing connectivity to: {issuer}")
        
        try:
            verify_ssl = ida_config.get('verify_ssl', True)
            ca_bundle = ida_config.get('ca_bundle_path')
            
            if ca_bundle and Path(ca_bundle).exists():
                verify_ssl = ca_bundle
            
            # Test basic connectivity
            response = requests.get(
                issuer,
                timeout=10,
                verify=verify_ssl,
                allow_redirects=True
            )
            
            print(f"✓ Connected to IDA (Status: {response.status_code})")
            
            # Check if proxy is configured
            if ida_config.get('proxy_enabled'):
                proxy_url = ida_config.get('proxy_url')
                print(f"  Proxy configured: {proxy_url}")
            
            return True
            
        except Timeout:
            print(f"✗ Timeout connecting to IDA")
            print(f"  Check firewall rules and proxy configuration")
            self.errors.append("Cannot connect to IDA - timeout")
            return False
        except RequestException as e:
            print(f"✗ Connection error: {e}")
            self.errors.append(f"Network connectivity issue: {e}")
            return False
    
    def test_ssl_certificates(self, ida_config: Dict[str, Any]) -> bool:
        """Test SSL certificate configuration"""
        print("\n" + "="*70)
        print("Test 6: SSL/TLS Configuration")
        print("="*70)
        
        verify_ssl = ida_config.get('verify_ssl', True)
        ca_bundle = ida_config.get('ca_bundle_path')
        
        if not verify_ssl:
            print("⚠ SSL verification is DISABLED")
            print("  This should only be used in development!")
            self.warnings.append("SSL verification disabled")
            return True
        
        print(f"✓ SSL verification enabled")
        
        if ca_bundle:
            ca_path = Path(ca_bundle)
            if ca_path.exists():
                print(f"✓ Custom CA bundle configured: {ca_bundle}")
                # Check if readable
                try:
                    with open(ca_path, 'r') as f:
                        content = f.read(100)
                        if 'BEGIN CERTIFICATE' in content:
                            print(f"  ✓ CA bundle appears valid")
                        else:
                            print(f"  ⚠ CA bundle format unclear")
                except Exception as e:
                    print(f"  ✗ Cannot read CA bundle: {e}")
                    self.errors.append(f"CA bundle not readable: {e}")
                    return False
            else:
                print(f"✗ CA bundle not found: {ca_bundle}")
                self.errors.append(f"CA bundle file missing: {ca_bundle}")
                return False
        else:
            print(f"  Using system CA certificates")
        
        return True
    
    def test_redirect_uris(self, client_config: Dict[str, Any]) -> bool:
        """Test redirect URI configuration"""
        print("\n" + "="*70)
        print("Test 7: Redirect URI Configuration")
        print("="*70)
        
        redirect_uris = client_config.get('redirect_uris', [])
        
        if not redirect_uris:
            print("⚠ No redirect URIs configured")
            self.warnings.append("No redirect URIs configured")
            return True
        
        print(f"✓ {len(redirect_uris)} redirect URI(s) configured:")
        
        for uri in redirect_uris:
            print(f"  - {uri}")
            
            # Validate URI format
            if not uri.startswith(('http://', 'https://')):
                print(f"    ⚠ URI should include protocol (http:// or https://)")
            
            if '/oauth-authorized/ida' not in uri and '/auth/oauth-authorized/ida' not in uri:
                print(f"    ⚠ URI should end with /oauth-authorized/ida (Airflow 2.x) or /auth/oauth-authorized/ida (Airflow 3.x)")
        
        return True
    
    def run_all_tests(self, test_endpoints: bool = False) -> bool:
        """Run all tests"""
        print("\n" + "="*70)
        print("IDA OIDC Authentication Test Suite")
        print(f"Airflow Home: {self.airflow_home}")
        print(f"Config Directory: {self.config_dir}")
        print(f"Timestamp: {datetime.now()}")
        print("="*70)
        
        # Run tests
        test_results = []
        
        # Test 1: File structure
        test_results.append(("File Structure", self.test_file_structure()))
        
        if not test_results[-1][1]:
            print("\n✗ Cannot proceed without configuration files")
            return False
        
        # Test 2: IDA configuration
        valid, ida_config = self.test_ida_configuration()
        test_results.append(("IDA Configuration", valid))
        
        if not valid:
            print("\n✗ Cannot proceed without valid IDA configuration")
            return False
        
        # Test 3: Metadata endpoint (if requested)
        if test_endpoints:
            test_results.append(("Metadata Endpoint", self.test_metadata_endpoint(ida_config)))
        
        # Test 4: Role mapping
        test_results.append(("Role Mapping", self.test_role_mapping()))
        
        # Test 5: Network connectivity (if requested)
        if test_endpoints:
            test_results.append(("Network Connectivity", self.test_network_connectivity(ida_config)))
        
        # Test 6: SSL certificates
        test_results.append(("SSL Configuration", self.test_ssl_certificates(ida_config)))
        
        # Test 7: Redirect URIs
        client_config = self.load_json('oidc_client.json')
        test_results.append(("Redirect URIs", self.test_redirect_uris(client_config)))
        
        # Print summary
        print("\n" + "="*70)
        print("Test Summary")
        print("="*70)
        
        passed = sum(1 for _, result in test_results if result)
        total = len(test_results)
        
        for test_name, result in test_results:
            symbol = "✓" if result else "✗"
            print(f"{symbol} {test_name}")
        
        print(f"\nPassed: {passed}/{total}")
        
        if self.warnings:
            print(f"\n⚠ Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        if self.errors:
            print(f"\n✗ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"  - {error}")
        
        print("="*70)
        
        if passed == total and not self.errors:
            print("✓ All tests passed! IDA configuration looks good.")
            print("\nNext steps:")
            print("1. Register redirect URIs with IDA team")
            print("2. Verify IDA groups are assigned to users")
            print("3. Start Airflow: airflow webserver")
            print("4. Test login with IDA credentials")
            return True
        else:
            print("✗ Some tests failed. Please fix the errors above.")
            return False

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Test IDA OIDC authentication configuration for Airflow'
    )
    parser.add_argument(
        '--airflow-home',
        help='Airflow home directory (default: $AIRFLOW_HOME or ~/airflow)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--test-endpoints',
        action='store_true',
        help='Test connectivity to IDA endpoints (requires network access)'
    )
    
    args = parser.parse_args()
    
    tester = IDAAuthenticationTester(
        airflow_home=args.airflow_home,
        verbose=args.verbose
    )
    
    success = tester.run_all_tests(test_endpoints=args.test_endpoints)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()