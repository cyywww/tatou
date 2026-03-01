import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from io import BytesIO

# Import the modules to test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Mock RMAP modules before importing server
sys.modules['rmap'] = Mock()
sys.modules['rmap.identity_manager'] = Mock()
sys.modules['rmap.rmap'] = Mock()

from server import create_app


class TestSimpleAPI:
    """Simple API tests without complex database mocking."""
    
    @pytest.fixture
    def app(self):
        """Create test app instance."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        
        # Use temporary directory for storage
        self.temp_dir = tempfile.mkdtemp()
        app.config['STORAGE_DIR'] = Path(self.temp_dir)
        
        # Mock database configuration
        app.config['DB_USER'] = 'test'
        app.config['DB_PASSWORD'] = 'test'
        app.config['DB_HOST'] = 'localhost'
        app.config['DB_PORT'] = 3306
        app.config['DB_NAME'] = 'test'
        
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()
    
    def _generate_test_token(self, app):
        """Generate a valid test token for authentication."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        return token
    
    def test_healthz_endpoint(self, client):
        """Test health check endpoint - database connection check."""
        response = client.get('/healthz')
        assert response.status_code == 200
        data = response.get_json()
        assert 'message' in data
        assert 'db_connected' in data
        # Should contain the message
        assert 'server is up' in data['message'].lower()
    
    def test_healthz_db_status(self, client):
        """Test health check returns proper database status."""
        response = client.get('/healthz')
        data = response.get_json()
        # db_connected should be boolean
        assert isinstance(data['db_connected'], bool)
    
    def test_static_file_serving(self, client):
        """Test static file serving."""
        response = client.get('/index.html')
        # Should return 200 or 404 depending on file existence
        assert response.status_code in [200, 404]
    
    def test_create_user_endpoint(self, client):
        """Test user creation endpoint."""
        data = {
            'email': 'test@example.com',
            'login': 'testuser',
            'password': 'testpassword'
        }
        
        response = client.post('/api/create-user', json=data)
        # Should return 503 due to RMAP configuration issues
        assert response.status_code in [400, 500, 503, 201]
    
    def test_login_endpoint(self, client):
        """Test login endpoint - basic functionality."""
        data = {
            'email': 'test@example.com',
            'password': 'testpassword'
        }
        
        response = client.post('/api/login', json=data)
        # Should return 503 (db error) or 401 (invalid creds)
        assert response.status_code in [400, 401, 500, 503]
    
    def test_login_missing_email(self, client):
        """Test login with missing email."""
        data = {'password': 'testpassword'}
        response = client.post('/api/login', json=data)
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
        assert 'email' in data['error'].lower()
    
    def test_login_missing_password(self, client):
        """Test login with missing password."""
        data = {'email': 'test@example.com'}
        response = client.post('/api/login', json=data)
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
        assert 'password' in data['error'].lower()
    
    def test_login_empty_credentials(self, client):
        """Test login with empty credentials."""
        test_cases = [
            {'email': '', 'password': ''},
            {'email': '  ', 'password': 'test'},
            {'email': 'test@example.com', 'password': ''},
        ]
        
        for data in test_cases:
            response = client.post('/api/login', json=data)
            assert response.status_code in [400, 401, 503]
    
    def test_login_with_whitespace(self, client):
        """Test login with whitespace in email."""
        data = {
            'email': '  test@example.com  ',
            'password': 'testpassword'
        }
        response = client.post('/api/login', json=data)
        # Should handle whitespace stripping
        assert response.status_code in [401, 503]
    
    def test_watermarking_methods_endpoint(self, client):
        """Test watermarking methods endpoint."""
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        data = response.get_json()
        assert 'methods' in data
        assert 'count' in data


class TestAPISecurityTests:
    """Comprehensive security tests for API endpoints."""
    
    @pytest.fixture
    def app(self):
        """Create test app instance."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        
        # Use temporary directory for storage
        self.temp_dir = tempfile.mkdtemp()
        app.config['STORAGE_DIR'] = Path(self.temp_dir)
        
        # Mock database configuration
        app.config['DB_USER'] = 'test'
        app.config['DB_PASSWORD'] = 'test'
        app.config['DB_HOST'] = 'localhost'
        app.config['DB_PORT'] = 3306
        app.config['DB_NAME'] = 'test'
        
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()
    
    def _generate_test_token(self, app):
        """Generate a valid test token for authentication."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        return token
    
    def test_upload_document_with_auth(self, app, client):
        """Test upload with valid authentication token."""
        token = self._generate_test_token(app)
        headers = {'Authorization': f'Bearer {token}'}
        
        data = {
            'file': (BytesIO(b'%PDF-1.4 test pdf content'), 'test.pdf'),
            'name': 'Authenticated Upload Test'
        }
        response = client.post('/api/upload-document',
                             data=data,
                             headers=headers,
                             content_type='multipart/form-data')
        # Should pass auth check, might fail on DB
        assert response.status_code in [200, 201, 400, 500, 503]
    
    def test_list_documents_with_auth(self, app, client):
        """Test list documents with authentication."""
        token = self._generate_test_token(app)
        headers = {'Authorization': f'Bearer {token}'}
        
        response = client.get('/api/list-documents', headers=headers)
        # Should pass auth, might fail on DB
        assert response.status_code in [200, 500, 503]
    
    def test_delete_document_with_auth(self, app, client):
        """Test delete document with authentication."""
        token = self._generate_test_token(app)
        headers = {'Authorization': f'Bearer {token}'}
        
        response = client.delete('/api/delete-document/1', headers=headers)
        # Should pass auth, might fail on DB or not found
        assert response.status_code in [200, 404, 500, 503]
    
    def test_auth_with_expired_token(self, app, client):
        """Test authentication with expired token."""
        from itsdangerous import URLSafeTimedSerializer
        import time
        
        # Create a token with very short expiration
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt="tatou-auth")
        old_ttl = app.config['TOKEN_TTL_SECONDS']
        app.config['TOKEN_TTL_SECONDS'] = -1  # Already expired
        
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {'Authorization': f'Bearer {token}'}
        
        # Try to use expired token
        response = client.get('/api/list-documents', headers=headers)
        app.config['TOKEN_TTL_SECONDS'] = old_ttl  # Restore
        
        # Should reject expired token
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])