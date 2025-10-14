import pytest
import json
from app import app

@pytest.fixture
def client():
    """Create a test client for the app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """Test the home page loads successfully"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'DevSecOps Dashboard' in response.data

def test_health_endpoint(client):
    """Test the health check endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'version' in data

def test_echo_endpoint_success(client):
    """Test the echo endpoint with valid data"""
    test_message = "Hello, DevSecOps!"
    response = client.post('/api/echo', json={'message': test_message})
    assert response.status_code == 200
    data = response.get_json()
    assert data['echo'] == test_message
    assert data['length'] == len(test_message)

def test_echo_endpoint_no_data(client):
    """Test the echo endpoint with empty message"""
    response = client.post('/api/echo', json={'message': ''})
    assert response.status_code == 200
    data = response.get_json()
    assert data['echo'] == ''
    assert data['length'] == 0

def test_echo_endpoint_too_long(client):
    """Test the echo endpoint with message too long"""
    test_message = "x" * 1001  # Exceeds 1000 character limit
    response = client.post('/api/echo', json={'message': test_message})
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data

def test_echo_endpoint_invalid_content_type(client):
    """Test the echo endpoint with invalid content type"""
    response = client.post('/api/echo', data='not json', content_type='text/plain')
    assert response.status_code in [400, 415]
