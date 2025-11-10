# I'm importing pytest and the Flask app to test it
import pytest
from app import app

# I'm using a pytest fixture to create a test client for the Flask app
@pytest.fixture
def client():
    app.config['WTF_CSRF_ENABLED'] = False # i'm disabling CSRF for testing purposes only
    app.config['TESTING'] = True  # Enables test mode
    with app.test_client() as client:
        yield client

# --- BASIC TEST 1(unit test): Check homepage loads correctly ---
def test_homepage_loads(client):
    response = client.get('/')
    assert response.status_code == 200  # 200 means OK
    assert b"Secure Health Application" in response.data  # Page should contain the title

# --- INTEGRATION TEST: I'm checking that login works and the dashboard loads properly ---
def test_login_and_dashboard(client):
    # I'm sending a POST request with a test user's correct credentials
    response = client.post('/login', data={
        'username': 'student',
        'password': 'password123'
    }, follow_redirects=True)

    # If login is successful, the word 'Dashboard' should appear on the redirected page
    assert b'Dashboard' in response.data

    # I'm now checking that the dashboard (a protected route) is accessible after login
    dash = client.get('/dashboard')
    assert dash.status_code == 200    # 200 = OK (page loaded successfully)
    assert b'Stroke Dataset Dashboard' in dash.data  # Dashboard content is displayed correctly