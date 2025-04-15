import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import secrets
import base64
import hashlib
import time
import datetime

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure session
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
# Using cookies instead of filesystem for serverless compatibility 
# app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True  # Set to True for cookie-based sessions
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('VERCEL_ENV') == 'production'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minute

# For production environments like Vercel, ensure HTTPS is used for callbacks
if os.getenv('VERCEL_ENV') == 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
    app.config['PREFERRED_URL_SCHEME'] = 'https'
else:
    # For local development only - remove in production.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# X OAuth 2.0 Settings
X_CLIENT_ID = os.getenv('X_CLIENT_ID')
X_CLIENT_SECRET = os.getenv('X_CLIENT_SECRET')

# Get the appropriate redirect URI based on environment
if os.getenv('X_REDIRECT_URI'):
    # Custom configured redirect URI
    X_REDIRECT_URI = os.getenv('X_REDIRECT_URI')
else:
    # Local development
    X_REDIRECT_URI = "http://127.0.0.1:5000/callback"

# X OAuth2 endpoints
AUTHORIZATION_BASE_URL = 'https://x.com/i/oauth2/authorize'
TOKEN_URL = 'https://api.x.com/2/oauth2/token'
USERINFO_URL = 'https://api.x.com/2/users/me'

# Scopes needed for the application
SCOPES = [
    'tweet.read',
    'users.read',
    'tweet.write',
    # 'offline.access',
    'ads.access.read',
    # 'ads.access.write',
    # 'ads.settings.read',
    # 'ads.settings.write',
    # 'ads.campaign.read',
    # 'ads.campaign.write',
    # 'ads.creatives.read',
    # 'ads.creatives.write',
    # 'ads.audiences.read',
    # 'ads.audiences.write',
    # ====
    # 'ads.spend.read',
    # 'ads.engagement.read',
    # 'ads.3pm.read',
    # 'ads.mact.read',
    # 'ads.mact.write',

]

# Helper function to generate a code verifier for PKCE
def generate_code_verifier(length=64):
    """Generate a code verifier string of specified length for PKCE"""
    return secrets.token_urlsafe(length)

# Helper function to generate a code challenge from a code verifier
def generate_code_challenge(code_verifier):
    """Generate a code challenge (S256) from a code verifier"""
    sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')

# Add Jinja2 filters
@app.template_filter('strftime')
def _jinja2_filter_strftime(timestamp, fmt=None):
    """Convert a Unix timestamp to a formatted datetime string"""
    if fmt is None:
        fmt = '%Y-%m-%d %H:%M:%S'
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime(fmt)

@app.route('/')
def index():
    """Main page that displays login option"""
    return render_template('index.html')


@app.route('/login')
def login():
    """Redirect to X authorization page with PKCE"""
    # Generate code verifier and challenge for PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store the verifier in session for later use in callback
    session['code_verifier'] = code_verifier
    
    # Create a combined state that includes the verifier
    # This is a backup in case sessions don't work
    combined_state = f"{secrets.token_urlsafe(16)}:{code_verifier}"
    
    # Create OAuth session
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    # Create the authorization URL with PKCE
    authorization_url, state = x_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge=code_challenge,
        code_challenge_method='S256',
        state=combined_state  # Use our combined state
    )
    
    # Debug prints
    print(f"Code Verifier: {code_verifier}")
    print(f"Code Challenge: {code_challenge}")
    print(f"Authorization URL: {authorization_url}")
    print(f"Combined State: {combined_state}")
    print(f"Redirect URI: {X_REDIRECT_URI}")
    
    # Store the state for later use
    session['oauth_state'] = combined_state
    
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Process the X OAuth 2.0 callback"""
    # Get request params
    request_state = request.args.get('state')
    
    # Try to get state and code verifier from the session
    session_state = session.get('oauth_state')
    code_verifier = session.get('code_verifier')
    
    # Debug prints
    print(f"Callback received")
    print(f"State from request: {request_state}")
    print(f"State from session: {session_state}")
    print(f"Code verifier from session: {code_verifier}")
    print(f"Request URL: {request.url}")
    
    # If session state is missing but request state is present
    if not session_state and request_state:
        # We'll use the state from the request, which should include the code_verifier
        print("Session state missing, using request state")
        session_state = request_state
        
        # Try to extract code_verifier from state
        if ':' in request_state:
            # Our state format is "random:code_verifier"
            state_parts = request_state.split(':', 1)
            if len(state_parts) == 2:
                code_verifier = state_parts[1]
                print(f"Extracted code_verifier from state: {code_verifier}")
    
    # If state or code_verifier is still None, return error
    if not session_state:
        return render_template('error.html', error="State is missing from session. Session may have expired.")
    if not code_verifier:
        return render_template('error.html', error="Code verifier is missing. Session may have expired.")
    
    # Create the OAuth session with state
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        state=session_state
    )
    
    try:
        # Get the full URL for authorization response
        if request.url.startswith('http://') and os.getenv('VERCEL_URL'):
            # Fix for Vercel deployment - transform HTTP to HTTPS
            auth_response_url = request.url.replace('http://', 'https://', 1)
        else:
            auth_response_url = request.url
        
        print(f"Auth response URL: {auth_response_url}")
            
        # Fetch the access token using the authorization code and code verifier
        token = x_session.fetch_token(
            TOKEN_URL,
            client_secret=X_CLIENT_SECRET,
            authorization_response=auth_response_url,
            code_verifier=code_verifier
        )
        
        # Add a timestamp to the token for tracking expiration
        token['timestamp'] = int(time.time())
        
        # Store the token in the session
        session['oauth_token'] = token
        
        # Fetch user information
        user_info = fetch_user_info(token)
        session['user_info'] = user_info
        
        # Redirect to trends page instead of profile
        return redirect(url_for('trends'))
    
    except Exception as e:
        print(f"Error in callback: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', error=str(e))


def fetch_user_info(token):
    """Fetch the user's information from X API"""
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # Include user fields to get more information
    params = {
        'user.fields': 'name,username,profile_image_url,description'
    }
    
    # Make the request to the userinfo endpoint
    response = x_session.get(USERINFO_URL, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        # Handle error
        return {'error': f"Error fetching user info: {response.status_code}"}


def fetch_personalized_trends(token):
    """Fetch the user's personalized trends from X API"""
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # The personalized trends endpoint
    trends_url = 'https://api.twitter.com/2/users/personalized_trends'
    
    try:
        # Make the request to the personalized trends endpoint
        response = x_session.get(trends_url)
        
        print(f"Trends API Response Status: {response.status_code}")
        print(f"Trends API Response Headers: {response.headers}")
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            # User might not have premium subscription
            return {
                'data': [
                    {
                        'error': True,
                        'message': 'Access to personalized trends requires X Premium',
                        'category': 'Subscription Required',
                        'trend_name': 'X Premium Required',
                        'post_count': '',
                        'trending_since': ''
                    }
                ]
            }
        else:
            # Handle other errors
            error_msg = f"Error fetching trends: {response.status_code}"
            try:
                error_data = response.json()
                if 'errors' in error_data and error_data['errors']:
                    error_msg = error_data['errors'][0].get('message', error_msg)
            except:
                pass
                
            return {
                'data': [
                    {
                        'error': True,
                        'message': error_msg,
                        'category': 'Error',
                        'trend_name': 'Could not fetch trends',
                        'post_count': '',
                        'trending_since': ''
                    }
                ]
            }
    except Exception as e:
        print(f"Exception fetching trends: {str(e)}")
        return {
            'data': [
                {
                    'error': True,
                    'message': str(e),
                    'category': 'Error',
                    'trend_name': 'Could not fetch trends',
                    'post_count': '',
                    'trending_since': ''
                }
            ]
        }


@app.route('/profile')
def profile():
    """Display the user's profile information"""
    # Check if the user is logged in
    user_info = session.get('user_info')
    
    if not user_info:
        return redirect(url_for('index'))
    
    return render_template('profile.html', user=user_info['data'])


@app.route('/trends')
def trends():
    """Display the user's personalized trends"""
    # Check if the user is logged in
    token = session.get('oauth_token')
    user_info = session.get('user_info')
    
    if not token or not user_info:
        return redirect(url_for('index'))
    
    # Fetch personalized trends
    trends_data = fetch_personalized_trends(token)
    
    return render_template('trends.html', 
                          trends=trends_data.get('data', []), 
                          user=user_info['data'])


@app.route('/logout')
def logout():
    """Log the user out by clearing the session"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/debug')
def debug_twitter():
    """Debug page for Twitter OAuth configuration"""
    # Create a debug info dictionary
    debug_info = {
        "client_id": X_CLIENT_ID,
        "redirect_uri": X_REDIRECT_URI,
        "scopes": SCOPES,
        "auth_url": AUTHORIZATION_BASE_URL,
        "token_url": TOKEN_URL,
        "vercel_url": os.getenv('VERCEL_URL'),
        "x_redirect_uri_env": os.getenv('X_REDIRECT_URI')
    }
    
    # Generate a test code verifier and challenge (without storing in session)
    test_verifier = generate_code_verifier()
    test_challenge = generate_code_challenge(test_verifier)
    
    # Create a test authorization URL
    test_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    test_auth_url, test_state = test_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge=test_challenge,
        code_challenge_method='S256'
    )
    
    # Add test values to debug info
    debug_info["test_verifier"] = test_verifier
    debug_info["test_challenge"] = test_challenge
    debug_info["test_auth_url"] = test_auth_url
    debug_info["test_state"] = test_state
    
    # Check for common configuration issues
    issues = []
    
    if not X_CLIENT_ID:
        issues.append("X_CLIENT_ID is not set")
    
    if not X_CLIENT_SECRET:
        issues.append("X_CLIENT_SECRET is not set")
    
    if not X_REDIRECT_URI:
        issues.append("X_REDIRECT_URI is not configured")
    
    if X_REDIRECT_URI and "localhost" in X_REDIRECT_URI:
        issues.append("Redirect URI contains 'localhost' which Twitter might not accept. Use 127.0.0.1 instead.")
    
    # For Vercel deployments
    if os.getenv('VERCEL_URL') and not X_REDIRECT_URI.startswith(f"https://{os.getenv('VERCEL_URL')}"):
        issues.append(f"Redirect URI doesn't match Vercel URL. Expected: https://{os.getenv('VERCEL_URL')}/callback")
    
    debug_info["issues"] = issues
    debug_info["session_cookie_secure"] = app.config.get('SESSION_COOKIE_SECURE', False)
    
    return render_template('debug.html', debug=debug_info)


def refresh_oauth_token(token):
    """Refresh the OAuth token using the refresh token"""
    if 'refresh_token' not in token:
        return {'error': 'No refresh token available'}
    
    refresh_token = token['refresh_token']
    
    # Create a new OAuth session
    x_session = OAuth2Session(X_CLIENT_ID)
    
    # Prepare the token data for refresh
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': X_CLIENT_ID
        # 'client_secret': X_CLIENT_SECRET
    }
    headers = {"X-B3-Flags": "1"}

    try:
        # Make a POST request to refresh the token
        response = x_session.post(TOKEN_URL, data=token_data, headers=headers)
        
        print(f"HEADERS: {response.headers}")
        if response.status_code == 200:
            new_token = response.json()
            
            # If the response doesn't include a refresh token, add the old one
            if 'refresh_token' not in new_token and refresh_token:
                new_token['refresh_token'] = refresh_token
                
            # Update the token timestamp
            new_token['timestamp'] = int(time.time())
            
            return new_token
        else:
            error_msg = f"Failed to refresh token: {response.status_code}"
            try:
                error_data = response.json()
                if 'error_description' in error_data:
                    error_msg = error_data['error_description']
                elif 'error' in error_data:
                    error_msg = error_data['error']
            except Exception:
                pass
                
            return {'error': error_msg}
    except Exception as e:
        return {'error': str(e)}


@app.route('/token')
def token_info():
    """Display token information and provide refresh option"""
    # Check if the user is logged in
    token = session.get('oauth_token')
    user_info = session.get('user_info')
    
    if not token or not user_info:
        return redirect(url_for('index'))
    
    # Add a timestamp if not present
    if 'timestamp' not in token:
        token['timestamp'] = int(time.time())
    
    return render_template('token.html', 
                          token=token, 
                          user=user_info['data'],
                          current_time=int(time.time()))


@app.route('/refresh-token')
def refresh_token():
    """Refresh the OAuth token and return the result"""
    # Check if the user is logged in
    token = session.get('oauth_token')
    
    if not token:
        return jsonify({'success': False, 'message': 'No token found in session'})
    
    # Refresh the token
    new_token = refresh_oauth_token(token)
    
    if 'error' in new_token:
        return jsonify({'success': False, 'message': new_token['error']})
    
    # Update the token in the session
    session['oauth_token'] = new_token
    
    return jsonify({
        'success': True, 
        'message': 'Token refreshed successfully',
        'token': new_token
    })


if __name__ == '__main__':
    app.run(debug=True) 