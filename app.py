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
import urllib.parse

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure session for serverless environment
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Use Flask's built-in session management (cookie-based)
# This is more reliable for serverless environments
app.config['SESSION_COOKIE_SECURE'] = os.getenv('VERCEL_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

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
if os.getenv('VERCEL_URL'):
    # Use the current Vercel URL for the callback
    X_REDIRECT_URI = f"https://{os.getenv('VERCEL_URL')}/callback"
elif os.getenv('X_REDIRECT_URI'):
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
    'tweet.write',
    'users.read',
    'users.email',
    'bookmark.read',
    'offline.access',
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


def debug_session():
    """Debug function to log session information"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("SESSION DEBUG INFORMATION:")
    logger.info(f"  Session ID: {session.get('_id', 'N/A')}")
    logger.info(f"  Session Keys: {list(session.keys())}")
    logger.info(f"  Session Modified: {session.modified}")
    logger.info(f"  Session Permanent: {session.permanent}")
    
    # Check for token data
    token = session.get('oauth_token')
    user_info = session.get('user_info')
    
    logger.info(f"  OAuth Token Present: {bool(token)}")
    logger.info(f"  User Info Present: {bool(user_info)}")
    
    if token:
        logger.info(f"  Token Keys: {list(token.keys())}")
        logger.info(f"  Token Type: {token.get('token_type', 'N/A')}")
        logger.info(f"  Token Timestamp: {token.get('timestamp', 'N/A')}")
    
    return {
        'session_id': session.get('_id', 'N/A'),
        'session_keys': list(session.keys()),
        'token_present': bool(token),
        'user_info_present': bool(user_info)
    }

@app.route('/')
def index():
    """Main page that displays login option"""
    return render_template('index.html')


@app.route('/login')
def login():
    """Redirect to X authorization page with PKCE"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("OAUTH2 LOGIN - DETAILED LOGGING")
    logger.info("=" * 80)
    logger.info(f"Login timestamp: {int(time.time())}")
    
    # Generate code verifier and challenge for PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    logger.info("PKCE DETAILS:")
    logger.info(f"  Code Verifier: {code_verifier}")
    logger.info(f"  Code Challenge: {code_challenge}")
    
    # Store the verifier in session for later use in callback
    session['code_verifier'] = code_verifier
    logger.info("  Code verifier stored in session")
    
    # Create a combined state that includes the verifier
    # This is a backup in case sessions don't work
    combined_state = f"{secrets.token_urlsafe(16)}:{code_verifier}"
    logger.info(f"  Combined State: {combined_state}")
    
    # Create OAuth session
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    logger.info("OAUTH2 CONFIGURATION:")
    logger.info(f"  Client ID: {X_CLIENT_ID}")
    logger.info(f"  Redirect URI: {X_REDIRECT_URI}")
    logger.info(f"  Scopes: {SCOPES}")
    logger.info(f"  Authorization Base URL: {AUTHORIZATION_BASE_URL}")
    
    # Create the authorization URL with PKCE
    authorization_url, state = x_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge=code_challenge,
        code_challenge_method='S256',
        state=combined_state  # Use our combined state
    )
    
    logger.info("AUTHORIZATION URL GENERATED:")
    logger.info(f"  Authorization URL: {authorization_url}")
    logger.info(f"  Generated State: {state}")
    
    # Store the state for later use
    session['oauth_state'] = combined_state
    logger.info("  OAuth state stored in session")
    
    # Force session to be saved
    session.modified = True
    
    logger.info("=" * 80)
    logger.info("REDIRECTING TO X AUTHORIZATION")
    logger.info("=" * 80)
    
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Process the X OAuth 2.0 callback"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("OAUTH2 CALLBACK - DETAILED LOGGING")
    logger.info("=" * 80)
    logger.info(f"Callback timestamp: {int(time.time())}")
    
    # Get request params
    request_state = request.args.get('state')
    authorization_code = request.args.get('code')
    error_param = request.args.get('error')
    error_description = request.args.get('error_description')
    
    logger.info("CALLBACK PARAMETERS:")
    logger.info(f"  Authorization Code: {authorization_code[:20] if authorization_code else 'None'}...")
    logger.info(f"  State: {request_state}")
    logger.info(f"  Error: {error_param}")
    logger.info(f"  Error Description: {error_description}")
    
    # Check for OAuth errors first
    if error_param:
        logger.error(f"OAUTH ERROR RECEIVED: {error_param}")
        logger.error(f"Error Description: {error_description}")
        return render_template('error.html', error=f"OAuth Error: {error_param} - {error_description}")
    
    if not authorization_code:
        logger.error("No authorization code received")
        return render_template('error.html', error="No authorization code received from X")
    
    # Try to get state and code verifier from the session
    session_state = session.get('oauth_state')
    code_verifier = session.get('code_verifier')
    
    # Debug prints
    logger.info("CALLBACK REQUEST DETAILS:")
    logger.info(f"  State from request: {request_state}")
    logger.info(f"  State from session: {session_state}")
    logger.info(f"  Code verifier from session: {code_verifier}")
    logger.info(f"  Request URL: {request.url}")
    logger.info(f"  Request method: {request.method}")
    logger.info(f"  User agent: {request.headers.get('User-Agent', 'N/A')}")
    
    # If session state is missing but request state is present
    if not session_state and request_state:
        # We'll use the state from the request, which should include the code_verifier
        logger.warning("Session state missing, using request state")
        session_state = request_state
        
        # Try to extract code_verifier from state
        if ':' in request_state:
            # Our state format is "random:code_verifier"
            state_parts = request_state.split(':', 1)
            if len(state_parts) == 2:
                code_verifier = state_parts[1]
                logger.info(f"Extracted code_verifier from state: {code_verifier[:20]}...")
                logger.info(f"Full code_verifier length: {len(code_verifier)}")
            else:
                logger.error(f"Invalid state format. Expected 'random:code_verifier', got: {request_state}")
        else:
            logger.error(f"No code_verifier found in state: {request_state}")
    elif not session_state and not request_state:
        logger.error("No state found in session or request")
    elif session_state and not code_verifier:
        logger.error("Session state found but no code_verifier in session")
    
    # If state or code_verifier is still None, return error
    if not session_state:
        logger.error("State is missing from session")
        return render_template('error.html', error="State is missing from session. Session may have expired. Please try logging in again.")
    if not code_verifier:
        logger.error("Code verifier is missing from session")
        return render_template('error.html', error="Code verifier is missing. Session may have expired. Please try logging in again.")
    
    # Validate code_verifier format
    if len(code_verifier) < 43:  # PKCE code verifiers should be at least 43 characters
        logger.error(f"Code verifier too short: {len(code_verifier)} characters")
        return render_template('error.html', error="Invalid code verifier format. Please try logging in again.")
    
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
        
        logger.info(f"Auth response URL: {auth_response_url}")
            
        # Fetch the access token using the authorization code and code verifier
        logger.info("Making OAuth2 token request...")
        logger.info(f"  Token URL: {TOKEN_URL}")
        logger.info(f"  Authorization Response URL: {auth_response_url}")
        logger.info(f"  Code Verifier: {code_verifier[:20]}...")
        
        # Get and decode the authorization code for the main request too
        raw_code = request.args.get('code')
        authorization_code = urllib.parse.unquote(raw_code) if raw_code else None
        
        logger.info("MAIN TOKEN REQUEST - AUTHORIZATION CODE:")
        logger.info(f"  Raw Code: {raw_code}")
        logger.info(f"  Decoded Code: {authorization_code}")
        
        token = x_session.fetch_token(
            TOKEN_URL,
            client_secret=X_CLIENT_SECRET,
            authorization_response=auth_response_url,
            code_verifier=code_verifier
        )
        
        # Log the response details from the token request
        logger.info("OAUTH2 TOKEN RESPONSE DETAILS:")
        logger.info(f"  Token Response Keys: {list(token.keys())}")
        logger.info(f"  Access Token (first 20 chars): {token.get('access_token', 'N/A')[:20]}...")
        logger.info(f"  Token Type: {token.get('token_type', 'N/A')}")
        logger.info(f"  Expires In: {token.get('expires_in', 'N/A')}")
        logger.info(f"  Scope: {token.get('scope', 'N/A')}")
        logger.info(f"  Refresh Token Present: {'Yes' if token.get('refresh_token') else 'No'}")
        
        # Note: The requests_oauthlib library doesn't expose response headers directly
        # We'll need to capture them by making the request manually if needed
        
        # Let's also make a manual request to capture full response headers
        logger.info("Making manual OAuth2 token request to capture headers...")
        import requests
        
        # Get and decode the authorization code
        raw_code = request.args.get('code')
        # The code might be URL-encoded, so let's decode it
        import urllib.parse
        authorization_code = urllib.parse.unquote(raw_code) if raw_code else None
        
        logger.info("AUTHORIZATION CODE PROCESSING:")
        logger.info(f"  Raw Code: {raw_code}")
        logger.info(f"  Decoded Code: {authorization_code}")
        
        # Prepare the token request data
        token_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': X_REDIRECT_URI,
            'client_id': X_CLIENT_ID,
            'code_verifier': code_verifier
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {base64.b64encode(f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode()).decode()}'
        }
        
        try:
            manual_response = requests.post(TOKEN_URL, data=token_data, headers=headers)
            logger.info("MANUAL OAUTH2 TOKEN REQUEST RESPONSE HEADERS:")
            logger.info(f"  Status Code: {manual_response.status_code}")
            logger.info(f"  Response URL: {manual_response.url}")
            logger.info("  Full Response Headers:")
            for header_name, header_value in manual_response.headers.items():
                logger.info(f"    {header_name}: {header_value}")
            
            if manual_response.status_code != 200:
                logger.error(f"  Manual request failed with status: {manual_response.status_code}")
                logger.error(f"  Response body: {manual_response.text}")
        except Exception as e:
            logger.error(f"  Manual request failed with exception: {str(e)}")
        
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
        logger.error(f"Error in callback: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return render_template('error.html', error=str(e))


def fetch_user_info(token):
    """Fetch the user's information from X API"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("FETCHING USER INFO - DETAILED LOGGING")
    logger.info("=" * 60)
    
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # Include user fields to get more information
    params = {
        'user.fields': 'name,username,profile_image_url,description'
    }
    
    logger.info("USER INFO REQUEST DETAILS:")
    logger.info(f"  URL: {USERINFO_URL}")
    logger.info(f"  Parameters: {params}")
    logger.info(f"  Access Token (first 20 chars): {token.get('access_token', 'N/A')[:20]}...")
    
    # Make the request to the userinfo endpoint
    logger.info("Making user info request...")
    response = x_session.get(USERINFO_URL, params=params)
    
    logger.info("USER INFO RESPONSE DETAILS:")
    logger.info(f"  Status Code: {response.status_code}")
    logger.info(f"  Response URL: {response.url}")
    logger.info("  Full Response Headers:")
    for header_name, header_value in response.headers.items():
        logger.info(f"    {header_name}: {header_value}")
    
    if response.status_code == 200:
        user_data = response.json()
        logger.info("USER INFO REQUEST SUCCESSFUL")
        logger.info(f"  User Data Keys: {list(user_data.keys())}")
        if 'data' in user_data:
            logger.info(f"  User ID: {user_data['data'].get('id', 'N/A')}")
            logger.info(f"  Username: {user_data['data'].get('username', 'N/A')}")
        return user_data
    else:
        logger.error(f"USER INFO REQUEST FAILED - Status: {response.status_code}")
        try:
            error_data = response.json()
            logger.error(f"  Error Response: {error_data}")
        except:
            logger.error(f"  Raw Response: {response.text}")
        return {'error': f"Error fetching user info: {response.status_code}"}
    
    logger.info("=" * 60)
    logger.info("USER INFO REQUEST COMPLETED")
    logger.info("=" * 60)


def fetch_personalized_trends(token):
    """Fetch the user's personalized trends from X API"""
    import logging
    logger = logging.getLogger(__name__)
    
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # The personalized trends endpoint
    trends_url = 'https://api.twitter.com/2/users/personalized_trends'
    
    try:
        # Make the request to the personalized trends endpoint
        response = x_session.get(trends_url)
        
        logger.info(f"Trends API Response Status: {response.status_code}")
        logger.info(f"Trends API Response Headers: {dict(response.headers)}")
        
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


def fetch_user_bookmarks(token, user_id):
    """Fetch the user's bookmarks from X API"""
    import logging
    
    # Set up detailed logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Log detailed token information
    logger.info("=" * 80)
    logger.info("BOOKMARKS API TEST - DETAILED LOGGING")
    logger.info("=" * 80)
    logger.info(f"Test timestamp: {int(time.time())}")
    logger.info(f"User ID: {user_id}")
    
    # Log complete token details
    logger.info("TOKEN DETAILS:")
    logger.info(f"  Access Token (first 20 chars): {token.get('access_token', 'N/A')[:20]}...")
    logger.info(f"  Token Type: {token.get('token_type', 'N/A')}")
    logger.info(f"  Expires At: {token.get('expires_at', 'N/A')}")
    logger.info(f"  Expires In: {token.get('expires_in', 'N/A')}")
    logger.info(f"  Scope: {token.get('scope', 'N/A')}")
    logger.info(f"  Refresh Token (first 20 chars): {token.get('refresh_token', 'N/A')[:20] if token.get('refresh_token') else 'N/A'}...")
    logger.info(f"  Token Timestamp: {token.get('timestamp', 'N/A')}")
    
    # Calculate token age
    if token.get('timestamp'):
        token_age = int(time.time()) - token['timestamp']
        token_age_minutes = token_age // 60
        token_age_seconds = token_age % 60
        logger.info(f"  Token Age: {token_age_minutes} minutes, {token_age_seconds} seconds")
    
    # Calculate time until expiration
    if token.get('expires_at'):
        current_time = int(time.time())
        expires_at = token['expires_at']
        time_until_expiry = expires_at - current_time
        if time_until_expiry > 0:
            expiry_minutes = time_until_expiry // 60
            expiry_seconds = time_until_expiry % 60
            logger.info(f"  Time Until Expiry: {expiry_minutes} minutes, {expiry_seconds} seconds")
        else:
            logger.info(f"  Token Expired: {abs(time_until_expiry)} seconds ago")
    
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # The bookmarks endpoint
    bookmarks_url = f'https://api.twitter.com/2/users/{user_id}/bookmarks'
    
    # Parameters for the request
    params = {
        'max_results': 100,
        'tweet.fields': 'created_at,author_id,text,public_metrics',
        'user.fields': 'name,username,profile_image_url'
    }
    
    logger.info("API REQUEST DETAILS:")
    logger.info(f"  URL: {bookmarks_url}")
    logger.info(f"  Parameters: {params}")
    logger.info(f"  Client ID: {X_CLIENT_ID}")
    
    try:
        # Make the request to the bookmarks endpoint
        logger.info("Making API request...")
        response = x_session.get(bookmarks_url, params=params)
        
        logger.info("API RESPONSE DETAILS:")
        logger.info(f"  Status Code: {response.status_code}")
        logger.info(f"  Response Headers: {dict(response.headers)}")
        logger.info(f"  Response URL: {response.url}")
        
        if response.status_code == 200:
            response_data = response.json()
            logger.info("API CALL SUCCESSFUL")
            logger.info(f"  Bookmarks Count: {len(response_data.get('data', []))}")
            logger.info(f"  Response Keys: {list(response_data.keys())}")
            return response_data
        elif response.status_code == 401:
            logger.error("API CALL FAILED - 401 UNAUTHORIZED")
            logger.error("  This indicates the token has expired or is invalid")
            try:
                error_data = response.json()
                logger.error(f"  Error Response: {error_data}")
            except:
                logger.error(f"  Raw Response: {response.text}")
            return {
                'error': True,
                'message': 'Token expired or invalid (401 Unauthorized)',
                'status_code': 401
            }
        elif response.status_code == 403:
            logger.error("API CALL FAILED - 403 FORBIDDEN")
            logger.error("  This indicates access to bookmarks is forbidden")
            try:
                error_data = response.json()
                logger.error(f"  Error Response: {error_data}")
            except:
                logger.error(f"  Raw Response: {response.text}")
            return {
                'error': True,
                'message': 'Access to bookmarks is forbidden (403 Forbidden)',
                'status_code': 403
            }
        else:
            logger.error(f"API CALL FAILED - STATUS CODE: {response.status_code}")
            error_msg = f"Error fetching bookmarks: {response.status_code}"
            try:
                error_data = response.json()
                logger.error(f"  Error Response: {error_data}")
                if 'errors' in error_data and error_data['errors']:
                    error_msg = error_data['errors'][0].get('message', error_msg)
            except:
                logger.error(f"  Raw Response: {response.text}")
                
            return {
                'error': True,
                'message': error_msg,
                'status_code': response.status_code
            }
    except Exception as e:
        logger.error(f"EXCEPTION DURING API CALL: {str(e)}")
        logger.error(f"Exception Type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'error': True,
            'message': str(e),
            'status_code': None
        }
    finally:
        logger.info("=" * 80)
        logger.info("BOOKMARKS API TEST COMPLETED")
        logger.info("=" * 80)


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
        "x_redirect_uri_env": os.getenv('X_REDIRECT_URI'),
        "current_vercel_url": os.getenv('VERCEL_URL'),
        "expected_callback_url": f"https://{os.getenv('VERCEL_URL')}/callback" if os.getenv('VERCEL_URL') else "Not set"
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
    if os.getenv('VERCEL_URL'):
        expected_callback = f"https://{os.getenv('VERCEL_URL')}/callback"
        if X_REDIRECT_URI != expected_callback:
            issues.append(f"Redirect URI mismatch. Current: {X_REDIRECT_URI}, Expected: {expected_callback}")
            issues.append("The app will now automatically use the correct Vercel URL for callbacks")
    else:
        issues.append("VERCEL_URL environment variable not set")
    
    debug_info["issues"] = issues
    debug_info["session_cookie_secure"] = app.config.get('SESSION_COOKIE_SECURE', False)
    
    return render_template('debug.html', debug=debug_info)


@app.route('/debug-session')
def debug_session_route():
    """Debug endpoint to check session state"""
    try:
        session_debug = debug_session()
        
        # Add additional session information
        session_debug.update({
            'request_cookies': dict(request.cookies),
            'session_cookie_name': app.config.get('SESSION_COOKIE_NAME', 'session'),
            'session_cookie_secure': app.config.get('SESSION_COOKIE_SECURE', False),
            'session_cookie_httponly': app.config.get('SESSION_COOKIE_HTTPONLY', True),
            'session_cookie_samesite': app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'),
            'session_lifetime': app.config.get('PERMANENT_SESSION_LIFETIME', 1800),
            'vercel_env': os.getenv('VERCEL_ENV'),
            'vercel_url': os.getenv('VERCEL_URL')
        })
        
        return jsonify(session_debug)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in debug-session: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__
        }), 500


@app.route('/test-session')
def test_session():
    """Test endpoint to verify session is working"""
    try:
        import logging
        logger = logging.getLogger(__name__)
        
        # Set a test value in session
        session['test_value'] = f"test_{int(time.time())}"
        session.modified = True
        
        logger.info("TEST SESSION:")
        logger.info(f"  Set test_value: {session['test_value']}")
        logger.info(f"  Session keys: {list(session.keys())}")
        logger.info(f"  Session modified: {session.modified}")
        
        return jsonify({
            'success': True,
            'test_value': session['test_value'],
            'session_keys': list(session.keys()),
            'session_modified': session.modified,
            'session_id': session.get('_id', 'N/A'),
            'session_type': 'built-in'
        })
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in test-session: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__
        }), 500


@app.route('/test-session-read')
def test_session_read():
    """Test endpoint to read session data"""
    try:
        import logging
        logger = logging.getLogger(__name__)
        
        test_value = session.get('test_value', 'Not found')
        
        logger.info("TEST SESSION READ:")
        logger.info(f"  Retrieved test_value: {test_value}")
        logger.info(f"  Session keys: {list(session.keys())}")
        
        return jsonify({
            'success': True,
            'test_value': test_value,
            'session_keys': list(session.keys()),
            'session_id': session.get('_id', 'N/A')
        })
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in test-session-read: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__
        }), 500


@app.route('/test-config')
def test_config():
    """Test endpoint to show current configuration"""
    return jsonify({
        'success': True,
        'vercel_url': os.getenv('VERCEL_URL'),
        'x_redirect_uri_env': os.getenv('X_REDIRECT_URI'),
        'current_redirect_uri': X_REDIRECT_URI,
        'expected_callback': f"https://{os.getenv('VERCEL_URL')}/callback" if os.getenv('VERCEL_URL') else "Not set",
        'client_id': X_CLIENT_ID[:20] + "..." if X_CLIENT_ID else "Not set",
        'client_secret': "Set" if X_CLIENT_SECRET else "Not set"
    })


def refresh_oauth_token(token):
    """Refresh the OAuth token using the refresh token"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("REFRESHING OAUTH TOKEN - DETAILED LOGGING")
    logger.info("=" * 60)
    
    if 'refresh_token' not in token:
        logger.error("No refresh token available")
        return {'error': 'No refresh token available'}
    
    refresh_token = token['refresh_token']
    logger.info(f"Refresh Token (first 20 chars): {refresh_token[:20]}...")
    
    # Create a new OAuth session
    x_session = OAuth2Session(X_CLIENT_ID)
    
    # Prepare the token data for refresh
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': X_CLIENT_ID
        # 'client_secret': X_CLIENT_SECRET
    }
    headers = {}

    logger.info("REFRESH TOKEN REQUEST DETAILS:")
    logger.info(f"  URL: {TOKEN_URL}")
    logger.info(f"  Token Data: {token_data}")
    logger.info(f"  Headers: {headers}")

    try:
        # Make a POST request to refresh the token
        logger.info("Making refresh token request...")
        response = x_session.post(TOKEN_URL, data=token_data, headers=headers)
        
        logger.info("REFRESH TOKEN RESPONSE DETAILS:")
        logger.info(f"  Status Code: {response.status_code}")
        logger.info(f"  Response URL: {response.url}")
        logger.info("  Full Response Headers:")
        for header_name, header_value in response.headers.items():
            logger.info(f"    {header_name}: {header_value}")
        
        if response.status_code == 200:
            new_token = response.json()
            logger.info("REFRESH TOKEN REQUEST SUCCESSFUL")
            logger.info(f"  New Token Keys: {list(new_token.keys())}")
            logger.info(f"  New Access Token (first 20 chars): {new_token.get('access_token', 'N/A')[:20]}...")
            logger.info(f"  New Token Type: {new_token.get('token_type', 'N/A')}")
            logger.info(f"  New Expires In: {new_token.get('expires_in', 'N/A')}")
            logger.info(f"  New Refresh Token Present: {'Yes' if new_token.get('refresh_token') else 'No'}")
            
            # If the response doesn't include a refresh token, add the old one
            if 'refresh_token' not in new_token and refresh_token:
                new_token['refresh_token'] = refresh_token
                logger.info("  Using old refresh token (not provided in response)")
                
            # Update the token timestamp
            new_token['timestamp'] = int(time.time())
            
            return new_token
        else:
            logger.error(f"REFRESH TOKEN REQUEST FAILED - Status: {response.status_code}")
            error_msg = f"Failed to refresh token: {response.status_code}"
            try:
                error_data = response.json()
                logger.error(f"  Error Response: {error_data}")
                if 'error_description' in error_data:
                    error_msg = error_data['error_description']
                elif 'error' in error_data:
                    error_msg = error_data['error']
            except Exception:
                logger.error(f"  Raw Response: {response.text}")
                
            return {'error': error_msg}
    except Exception as e:
        logger.error(f"REFRESH TOKEN REQUEST EXCEPTION: {str(e)}")
        logger.error(f"Exception Type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {'error': str(e)}
    
    logger.info("=" * 60)
    logger.info("REFRESH TOKEN REQUEST COMPLETED")
    logger.info("=" * 60)


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


@app.route('/test-bookmarks')
def test_bookmarks():
    """Test the access token by fetching user bookmarks"""
    import logging
    
    # Set up logging for the endpoint
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("BOOKMARKS TEST ENDPOINT CALLED")
    logger.info("=" * 80)
    logger.info(f"Request timestamp: {int(time.time())}")
    logger.info(f"Request URL: {request.url}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"User agent: {request.headers.get('User-Agent', 'N/A')}")
    
    # Check if the user is logged in
    token = session.get('oauth_token')
    user_info = session.get('user_info')
    
    # Get detailed session debug info
    session_debug = debug_session()
    
    logger.info("SESSION INFORMATION:")
    logger.info(f"  Session ID: {session_debug['session_id']}")
    logger.info(f"  Session Keys: {session_debug['session_keys']}")
    logger.info(f"  Token in session: {'Yes' if session_debug['token_present'] else 'No'}")
    logger.info(f"  User info in session: {'Yes' if session_debug['user_info_present'] else 'No'}")
    
    if not token or not user_info:
        logger.error("MISSING SESSION DATA")
        logger.error(f"  Token present: {bool(token)}")
        logger.error(f"  User info present: {bool(user_info)}")
        return jsonify({'success': False, 'message': 'No token or user info found in session'})
    
    # Get user ID from user info
    user_id = user_info['data']['id']
    logger.info(f"User ID from session: {user_id}")
    
    # Log session token details before making the API call
    logger.info("SESSION TOKEN SUMMARY:")
    logger.info(f"  Access Token (first 20 chars): {token.get('access_token', 'N/A')[:20]}...")
    logger.info(f"  Token Type: {token.get('token_type', 'N/A')}")
    logger.info(f"  Expires At: {token.get('expires_at', 'N/A')}")
    logger.info(f"  Token Timestamp: {token.get('timestamp', 'N/A')}")
    
    # Fetch bookmarks to test the token
    logger.info("Calling fetch_user_bookmarks function...")
    bookmarks_result = fetch_user_bookmarks(token, user_id)
    
    # Add timestamp for debugging
    bookmarks_result['test_timestamp'] = int(time.time())
    bookmarks_result['token_timestamp'] = token.get('timestamp', 'unknown')
    
    logger.info("TEST RESULT SUMMARY:")
    logger.info(f"  Success: {not bookmarks_result.get('error', False)}")
    logger.info(f"  Status Code: {bookmarks_result.get('status_code', 'N/A')}")
    logger.info(f"  Message: {bookmarks_result.get('message', 'N/A')}")
    logger.info(f"  Test Timestamp: {bookmarks_result['test_timestamp']}")
    logger.info(f"  Token Timestamp: {bookmarks_result['token_timestamp']}")
    
    logger.info("=" * 80)
    logger.info("BOOKMARKS TEST ENDPOINT COMPLETED")
    logger.info("=" * 80)
    
    return jsonify(bookmarks_result)


if __name__ == '__main__':
    app.run(debug=True) 
