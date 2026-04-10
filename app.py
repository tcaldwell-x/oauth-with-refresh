# OAuth2.0 Application - Minimal access token retrieval flow
import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import secrets
import base64
import hashlib
import time
import datetime
import urllib.parse
import requests as req_lib

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
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 30 minutes

# Add error handling for app initialization
try:
    # Test basic app functionality
    with app.app_context():
        pass
except Exception as e:
    print(f"Error initializing Flask app: {str(e)}")
    import traceback
    traceback.print_exc()

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

# Production domain configuration
PRODUCTION_DOMAIN = os.getenv('PRODUCTION_DOMAIN', 'oauth-with-refresh-x3j6.vercel.app')

# Get the appropriate redirect URI based on environment
if os.getenv('X_REDIRECT_URI'):
    # Use custom configured redirect URI (highest priority)
    X_REDIRECT_URI = os.getenv('X_REDIRECT_URI')
elif os.getenv('VERCEL_ENV') == 'production':
    # Use production domain for production deployments
    X_REDIRECT_URI = f"https://{PRODUCTION_DOMAIN}/callback"
elif os.getenv('VERCEL_URL'):
    # Use Vercel URL for preview deployments
    X_REDIRECT_URI = f"https://{os.getenv('VERCEL_URL')}/callback"
else:
    # Local development
    X_REDIRECT_URI = "https://oauth-with-refresh-x3j6.vercel.app/callback"

# Shared headers for all X API requests
# NOTE: staging headers (X-B3-Flags, X-TFE-Experiment-environment) removed —
# they route requests to an internal staging environment which breaks user-info
# and other API calls in production.
X_REQUEST_HEADERS = {}

# X OAuth2 endpoints
AUTHORIZATION_BASE_URL = 'https://localhost.twitter.com:3443/i/oauth2/authorize'
TOKEN_URL = 'https://api.x.com/2/oauth2/token'
USERINFO_URL = 'https://api.x.com/2/users/me'

# Scopes needed for the application
SCOPES = [
    'tweet.read',
    'tweet.write',
    'tweet.moderate.write',
    'users.read',
    'users.email',
    'follows.read',
    'follows.write',
    'like.read',
    'like.write',
    'list.read',
    'list.write',
    'block.read',
    'block.write',
    'mute.read',
    'mute.write',
    'bookmark.read',
    'bookmark.write',
    'dm.read',
    'dm.write',
    'media.write',
    'space.read',
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


@app.errorhandler(Exception)
def handle_exception(e):
    """Catch-all error handler that shows the real error (useful on Vercel)."""
    import traceback as tb
    trace = tb.format_exc()
    # Return JSON for AJAX/fetch requests, HTML otherwise
    if request.accept_mimetypes.best == 'application/json' or request.is_json:
        return jsonify({'success': False, 'error': f'{type(e).__name__}: {e}'}), 500
    return (
        f'<h1>500 — {type(e).__name__}</h1>'
        f'<pre style="white-space:pre-wrap;color:red;">{trace}</pre>'
    ), 500


@app.route('/')
def index():
    """Main page that displays login option"""
    return render_template('index.html')


@app.route('/health')
def health_check():
    """Health check endpoint to verify the app is working"""
    try:
        return jsonify({
            'status': 'healthy',
            'timestamp': int(time.time()),
            'vercel_env': os.getenv('VERCEL_ENV'),
            'vercel_url': os.getenv('VERCEL_URL'),
            'app_config': {
                'secret_key_set': bool(app.config.get('SECRET_KEY')),
                'session_cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
                'session_cookie_httponly': app.config.get('SESSION_COOKIE_HTTPONLY'),
                'session_lifetime': app.config.get('PERMANENT_SESSION_LIFETIME')
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__,
            'timestamp': int(time.time())
        }), 500


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
    random_state = secrets.token_urlsafe(16)
    combined_state = f"{random_state}:{code_verifier}"
    logger.info(f"  Random State: {random_state}")
    logger.info(f"  Combined State: {combined_state[:50]}...")
    logger.info(f"  Code Verifier Length: {len(code_verifier)}")
    
    # Create OAuth session
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    # Add X-B3-Flags header to the session
    x_session.headers.update(X_REQUEST_HEADERS)
    
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
    
    # Additional session debugging
    logger.info("SESSION DEBUG IN LOGIN:")
    logger.info(f"  Session ID: {session.get('_id', 'N/A')}")
    logger.info(f"  Session Keys: {list(session.keys())}")
    logger.info(f"  Session Modified: {session.modified}")
    logger.info(f"  Code Verifier in Session: {session.get('code_verifier', 'Not found')[:20] if session.get('code_verifier') else 'Not found'}...")
    logger.info(f"  OAuth State in Session: {session.get('oauth_state', 'Not found')[:20] if session.get('oauth_state') else 'Not found'}...")
    
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
    logger.info(f"Callback function called successfully")
    logger.info(f"Request URL: {request.url}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request args: {dict(request.args)}")
    
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
                logger.info(f"State parts: random_state={state_parts[0][:10]}..., code_verifier={code_verifier[:10]}...")
                
                # Validate code verifier format
                if len(code_verifier) < 43:
                    logger.error(f"Extracted code_verifier too short: {len(code_verifier)} characters")
                else:
                    logger.info("Code verifier extraction successful")
            else:
                logger.error(f"Invalid state format. Expected 'random:code_verifier', got: {request_state}")
        else:
            logger.error(f"No code_verifier found in state: {request_state}")
            logger.error(f"State format analysis: contains ':' = {':' in request_state}")
            logger.error(f"State length: {len(request_state) if request_state else 0}")
    elif not session_state and not request_state:
        logger.error("No state found in session or request")
    elif session_state and not code_verifier:
        logger.error("Session state found but no code_verifier in session")
    
    # Additional debugging for session issues
    logger.info("SESSION DEBUG IN CALLBACK:")
    logger.info(f"  Session ID: {session.get('_id', 'N/A')}")
    logger.info(f"  Session Keys: {list(session.keys())}")
    logger.info(f"  Session Modified: {session.modified}")
    logger.info(f"  Request Cookies: {dict(request.cookies)}")
    logger.info(f"  Session Cookie Name: {app.config.get('SESSION_COOKIE_NAME', 'session')}")
    logger.info(f"  Session Cookie Present: {'session' in request.cookies}")
    
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
    
    # Add X-B3-Flags header to the session
    x_session.headers.update(X_REQUEST_HEADERS)
    
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
            'Authorization': f'Basic {base64.b64encode(f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode()).decode()}',
            **X_REQUEST_HEADERS,
        }
        
        try:
            manual_response = requests.post(TOKEN_URL, data=token_data, headers=headers)
            logger.info("MANUAL OAUTH2 TOKEN REQUEST RESPONSE HEADERS:")
            logger.info(f"  Status Code: {manual_response.status_code}")
            logger.info(f"  Response URL: {manual_response.url}")
            logger.info("  Full Response Headers:")
            for header_name, header_value in manual_response.headers.items():
                logger.info(f"    {header_name}: {header_value}")
            
            # Specifically log x-transaction-id if present
            x_transaction_id = manual_response.headers.get('x-transaction-id')
            if x_transaction_id:
                logger.info(f"  X-Transaction-ID: {x_transaction_id}")
            else:
                logger.info("  X-Transaction-ID: Not present in response headers")
            
            if manual_response.status_code != 200:
                logger.error(f"  Manual request failed with status: {manual_response.status_code}")
                logger.error(f"  Response body: {manual_response.text}")
        except Exception as e:
            logger.error(f"  Manual request failed with exception: {str(e)}")
        
        # Add a timestamp to the token for tracking expiration
        token['timestamp'] = int(time.time())

        # Store only the essential token fields to keep the cookie small
        session['oauth_token'] = {
            'access_token': token.get('access_token'),
            'refresh_token': token.get('refresh_token'),
            'token_type': token.get('token_type'),
            'expires_in': token.get('expires_in'),
            'expires_at': token.get('expires_at'),
            'scope': token.get('scope'),
            'timestamp': token['timestamp'],
        }

        # Fetch user information and store only the flat fields we need.
        user_info = fetch_user_info(token)
        user_data = user_info.get('data') or {}
        if not user_data.get('username'):
            # Fallback attempt without OAuth2Session wrapper
            try:
                r = req_lib.get(
                    'https://api.x.com/2/users/me',
                    headers={'Authorization': f'Bearer {token["access_token"]}'},
                    params={'user.fields': 'name,username,profile_image_url'},
                )
                if r.status_code == 200:
                    user_data = r.json().get('data') or {}
            except Exception:
                pass

        # If user info is still unavailable (e.g. app not enrolled in a
        # Project, or Free-tier), generate a stable short ID from the
        # access token so each login is distinguishable.
        if not user_data.get('username'):
            token_hash = hashlib.sha256(
                token['access_token'].encode()
            ).hexdigest()[:8]
            user_data = {
                'id': token_hash,
                'name': f'User {token_hash}',
                'username': f'user_{token_hash}',
                'profile_image_url': '',
            }

        session['user_info'] = {
            'data': {
                'id': user_data.get('id'),
                'name': user_data.get('name'),
                'username': user_data.get('username'),
                'profile_image_url': user_data.get('profile_image_url') or '',
            }
        }

        # Clear PKCE / state values that are no longer needed
        session.pop('code_verifier', None)
        session.pop('oauth_state', None)

        # Redirect to token display page
        return redirect(url_for('token_info'))
    
    except Exception as e:
        logger.error(f"Error in callback: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Return a more detailed error page
        error_details = {
            'error_message': str(e),
            'error_type': type(e).__name__,
            'timestamp': int(time.time()),
            'request_url': request.url,
            'request_method': request.method
        }
        
        return render_template('error.html', 
                              error=f"OAuth Callback Error: {str(e)}", 
                              error_details=error_details)


def fetch_user_info(token):
    """Fetch the user's information from X API"""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("FETCHING USER INFO - DETAILED LOGGING")
    logger.info("=" * 60)
    
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # Add X-B3-Flags header to the session
    x_session.headers.update(X_REQUEST_HEADERS)
    
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


@app.route('/logout')
def logout():
    """Log the user out by clearing the session"""
    session.clear()
    return redirect(url_for('index'))


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
    headers = {
        **X_REQUEST_HEADERS,
    }

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
        
        # Specifically log x-transaction-id if present
        x_transaction_id = response.headers.get('x-transaction-id')
        if x_transaction_id:
            logger.info(f"  X-Transaction-ID: {x_transaction_id}")
        else:
            logger.info("  X-Transaction-ID: Not present in response headers")
        
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
            
            # Add response details to the token
            new_token['status_code'] = response.status_code
            new_token['x_transaction_id'] = response.headers.get('x-transaction-id', 'N/A')
            
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
                
            return {
                'error': error_msg,
                'status_code': response.status_code,
                'x_transaction_id': response.headers.get('x-transaction-id', 'N/A')
            }
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
    
    if not token:
        return redirect(url_for('index'))

    user_data = (user_info or {}).get('data') or {}
    # Provide sensible defaults so the page always renders
    user_data.setdefault('name', 'User')
    user_data.setdefault('username', 'user')

    # Add a timestamp if not present
    if 'timestamp' not in token:
        token['timestamp'] = int(time.time())
    
    return render_template('token.html', 
                          token=token, 
                          user=user_data,
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


@app.route('/api-request', methods=['POST'])
def api_request():
    """Make an authenticated request to any X API endpoint using the session token"""
    token = session.get('oauth_token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    url = data.get('url', '').strip()
    method = data.get('method', 'GET').upper()
    body = data.get('body')  # optional JSON body for POST/PUT/PATCH
    custom_headers = data.get('headers') or {}  # per-request headers from the UI

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    import requests as req_lib

    # Build headers: start with Authorization Bearer (same as Postman),
    # then layer in whatever the user has set in the explorer UI.
    request_headers = {
        'Authorization': f'Bearer {token["access_token"]}',
        **custom_headers,
    }

    try:
        kwargs = {'headers': request_headers}
        if body and method in ('POST', 'PUT', 'PATCH'):
            kwargs['json'] = body

        upstream = req_lib.request(method, url, **kwargs)
        content_type = upstream.headers.get('Content-Type', '')
        is_success = 200 <= upstream.status_code < 300

        # Only proxy raw binary for successful non-JSON responses (images etc.)
        # Error responses always come back as JSON so the body is visible in the UI.
        # If the body is empty (Content-Length: 0) fall through to the debug JSON view.
        if is_success and not content_type.startswith('application/json') and len(upstream.content) > 0:
            filename = url.rstrip('/').split('/')[-1] or 'download'
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            image_exts = {'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
                          'gif': 'image/gif', 'webp': 'image/webp'}
            resolved_type = image_exts.get(ext, content_type) or 'application/octet-stream'
            return Response(
                upstream.content,
                status=upstream.status_code,
                content_type=resolved_type,
                headers={
                    'X-Api-Status-Code': str(upstream.status_code),
                    'X-Response-Is-Binary': 'true',
                    'X-Upstream-Content-Type': resolved_type,
                    'Content-Disposition': f'inline; filename="{filename}"',
                },
            )

        # JSON / error response — always return the envelope so the UI can display it
        try:
            response_body = upstream.json()
        except Exception:
            response_body = upstream.text

        # Mask token but confirm it's present
        auth_sent = request_headers.get('Authorization', '')
        auth_debug = (auth_sent[:15] + '…' + auth_sent[-4:]) if len(auth_sent) > 20 else '(empty)'

        # Build redirect chain so we can see every hop
        redirect_chain = [
            {
                'url': r.url,
                'status_code': r.status_code,
                'headers': dict(r.headers),
            }
            for r in upstream.history
        ]

        return jsonify({
            'status_code': upstream.status_code,
            'body': response_body,
            'debug': {
                'final_url': upstream.url,
                'content_length': upstream.headers.get('Content-Length'),
                'content_type': upstream.headers.get('Content-Type'),
                'authorization_sent': auth_debug,
                'request_headers': {k: (v if k.lower() != 'authorization' else auth_debug)
                                    for k, v in request_headers.items()},
                'response_headers': dict(upstream.headers),
                'redirect_chain': redirect_chain,
            },
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Secret Rotation Test – persistent token store & testing dashboard
# ---------------------------------------------------------------------------

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

DATABASE_URL = os.getenv('DATABASE_URL')  # Neon connection string


def _get_db():
    """Return a psycopg2 connection to the Neon database."""
    if not HAS_PSYCOPG2:
        raise RuntimeError('psycopg2 is not installed')
    return psycopg2.connect(DATABASE_URL, sslmode='require')


def _init_db():
    """Create the saved_tokens table if it doesn't already exist."""
    if not DATABASE_URL or not HAS_PSYCOPG2:
        return
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS saved_tokens (
                    username        TEXT PRIMARY KEY,
                    user_id         TEXT,
                    name            TEXT,
                    profile_image_url TEXT,
                    token_data      JSONB NOT NULL,
                    saved_at        BIGINT,
                    client_id_used  TEXT,
                    client_secret_hint TEXT,
                    last_refreshed_at BIGINT,
                    client_secret_hint_at_refresh TEXT
                )
            """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB init warning: {e}")


# Auto-create table on startup
_init_db()


def _load_saved_tokens():
    """Load all saved tokens from the database, returned as {username: entry}."""
    if not DATABASE_URL or not HAS_PSYCOPG2:
        return {}
    try:
        conn = _get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM saved_tokens ORDER BY saved_at DESC")
            rows = cur.fetchall()
        conn.close()
        result = {}
        for row in rows:
            entry = dict(row)
            entry['token'] = entry.pop('token_data')
            result[entry['username']] = entry
        return result
    except Exception as e:
        print(f"DB read error: {e}")
        return {}


def _save_token_entry(username, entry):
    """Upsert a single token entry into the database."""
    if not DATABASE_URL or not HAS_PSYCOPG2:
        return
    conn = _get_db()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO saved_tokens
                (username, user_id, name, profile_image_url, token_data,
                 saved_at, client_id_used, client_secret_hint,
                 last_refreshed_at, client_secret_hint_at_refresh)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (username) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                name = EXCLUDED.name,
                profile_image_url = EXCLUDED.profile_image_url,
                token_data = EXCLUDED.token_data,
                saved_at = EXCLUDED.saved_at,
                client_id_used = EXCLUDED.client_id_used,
                client_secret_hint = EXCLUDED.client_secret_hint,
                last_refreshed_at = EXCLUDED.last_refreshed_at,
                client_secret_hint_at_refresh = EXCLUDED.client_secret_hint_at_refresh
        """, (
            username,
            entry.get('user_id'),
            entry.get('name'),
            entry.get('profile_image_url'),
            json.dumps(entry.get('token', {})),
            entry.get('saved_at'),
            entry.get('client_id_used'),
            entry.get('client_secret_hint'),
            entry.get('last_refreshed_at'),
            entry.get('client_secret_hint_at_refresh'),
        ))
    conn.commit()
    conn.close()


def _delete_token_entry(username):
    """Remove a token entry from the database."""
    if not DATABASE_URL or not HAS_PSYCOPG2:
        return
    conn = _get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM saved_tokens WHERE username = %s", (username,))
    conn.commit()
    conn.close()


@app.route('/save-token', methods=['POST'])
def save_token():
    """Persist the current session token to the database so it survives deploys & secret rotations."""
    if not DATABASE_URL:
        return jsonify({'success': False, 'message': 'DATABASE_URL is not configured. Add it to your Vercel environment variables.'}), 500
    if not HAS_PSYCOPG2:
        return jsonify({'success': False, 'message': 'psycopg2 is not installed.'}), 500

    token = session.get('oauth_token')
    user_info = session.get('user_info')
    if not token or not user_info:
        return jsonify({'success': False, 'message': 'No active session to save'}), 400

    user_data = user_info.get('data') or {}
    username = user_data.get('username') or None
    user_id = user_data.get('id') or None

    if not username:
        return jsonify({'success': False, 'message': 'No username in session. Try logging out and back in.'}), 400

    entry = {
        'username': username,
        'user_id': user_id,
        'name': user_data.get('name') or username,
        'profile_image_url': user_data.get('profile_image_url') or '',
        'token': token,
        'saved_at': int(time.time()),
        'client_id_used': X_CLIENT_ID,
        'client_secret_hint': (X_CLIENT_SECRET or '')[:4] + '...' + (X_CLIENT_SECRET or '')[-4:] if X_CLIENT_SECRET else 'N/A',
    }
    try:
        _save_token_entry(username, entry)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Database error: {e}'}), 500
    return jsonify({'success': True, 'message': f'Token saved for @{username}'})


@app.route('/secret-test')
def secret_test():
    """Dashboard for testing whether tokens still work after a secret rotation."""
    tokens = _load_saved_tokens()
    current_secret_hint = (X_CLIENT_SECRET or '')[:4] + '...' + (X_CLIENT_SECRET or '')[-4:] if X_CLIENT_SECRET else 'N/A'
    return render_template(
        'secret_test.html',
        saved_tokens=tokens,
        current_secret_hint=current_secret_hint,
        client_id=X_CLIENT_ID,
    )


@app.route('/secret-test/api-call', methods=['POST'])
def secret_test_api_call():
    """Use a saved access token to call GET /2/users/me and report the result."""
    data = request.get_json()
    username = data.get('username')
    tokens = _load_saved_tokens()
    entry = tokens.get(username)
    if not entry:
        return jsonify({'success': False, 'error': 'Token not found for this user'})

    access_token = entry['token'].get('access_token', '')
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    try:
        r = req_lib.get(
            'https://api.x.com/2/users/me',
            headers=headers,
            params={'user.fields': 'name,username,profile_image_url'},
        )
        try:
            body = r.json()
        except Exception:
            body = r.text
        return jsonify({
            'success': r.status_code == 200,
            'status_code': r.status_code,
            'body': body,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/secret-test/refresh', methods=['POST'])
def secret_test_refresh():
    """Try to refresh a saved token using the *current* client secret."""
    data = request.get_json()
    username = data.get('username')
    tokens = _load_saved_tokens()
    entry = tokens.get(username)
    if not entry:
        return jsonify({'success': False, 'error': 'Token not found for this user'})

    refresh_token_val = entry['token'].get('refresh_token')
    if not refresh_token_val:
        return jsonify({'success': False, 'error': 'No refresh token saved for this user'})

    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token_val,
        'client_id': X_CLIENT_ID,
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {base64.b64encode(f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode()).decode()}',
    }
    try:
        r = req_lib.post(TOKEN_URL, data=token_data, headers=headers)
        try:
            body = r.json()
        except Exception:
            body = r.text
        result = {
            'success': r.status_code == 200,
            'status_code': r.status_code,
            'body': body,
        }
        # If refresh succeeded, update the saved token in the database
        if r.status_code == 200 and isinstance(body, dict):
            new_token = body.copy()
            if 'refresh_token' not in new_token and refresh_token_val:
                new_token['refresh_token'] = refresh_token_val
            new_token['timestamp'] = int(time.time())
            entry['token'] = new_token
            entry['last_refreshed_at'] = int(time.time())
            entry['client_secret_hint_at_refresh'] = (X_CLIENT_SECRET or '')[:4] + '...' + (X_CLIENT_SECRET or '')[-4:] if X_CLIENT_SECRET else 'N/A'
            _save_token_entry(username, entry)
            result['message'] = 'Token refreshed and saved.'
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/secret-test/delete', methods=['POST'])
def secret_test_delete():
    """Remove a saved token."""
    data = request.get_json()
    username = data.get('username')
    _delete_token_entry(username)
    return jsonify({'success': True})


if __name__ == '__main__':
    try:
        app.run(debug=True)
    except Exception as e:
        print(f"Error running Flask app: {str(e)}")
        import traceback
        traceback.print_exc() 
