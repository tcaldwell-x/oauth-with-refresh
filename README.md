# X OAuth2.0 Demo - Flask Application

A simple Flask web application that demonstrates how to implement OAuth 2.0 authentication with X.

## Features

- **X OAuth 2.0 Authentication**: Implement a secure login flow with X
- **User Profile Display**: Show the authenticated user's profile information
- **Session Management**: Handle user sessions and token storage
- **Error Handling**: Proper error handling for authentication failures

## Deployment to Vercel

This application is ready to deploy to Vercel. Follow these steps to deploy your own instance:

### 1. Fork/Clone this Repository

```bash
git clone <repository-url>
cd x-oauth-demo
```

### 2. Install Vercel CLI (Optional)

```bash
npm install -g vercel
```

### 3. Deploy to Vercel

#### Option A: Using Vercel CLI

```bash
vercel login
vercel
```

#### Option B: Using Vercel Web Interface

1. Go to [vercel.com](https://vercel.com)
2. Create a new project and import your GitHub repository
3. Configure the project as follows:
   - Framework Preset: Other
   - Build Command: None
   - Output Directory: None
   - Install Command: `pip install -r requirements.txt`

### 4. Configure Environment Variables

Add the following environment variables in your Vercel project settings:

- `SECRET_KEY`: A secure random string for session management
- `X_CLIENT_ID`: Your X API client ID
- `X_CLIENT_SECRET`: Your X API client secret

### 5. Update X Developer Portal Settings

Go to the [X Developer Portal](https://developer.twitter.com/) and update your app settings:

1. Set the callback URL to your Vercel domain: `https://your-app.vercel.app/callback`
2. Ensure the OAuth 2.0 settings are enabled with appropriate scopes

## Local Development

### 1. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Create a `.env` File

Copy `.env.example` to `.env` and add your X API credentials:

```
SECRET_KEY=your-secret-key-here
X_CLIENT_ID=your-x-client-id
X_CLIENT_SECRET=your-x-client-secret
X_REDIRECT_URI=http://127.0.0.1:5000/callback
```

### 4. Run the Application

```bash
python app.py
```

Visit `http://127.0.0.1:5000/` in your browser.

## Project Structure

- `app.py`: Main application file with routes and OAuth 2.0 logic
- `api/index.py`: Vercel serverless function entry point
- `vercel.json`: Vercel deployment configuration
- `templates/`: HTML templates using Jinja2
- `static/`: CSS styles and other static assets
- `.env.example`: Example environment variables (create a `.env` file based on this)

## License

MIT 