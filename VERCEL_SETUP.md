# Vercel OAuth Setup Guide

## Problem
Vercel preview deployments generate unique URLs (e.g., `oauth-with-refresh-pnzjhtf76-taylors-projects-c30b24d3.vercel.app`) that change with each deployment, making OAuth redirect URIs unpredictable.

## Solutions

### Option 1: Custom Domain (Recommended)

1. **Set up a custom domain in Vercel:**
   - Go to your Vercel project dashboard
   - Navigate to Settings → Domains
   - Add a custom domain (e.g., `oauth-demo.yourdomain.com`)

2. **Configure environment variables:**
   ```bash
   # In Vercel dashboard → Settings → Environment Variables
   X_REDIRECT_URI=https://oauth-demo.yourdomain.com/callback
   ```

3. **Update Twitter Developer Portal:**
   - Go to Twitter Developer Portal
   - Update callback URL to: `https://oauth-demo.yourdomain.com/callback`

### Option 2: Production Deployment

1. **Deploy to production:**
   ```bash
   vercel --prod
   ```

2. **Use the production URL:**
   - Production deployments have stable URLs
   - Update Twitter Developer Portal with the production URL

### Option 3: Multiple Callback URLs

1. **Add multiple callback URLs in Twitter Developer Portal:**
   - `https://oauth-demo.yourdomain.com/callback` (custom domain)
   - `https://your-app.vercel.app/callback` (production)
   - `https://oauth-with-refresh-*.vercel.app/callback` (preview deployments)

2. **Note:** Twitter allows multiple callback URLs, but you need to specify which one to use in your OAuth request.

## Current Configuration

The app now automatically handles different environments:

- **Production**: Uses `X_REDIRECT_URI` environment variable
- **Preview**: Uses current Vercel URL
- **Local**: Uses `http://127.0.0.1:5000/callback`

## Testing

Use the "Test Config" button to verify your current configuration:

```json
{
  "vercel_env": "preview",
  "current_redirect_uri": "https://current-vercel-url.vercel.app/callback",
  "deployment_type": "preview"
}
```

## Recommended Setup

1. **Set up a custom domain** (e.g., `oauth-demo.yourdomain.com`)
2. **Configure `X_REDIRECT_URI`** in Vercel environment variables
3. **Update Twitter Developer Portal** with the custom domain
4. **Deploy to production** for stable URLs

This ensures your OAuth flow works consistently across all deployments. 