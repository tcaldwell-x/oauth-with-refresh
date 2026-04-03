import os
import sys

# Add the parent directory to the path so we can import app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
except Exception as exc:
    # Vercel's @vercel/python builder requires a top-level `app` (WSGI callable)
    # to exist at import time.  If the real app fails to load we still need to
    # expose *something* so the build step succeeds and the error is visible at
    # runtime rather than a cryptic "could not find handler" message.
    import traceback
    traceback.print_exc()

    from flask import Flask
    app = Flask(__name__)
    _startup_error = str(exc)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def _error_page(path):
        return (
            f"<h1>App failed to start</h1><pre>{_startup_error}</pre>",
            500,
        )

# Vercel serverless entry point — `app` is the WSGI callable.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))