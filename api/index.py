import os
import sys

# Add the parent directory to the path so we can import app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402 – Vercel needs a top-level `app` WSGI callable

# Vercel serverless entry point — `app` is the WSGI callable.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))