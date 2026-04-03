import os
import sys

# Minimal WSGI callable so Vercel's static analysis always finds a
# top-level "app" even before dependencies are installed.
def app(environ, start_response):
    start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
    return [b"App not loaded"]

# At runtime (after pip install), replace with the real Flask app.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app import app  # noqa: F811
except Exception:
    pass  # keep the fallback WSGI callable defined above

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))