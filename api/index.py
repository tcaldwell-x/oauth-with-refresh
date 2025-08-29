import os
import sys

# Add the parent directory to the path so we can import app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Import the Flask app from our main file
    from app import app
except Exception as e:
    print(f"Error importing Flask app: {str(e)}")
    import traceback
    traceback.print_exc()
    raise

# This is for Vercel serverless environment
if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
    except Exception as e:
        print(f"Error running Flask app: {str(e)}")
        import traceback
        traceback.print_exc()
        raise 