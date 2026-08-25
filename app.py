import os
import tempfile
import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Import the provided phishing analyzer logic
from phishing_analyzer import analyze_url, analyze_email

# Import the agentic decision layer (built on top of the analyzer above,
# untouched) — adds ALLOW/FLAG_FOR_REVIEW/BLOCK/ESCALATE decisions,
# fintech payment-impersonation context, and an audit-trail memory.
from risk_agent import RiskAgent

risk_agent = RiskAgent()

# Load environment variables
load_dotenv()

# Initialize Flask app, configuring static folder
app = Flask(__name__, static_folder='static', static_url_path='')

# Allow the browser extension (chrome-extension:// / moz-extension:// origins)
# to call the API endpoints. The extension only ever POSTs a URL or a .eml file
# it already has, so an open CORS policy on these two routes is low-risk.
CORS(app, resources={r"/api/*": {"origins": "*"}})

def json_serializable(data):
    """
    Recursively inspects data and converts datetime/date objects to strings
    to prevent JSON serialization crashes, while preserving key names and shapes.
    """
    if isinstance(data, dict):
        return {k: json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [json_serializable(item) for item in data]
    elif isinstance(data, (datetime.datetime, datetime.date)):
        return data.strftime('%Y-%m-%d %H:%M:%S')
    return data

@app.route('/')
def serve_index():
    """Serves the static index.html page."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/check-url', methods=['POST'])
def check_url_endpoint():
    """
    Accepts JSON containing a URL: { "url": "https://example.com" }
    Runs the URL forensic analysis and returns the scoring / verdict results.
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request. Missing 'url' field in JSON body."}), 400
        
        url_to_scan = data['url'].strip()
        if not url_to_scan:
            return jsonify({"error": "The URL field cannot be empty."}), 400

        # Perform analysis using unmodified phishing_analyzer.py function
        raw_result = analyze_url(url_to_scan, verbose=False)
        
        # Serialize datetime objects recursively
        result = json_serializable(raw_result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Internal server error occurred: {str(e)}"}), 500

@app.route('/api/assess-url', methods=['POST'])
def assess_url_endpoint():
    """
    Agentic version of /api/check-url. Accepts JSON containing a URL:
    { "url": "https://example.com" }
    Runs the same forensic analysis, then passes it through RiskAgent to
    get a decision (ALLOW / FLAG_FOR_REVIEW / BLOCK / ESCALATE), a plain-
    language explanation, and fintech-specific context (payment-flow
    impersonation keywords, repeat-offender history from the audit log).
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request. Missing 'url' field in JSON body."}), 400

        url_to_scan = data['url'].strip()
        if not url_to_scan:
            return jsonify({"error": "The URL field cannot be empty."}), 400

        raw_result = risk_agent.assess_url(url_to_scan)
        result = json_serializable(raw_result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Internal server error occurred: {str(e)}"}), 500


@app.route('/api/check-email', methods=['POST'])
def check_email_endpoint():
    """
    Accepts a multipart form submission with file='foo.eml' containing EML bytes.
    Saves it to a temporary file, runs analysis, cleans up, and returns results.
    """
    if 'file' not in request.files:
        return jsonify({"error": "Invalid request. No file part found in request."}), 400
    
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No file selected. Please select a valid .eml file."}), 400

    # Ensure it's a .eml file
    if not uploaded_file.filename.lower().endswith('.eml'):
        return jsonify({"error": "Unsupported file format. Only .eml files are supported."}), 400

    temp_path = None
    try:
        # Create a secure temporary file to write the stream content
        fd, temp_path = tempfile.mkstemp(suffix='.eml')
        with os.fdopen(fd, 'wb') as tmp:
            uploaded_file.save(tmp)

        # Run parsing and scanning on the temporary file path
        raw_result = analyze_email(temp_path, scan_urls=True, verbose=False)
        
        # Serialize datetime objects recursively
        result = json_serializable(raw_result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Internal server error occurred during email parse: {str(e)}"}), 500

    finally:
        # Guarantee temporary file is deleted in all execution cases
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as err:
                app.logger.error(f"Failed to delete temp file {temp_path}: {str(err)}")

@app.route('/api/assess-email', methods=['POST'])
def assess_email_endpoint():
    """
    Agentic version of /api/check-email. Accepts a multipart form submission
    with file='foo.eml' containing EML bytes. Runs the same email analysis,
    then passes it through RiskAgent for a decision + explanation, same as
    /api/assess-url does for links.
    """
    if 'file' not in request.files:
        return jsonify({"error": "Invalid request. No file part found in request."}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No file selected. Please select a valid .eml file."}), 400

    if not uploaded_file.filename.lower().endswith('.eml'):
        return jsonify({"error": "Unsupported file format. Only .eml files are supported."}), 400

    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(suffix='.eml')
        with os.fdopen(fd, 'wb') as tmp:
            uploaded_file.save(tmp)

        raw_result = risk_agent.assess_email(temp_path)
        result = json_serializable(raw_result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Internal server error occurred during email parse: {str(e)}"}), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as err:
                app.logger.error(f"Failed to delete temp file {temp_path}: {str(err)}")


if __name__ == '__main__':
    # Render binds to PORT env variable, defaulting locally to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
