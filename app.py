"""
Simple Flask web application for DevSecOps demonstration
"""
from flask import Flask, request, jsonify, render_template_string
import os

app = Flask(__name__)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f0f0f0; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DevSecOps Demo Application</h1>
        <div class="info">
            <p><strong>Status:</strong> <span class="success">Running</span></p>
            <p><strong>Version:</strong> 1.0.0</p>
        </div>
        <p>This is a simple demonstration application for DevSecOps practices including:</p>
        <ul>
            <li>Security scanning with Bandit</li>
            <li>Dependency checking with Safety</li>
            <li>Automated testing</li>
            <li>CI/CD pipeline</li>
            <li>Docker containerization</li>
        </ul>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    """Home page endpoint"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    }), 200

@app.route('/api/echo', methods=['POST'])
def echo():
    """Echo API endpoint for testing"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Input validation
    message = data.get('message', '')
    if len(message) > 1000:
        return jsonify({'error': 'Message too long'}), 400

    return jsonify({
        'echo': message,
        'length': len(message)
    }), 200

if __name__ == '__main__':
    # Use environment variable for port, default to 5000
    port = int(os.environ.get('PORT', 5000))
    # Disable debug mode in production
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
