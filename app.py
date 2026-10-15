from flask import Flask, request, jsonify, render_template
import urllib.parse
from dotenv import load_dotenv
import os
import datetime

# Load environment variables from .env file
load_dotenv()

from engine.scoring import calculate_score

app = Flask(__name__)

# In-memory store for scan history
scan_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # Ensure scheme is present
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
        
    try:
        # Validate URL formatting
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
            
        result = calculate_score(url)
        
        # Save to history
        scan_entry = {
            'url': url,
            'score': result['score'],
            'verdict': result['verdict'],
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        # Prepend so newest is first, keep last 50
        scan_history.insert(0, scan_entry)
        if len(scan_history) > 50:
            scan_history.pop()
            
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify(scan_history)

@app.route('/google458fcac4455a9d14.html')
def google_verification():
    return "google-site-verification: google458fcac4455a9d14.html", 200, {'Content-Type': 'text/html; charset=utf-8'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
