import os
import requests
import json
import base64

def check_google_safe_browsing(url):
    """
    Checks the URL against the Google Safe Browsing API.
    Returns True if flagged as a threat, False otherwise.
    """
    api_key = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key or api_key == 'your_google_api_key_here':
        return False
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data and len(data['matches']) > 0:
                return True
        return False
    except Exception as e:
        print(f"Google Safe Browsing API Error: {e}")
        # In case of connection error or timeout, we return False to rely on local heuristics
        return False

def check_virustotal(url):
    """
    Checks the URL against the VirusTotal API (v3).
    Returns True if flagged as malicious or suspicious, False otherwise.
    """
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not api_key or api_key == 'your_virustotal_api_key_here':
        return False
        
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            # Require at least 2 security vendor detections to prevent single-vendor false positives
            # from flagging legitimate high-traffic enterprise platforms.
            if malicious_count >= 2:
                return True
        return False
    except Exception as e:
        print(f"VirusTotal API Error: {e}")
        return False

def analyze_api(url):
    """Runs all API-based checks."""
    return {
        'google_safe_browsing_flagged': check_google_safe_browsing(url),
        'virustotal_flagged': check_virustotal(url)
    }

