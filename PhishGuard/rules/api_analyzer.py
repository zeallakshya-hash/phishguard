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

def check_phishtank(url):
    """
    Checks the URL against the PhishTank API.
    Returns True if flagged as a threat, False otherwise.
    """
    # PhishTank's CheckURL API does not always require an API key, but it's recommended
    # to avoid rate limits. It expects a POST request.
    api_key = os.environ.get('PHISHTANK_API_KEY')
    
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    
    data = {
        "url": url,
        "format": "json"
    }
    
    if api_key and api_key != 'your_phishtank_api_key_here':
        data['app_key'] = api_key
        
    try:
        # PhishTank can be slow sometimes
        response = requests.post(endpoint, data=data, timeout=8)
        if response.status_code == 200:
            result = response.json()
            if result.get('results', {}).get('in_database') and result.get('results', {}).get('valid'):
                return True
        return False
    except Exception as e:
        print(f"PhishTank API Error: {e}")
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
            if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                return True
        return False
    except Exception as e:
        print(f"VirusTotal API Error: {e}")
        return False

def analyze_api(url):
    """Runs all API-based checks."""
    return {
        'google_safe_browsing_flagged': check_google_safe_browsing(url),
        'phishtank_flagged': check_phishtank(url),
        'virustotal_flagged': check_virustotal(url)
    }
