import requests
from bs4 import BeautifulSoup
import urllib.parse
import tldextract

def get_base_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None

def check_cloaking(url):
    """
    Checks for anti-bot cloaking by comparing responses from a standard browser User-Agent
    vs a known bot User-Agent (Googlebot).
    """
    standard_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    bot_ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    
    try:
        req_standard = requests.get(url, headers={'User-Agent': standard_ua}, timeout=5, allow_redirects=True)
        req_bot = requests.get(url, headers={'User-Agent': bot_ua}, timeout=5, allow_redirects=True)
        
        # Mismatch in status code (e.g. standard gets 200, bot gets 403)
        if req_standard.status_code != req_bot.status_code:
            # If standard is 200 but bot is blocked, that's cloaking
            if req_standard.status_code == 200 and req_bot.status_code in [403, 404, 401]:
                return True
                
        # Length mismatch (e.g. bot gets empty page, standard gets full phishing page)
        # Threshold: > 50% difference in size
        len_std = len(req_standard.text)
        len_bot = len(req_bot.text)
        
        if len_std > 0:
            diff_ratio = abs(len_std - len_bot) / max(len_std, len_bot)
            if diff_ratio > 0.5:
                return True
                
        return False
    except requests.exceptions.RequestException:
        # If we can't reach it, we can't accurately check for cloaking
        return False

def check_visual_logo_mismatch(url):
    """
    Checks if the page contains mentions of major brands but is hosted on an unverified domain.
    This acts as a text/DOM-based proxy for visual logo mismatch.
    """
    brands = {
        'paypal': ['paypal.com'],
        'microsoft': ['microsoft.com', 'live.com', 'office.com', 'windows.com'],
        'google': ['google.com', 'gmail.com', 'youtube.com'],
        'apple': ['apple.com', 'icloud.com'],
        'netflix': ['netflix.com'],
        'amazon': ['amazon.com'],
        'facebook': ['facebook.com', 'meta.com'],
        'bank of america': ['bankofamerica.com'],
        'chase': ['chase.com'],
        'wells fargo': ['wellsfargo.com']
    }
    
    base_domain = get_base_domain(url)
    if not base_domain:
        return False
        
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        page_text = soup.get_text().lower()
        title_text = soup.title.string.lower() if soup.title else ""
        
        # Check against each brand
        for brand, official_domains in brands.items():
            # If the brand is mentioned significantly (in title or multiple times in body)
            if brand in title_text or page_text.count(brand) > 2:
                # Is the domain an official domain?
                if base_domain.lower() not in official_domains:
                    return True
        return False
    except requests.exceptions.RequestException:
        return False

def analyze_cloaking(url):
    """Runs advanced intelligence and cloaking checks."""
    return {
        'cloaking_detected': check_cloaking(url),
        'visual_logo_mismatch': check_visual_logo_mismatch(url)
    }
