import requests
from bs4 import BeautifulSoup
import urllib.parse
import tldextract

def get_base_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None

def analyze_content(url):
    """Scrapes the URL and checks content-based phishing indicators."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/'
    }
    
    results = {
        'insecure_login_form': False,
        'mismatched_favicon': False,
        'external_form_target': False,
        'hidden_iframes': False,
        'right_click_blocked': False,
        'content_unreachable': False,
        'connection_blocked_by_antivirus': False,
        'decoy_captcha': False,
        'obfuscated_javascript': False,
        'client_side_redirect': False,
        'anti_analysis_blocking': False,
        'highly_sensitive_inputs': False
    }

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        # If response is not 200 OK, we might not get full HTML, but we try parsing anyway.
        soup = BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException as e:
        error_msg = str(e).lower()
        # Windows Defender or network firewalls often forcibly close connections to malicious payloads
        if 'connection aborted' in error_msg or 'connection reset' in error_msg or 'forcibly closed' in error_msg or 'winsock' in error_msg:
            results['connection_blocked_by_antivirus'] = True
        else:
            results['content_unreachable'] = True
        return results

    base_domain = get_base_domain(url)
    is_https = url.startswith('https://')

    # Check for login forms on non-HTTPS pages
    password_inputs = soup.find_all('input', type='password')
    if password_inputs and not is_https:
        results['insecure_login_form'] = True

    # Check for external form targets
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            action_url = urllib.parse.urljoin(url, action)
            action_domain = get_base_domain(action_url)
            if action_domain and action_domain != base_domain:
                results['external_form_target'] = True
                break

    # Check for mismatched favicon
    favicon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
    if favicon_link:
        href = favicon_link.get('href')
        if href:
            favicon_url = urllib.parse.urljoin(url, href)
            favicon_domain = get_base_domain(favicon_url)
            if favicon_domain and favicon_domain != base_domain:
                results['mismatched_favicon'] = True

    # Check for hidden iframes
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        style = iframe.get('style', '').lower()
        width = iframe.get('width', '').lower()
        height = iframe.get('height', '').lower()
        if 'display:none' in style or 'visibility:hidden' in style or width == '0' or height == '0':
            results['hidden_iframes'] = True
            break

    # Check for highly sensitive inputs
    inputs = soup.find_all('input')
    sensitive_keywords = ['cvv', 'ssn', 'pin', 'otp', '2fa', 'social security']
    for inp in inputs:
        name = inp.get('name', '').lower()
        id_attr = inp.get('id', '').lower()
        placeholder = inp.get('placeholder', '').lower()
        if any(kw in name or kw in id_attr or kw in placeholder for kw in sensitive_keywords):
            results['highly_sensitive_inputs'] = True
            break

    # Check for decoy captcha / turnstile
    page_text = soup.get_text().lower()
    captcha_phrases = ['verify you are human', 'checking your browser', 'security check', 'prove you are human']
    has_captcha_text = any(phrase in page_text for phrase in captcha_phrases)
    
    # If it says it's checking your browser but no legitimate cloudflare/turnstile/recaptcha scripts are loaded
    if has_captcha_text:
        has_real_captcha = False
        for script in soup.find_all('script'):
            src = script.get('src', '').lower()
            if 'recaptcha' in src or 'cloudflare' in src or 'turnstile' in src or 'hcaptcha' in src:
                has_real_captcha = True
                break
        if not has_real_captcha:
            results['decoy_captcha'] = True

    # JavaScript based checks (obfuscation, redirects, anti-analysis)
    scripts = soup.find_all('script')
    html_str = response.text.lower()
    
    # Anti-Analysis
    if ('event.button == 2' in html_str or 'oncontextmenu' in html_str or 
        'keycode == 123' in html_str or 'keycode==123' in html_str or 
        'debugger;' in html_str or 'debugger' in html_str):
        results['anti_analysis_blocking'] = True
        # Keep old key for backwards compat
        results['right_click_blocked'] = True
        
    # Client-Side Redirect
    if ('window.location.replace' in html_str or 'window.location.href=' in html_str.replace(' ', '')):
        results['client_side_redirect'] = True
    
    meta_refresh = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'})
    if meta_refresh:
        results['client_side_redirect'] = True

    # Obfuscated JavaScript
    for script in scripts:
        script_content = script.string
        if script_content:
            script_content = script_content.lower()
            if 'eval(function(p,a,c,k,e,' in script_content:
                results['obfuscated_javascript'] = True
                break
            # JSFuck check `[][(![]+[])`
            if '[][(![]+[])' in script_content:
                results['obfuscated_javascript'] = True
                break
            # common hex obfuscator `var _0x`
            if 'var _0x' in script_content:
                results['obfuscated_javascript'] = True
                break

    return results
