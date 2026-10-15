"""
rules/allowlist.py
==================
Pre-filter Allowlist Module using Tranco Top 10k list.
Accurately extracts eTLD+1 root domains using tldextract and performs O(1)
lookups against an in-memory set to prevent false-positive heuristic penalties
for verified global and enterprise domains.
"""

import os
import urllib.parse
import logging
import tldextract

logger = logging.getLogger(__name__)

# Fallback set of hardcoded top domains in case the local Tranco dataset file is missing
FALLBACK_TOP_DOMAINS = {
    # Tech & Cloud Giants
    "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr",
    "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "youtu.be",
    "microsoft.com", "office.com", "live.com", "bing.com", "azure.com", "windows.com",
    "apple.com", "icloud.com", "apple-dns.net",
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "aws.amazon.com",
    "cloudflare.com", "cloudflare-dns.com",
    
    # Enterprise & Creative Software
    "adobe.com", "behance.net", "typekit.net",
    "salesforce.com", "force.com",
    "oracle.com", "ibm.com", "cisco.com", "intel.com", "nvidia.com", "dell.com", "hp.com",
    "github.com", "github.io", "gitlab.com", "bitbucket.org", "atlassian.com", "jira.com",
    "stackoverflow.com", "stackexchange.com",
    "zoom.us", "slack.com", "notion.so", "figma.com", "canva.com", "dropbox.com", "box.com",
    
    # E-Commerce & Retail (Addresses enterprise false positives like flipkart.com)
    "flipkart.com", "flipkart.co.in",
    "walmart.com", "ebay.com", "target.com", "bestbuy.com", "etsy.com", "aliexpress.com",
    "myntra.com", "snapdeal.com", "paytmmall.com",
    
    # Social & Communications
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "threads.net",
    "twitter.com", "x.com", "twimg.com", "linkedin.com", "licdn.com",
    "reddit.com", "redditmedia.com", "tiktok.com", "pinterest.com",
    "telegram.org", "discord.com", "discordapp.com",
    
    # Financial Services & Payment Processors
    "paypal.com", "paypalobjects.com", "stripe.com",
    "visa.com", "mastercard.com", "americanexpress.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "citi.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in",
    
    # Streaming & Media & Reference
    "netflix.com", "nflxvideo.net", "spotify.com", "hulu.com", "disneyplus.com",
    "wikipedia.org", "wikimedia.org", "yahoo.com", "cnn.com", "bbc.com", "nytimes.com",
    
    # Infrastructure & CDN
    "akamai.net", "akamaiedge.net", "fastly.net", "cloudfront.net"
}

def extract_etld_plus_one(url: str) -> str:
    """
    Accurately extracts the eTLD+1 root domain (effective Top-Level Domain plus one label)
    using tldextract, correctly handling multi-part suffixes like .co.in, .com.au, .co.uk.
    
    Examples:
        - "https://subdomain.adobe.com/path" -> "adobe.com"
        - "https://www.flipkart.co.in/account" -> "flipkart.co.in"
        - "google.com" -> "google.com"
    """
    if not url:
        return ""
        
    try:
        extracted = tldextract.extract(url)
        registered_domain = extracted.registered_domain
        if registered_domain:
            return registered_domain.lower().strip()
            
        # Fallback for plain domain names, IP addresses, or localhost
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.netloc or parsed.path).split('/')[0].split(':')[0].strip().lower()
        return host
    except Exception as e:
        logger.warning(f"Error extracting root domain from '{url}': {e}")
        return ""

def _find_tranco_file() -> str:
    """
    Locates the Tranco top 10k dataset file on disk across common candidate paths
    or an optional environment variable TRANCO_LIST_PATH.
    """
    env_path = os.environ.get("TRANCO_LIST_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
        
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "..", "data", "tranco_top10k.csv"),
        os.path.join(base_dir, "..", "data", "tranco_top10k.txt"),
        os.path.join(base_dir, "..", "config", "tranco_top10k.csv"),
        os.path.join(base_dir, "..", "config", "tranco_top10k.txt"),
        os.path.join(os.getcwd(), "data", "tranco_top10k.csv"),
        os.path.join(os.getcwd(), "tranco_top10k.csv"),
    ]
    
    for candidate in candidates:
        norm_path = os.path.normpath(candidate)
        if os.path.isfile(norm_path):
            return norm_path
            
    return ""

def load_allowlist(file_path: str = None) -> set:
    """
    Loads top domains from a local CSV or text file into an in-memory set.
    Supports both Tranco CSV format ('rank,domain') and plain text (one domain per line).
    Merges with the hardcoded fallback set to guarantee enterprise availability.
    """
    target_path = file_path or _find_tranco_file()
    allowlist = set(FALLBACK_TOP_DOMAINS)
    
    if not target_path:
        logger.warning("Tranco dataset file not found. Initialized allowlist with hardcoded fallback domains.")
        return allowlist
        
    try:
        loaded_count = 0
        with open(target_path, mode='r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Support CSV format (rank,domain) or single domain per line
                parts = line.split(',')
                domain = parts[1].strip().lower() if len(parts) > 1 else parts[0].strip().lower()
                
                # Filter out header rows like "rank,domain"
                if domain and '.' in domain and domain != "domain":
                    allowlist.add(domain)
                    loaded_count += 1
                    
        logger.info(f"Loaded {loaded_count} domains from '{target_path}'. Total allowlist size: {len(allowlist)}.")
    except Exception as e:
        logger.error(f"Error loading allowlist from '{target_path}': {e}. Using fallback set.")
        
    return allowlist

# Global in-memory set loaded at startup for O(1) membership queries
ALLOWLIST: set = load_allowlist()

def is_allowlisted(url: str) -> bool:
    """
    Checks if the eTLD+1 root domain of the given URL is in the in-memory allowlist.
    Returns True for verified global/enterprise domains, False otherwise.
    
    Complexity: O(1) set lookup after eTLD+1 extraction.
    """
    if not url:
        return False
        
    root_domain = extract_etld_plus_one(url)
    if not root_domain:
        return False
        
    return root_domain in ALLOWLIST

def get_registered_domain(url: str) -> str:
    """Convenience alias for root domain extraction."""
    return extract_etld_plus_one(url)
