import unittest
from unittest.mock import patch
from rules.allowlist import is_allowlisted, extract_etld_plus_one, ALLOWLIST
from engine.scoring import calculate_score

class TestAllowlistModule(unittest.TestCase):
    
    def test_extract_etld_plus_one(self):
        # Standard domains
        self.assertEqual(extract_etld_plus_one("https://www.google.com/path"), "google.com")
        self.assertEqual(extract_etld_plus_one("http://adobe.com"), "adobe.com")
        self.assertEqual(extract_etld_plus_one("auth.services.adobe.com"), "adobe.com")
        
        # Multi-part ccTLD suffixes (.co.in, .com.au, .co.uk)
        self.assertEqual(extract_etld_plus_one("https://www.flipkart.co.in/account"), "flipkart.co.in")
        self.assertEqual(extract_etld_plus_one("https://sub.amazon.co.uk/item"), "amazon.co.uk")
        self.assertEqual(extract_etld_plus_one("https://store.ebay.com.au/cart"), "ebay.com.au")

    def test_is_allowlisted_enterprise_domains(self):
        # Verified global enterprise domains must be True
        self.assertTrue(is_allowlisted("https://www.flipkart.com"))
        self.assertTrue(is_allowlisted("https://flipkart.co.in"))
        self.assertTrue(is_allowlisted("https://www.adobe.com"))
        self.assertTrue(is_allowlisted("https://creativecloud.adobe.com"))
        self.assertTrue(is_allowlisted("https://www.google.com"))
        self.assertTrue(is_allowlisted("https://accounts.google.com/signin"))
        
        # Random / malicious / unverified domains must be False
        self.assertFalse(is_allowlisted("http://phish-secure-login-update.xyz"))
        self.assertFalse(is_allowlisted("https://adobe-account-verify-free.top"))
        self.assertFalse(is_allowlisted("http://flipkart-offer-free-iphone.tk"))

    @patch('engine.scoring.analyze_api')
    def test_pipeline_allowlisted_bypasses_heuristics(self, mock_analyze_api):
        # External threat intelligence returns clean
        mock_analyze_api.return_value = {
            'google_safe_browsing_flagged': False,
            'virustotal_flagged': False
        }
        
        # Evaluate flipkart.com
        result = calculate_score("https://www.flipkart.com")
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['total_score'], 0)
        self.assertEqual(result['verdict'], 'Legitimate')
        self.assertEqual(result['classification'], 'SAFE')
        self.assertEqual(len(result['triggered_rules']), 0)
        self.assertIn("verified in global top allowlist", result['reasons'][0])

        # Evaluate adobe.com
        result_adobe = calculate_score("https://auth.services.adobe.com/login")
        self.assertEqual(result_adobe['score'], 0)
        self.assertEqual(result_adobe['verdict'], 'Legitimate')
        self.assertEqual(len(result_adobe['triggered_rules']), 0)

    @patch('engine.scoring.analyze_api')
    def test_pipeline_threat_intel_override_allowlist(self, mock_analyze_api):
        # Scenario: An allowlisted domain contains a malicious path or compromised redirect
        # flagged by VirusTotal or Safe Browsing
        mock_analyze_api.return_value = {
            'google_safe_browsing_flagged': True,
            'virustotal_flagged': False
        }
        
        result = calculate_score("https://google.com/compromised_path")
        # Must still be marked as Phishing with score = 100
        self.assertEqual(result['score'], 100)
        self.assertEqual(result['verdict'], 'Phishing')
        self.assertEqual(result['classification'], 'PHISHING')
        self.assertTrue(any(r['rule_name'] == 'google_safe_browsing_flagged' for r in result['triggered_rules']))

if __name__ == '__main__':
    unittest.main()
