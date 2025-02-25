#test_scanner
import unittest
import os
from leakhunter.scanner import find_sensitive_data
from leakhunter.yara_scanner import load_yara_rules, scan_with_yara

class TestScanner(unittest.TestCase):
    def setUp(self):
        
        self.test_file = "test_file.txt"
        with open(self.test_file, "w") as f:
            f.write("email=test@example.com\n")
            f.write("password=securepassword123\n")
            f.write("credit_card=1234-5678-9012-3456\n")
            f.write("api_key=1234567890abcdef\n")

    def tearDown(self):
        # Clean up the test file
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_regex_scanner(self):
        # Test regex-based scanning
        results = find_sensitive_data(self.test_file)
        self.assertEqual(len(results), 4) 

    def test_yara_scanner(self):
        # Test YARA-based scanning
        rules = load_yara_rules("rules/sensitive_data.yar")
        self.assertIsNotNone(rules)  
        results = scan_with_yara(self.test_file, rules)
        self.assertEqual(len(results), 4)  

if __name__ == "__main__":
    unittest.main()
