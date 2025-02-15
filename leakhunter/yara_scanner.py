import yara
from colorama import Fore, Style

def load_yara_rules(rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
        print("[DEBUG] YARA rules loaded successfully")
        return rules
    except yara.Error as e:
        print(Fore.RED + f"[ERROR] Failed to load YARA rules: {e}" + Style.RESET_ALL)
        return None

def find_sensitive_data_yara(file_path, rules):
    findings = []
    try:
        print(f"[DEBUG] Scanning {file_path} with YARA...")
        matches = rules.match(file_path)
        if not matches:
            print(f"[DEBUG] No matches found in {file_path}")
        for match in matches:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for string in match.strings:
                offset, identifier, matched_data = string
                if isinstance(matched_data, bytes):
                    matched_data = matched_data.decode('utf-8', errors='ignore')
                
                line_no = content.count('\n', 0, offset) + 1
                findings.append((match.rule, file_path, line_no, matched_data))
                print(f"[DEBUG] Match found: Rule {match.rule}, File: {file_path}, Line: {line_no}, Data: {matched_data}")
        
        return findings
    except Exception as e:
        print(Fore.RED + f"[ERROR] YARA scan failed for {file_path}: {e}" + Style.RESET_ALL)
        return []
