import yara
from colorama import Fore, Style

def load_yara_rules(rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
        return rules
    except yara.Error as e:
        print(Fore.RED + f"[ERROR] Failed to load YARA rules: {e}" + Style.RESET_ALL)
        return None

def scan_with_yara(file_path, rules):
    findings = []
    try:
        matches = rules.match(file_path)
        for match in matches:
            findings.append((match.rule, file_path, match.strings))
    except yara.Error as e:
        print(Fore.RED + f"[ERROR] YARA scan failed for {file_path}: {e}" + Style.RESET_ALL)
    return findings