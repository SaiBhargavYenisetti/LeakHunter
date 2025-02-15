import os
import logging
from colorama import Fore, Style

def setup_logging(level=logging.INFO):
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def is_binary_file(file_path):
    """Check if a file is binary"""
    try:
        with open(file_path, 'tr') as check_file:
            check_file.read(1024)
            return False
    except UnicodeDecodeError:
        return True

def format_finding(finding_type, file_path, line_no, match):
    """Format a finding for output"""
    return {
        'type': finding_type,
        'file': file_path,
        'line': line_no,
        'match': match,
    }

def print_finding(finding):
    """Print a formatted finding"""
    color = {
        'API Key': Fore.RED,
        'Password': Fore.RED,
        'Email': Fore.YELLOW,
        'Credit Card': Fore.RED,
    }.get(finding['type'], Fore.WHITE)
    
    print(f"{color}[LEAK] {finding['type']} found in {finding['file']} "
          f"(Line {finding['line']}): {finding['match']}{Style.RESET_ALL}")