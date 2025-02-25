# Import core functions to make them available at the package level
import sys
sys.path.append("/home/bhargav/LeakHunter")
from .scanner import find_sensitive_data_regex  # Removed duplicate import
from .yara_scanner import find_sensitive_data_yara, load_yara_rules
from .virustotal import check_file_virustotal
from .utils import setup_logging, is_binary_file

# Package version
__version__ = "1.0.0"

# Package description
__description__ = "LeakHunter - A Simple Sensitive Data Scanner"

__all__ = [
    'find_sensitive_data_regex',
    'find_sensitive_data_yara',
    'load_yara_rules',
    'check_file_virustotal',
    'setup_logging',
    'is_binary_file'
]
