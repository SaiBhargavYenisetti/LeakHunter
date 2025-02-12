from colorama import Fore, Style

def log_error(message):
    print(Fore.RED + f"[ERROR] {message}" + Style.RESET_ALL)

def log_info(message):
    print(Fore.BLUE + f"[INFO] {message}" + Style.RESET_ALL)

def log_success(message):
    print(Fore.GREEN + f"[SUCCESS] {message}" + Style.RESET_ALL)