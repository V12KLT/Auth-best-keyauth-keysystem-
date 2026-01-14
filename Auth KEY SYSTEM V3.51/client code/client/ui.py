import os
import re
import datetime
from colorama import Fore, init

init(autoreset=True)

def print_banner(title, width=80):
    print(Fore.CYAN + "╔" + "═" * (width - 2) + "╗")
    print(Fore.CYAN + "║" + title.center(width - 2) + "║")
    print(Fore.CYAN + "╚" + "═" * (width - 2) + "╝" + Fore.RESET)

def validate_input(prompt, regex=None, min_len=0, max_len=None):
    while True:
        value = input(prompt).strip()
        if min_len and len(value) < min_len:
            print(f"{Fore.RED}input must be at least {min_len} characters.{Fore.RESET}")
            continue
        if max_len and len(value) > max_len:
            print(f"{Fore.RED}Input must be at most {max_len} characters.{Fore.RESET}")
            continue
        if regex and not re.match(regex, value):
            print(f"{Fore.RED}Invalid format.{Fore.RESET}")
            continue
        return value

def format_timestamps_in_text(text):
    def replace_timestamp(match):
        timestamp_str = match.group(0)
        try:
            timestamp = int(timestamp_str)
            if 946684800 < timestamp < 4102444800:
                dt = datetime.datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            pass
        return timestamp_str
    
    return re.sub(r'\b\d{10}\b', replace_timestamp, text)

def colorize_keys(text):
    lines = text.split('\n')
    colored_lines = []
    for line in lines:
        if line.strip().startswith('Key:'):
            match = re.match(r'Key:\s*([^,]+),\s*HWID:\s*([^,]+),\s*Expiration:\s*(.+)', line.strip())
            if match:
                key_val = match.group(1).strip()
                hwid_val = match.group(2).strip()
                exp_val = match.group(3).strip()
                colored_line = (
                    f"{Fore.WHITE}Key: {Fore.YELLOW}{key_val}{Fore.WHITE}, "
                    f"HWID: {Fore.MAGENTA}{hwid_val}{Fore.WHITE}, "
                    f"Expiration: {Fore.GREEN}{exp_val}{Fore.RESET}"
                )
                colored_lines.append(colored_line)
            else:
                colored_lines.append(line)
        else:
            colored_lines.append(line)
    return '\n'.join(colored_lines)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def center(text, width=80):
    return text.center(width)
