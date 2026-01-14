import os
import time
import re
import datetime
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner, validate_input
except ImportError:
    from connection import get_client
    from ui import print_banner, validate_input

def add_key():
    client = get_client()
    os.system("cls")
    print_banner("ADD NEW KEY")
    print()
    
    enter_new_key = input(f"{Fore.CYAN}┌─[{Fore.WHITE}License Key{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
    
    os.system("cls")
    print_banner("SELECT KEY DURATION")
    print()
    print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}1 Minute")
    print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}1 Day")
    print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}1 Week")
    print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}1 Month")
    print(f"{Fore.CYAN}  [5] ➤ {Fore.WHITE}1 Year")
    print(f"{Fore.CYAN}  [6] ➤ {Fore.WHITE}Permanent")
    print(f"\n{Fore.CYAN}{'─' * 60}{Fore.RESET}")
    
    enter_time_of_key = input(f"{Fore.CYAN}└──➤ Enter option (1-6): {Fore.WHITE}")
    
    if enter_time_of_key not in ["1", "2", "3", "4", "5", "6"]:
        print(f"\n{Fore.RED}Invalid duration option.{Fore.RESET}")
        time.sleep(2)
        return
    
    dur_map = {"1": "1 minute", "2": "1 day", "3": "1 week", "4": "1 month", "5": "1 year", "6": "Perm"}
    enter_time_of_key = dur_map[enter_time_of_key]
    
    data = f"add_key|{enter_new_key}|{enter_time_of_key}"
    client.send(data.encode("utf-8"))

def remove_keys():
    client = get_client()
    print()
    key_to_delete = input(f"{Fore.CYAN}┌─[{Fore.WHITE}License Key to Delete{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
    if not key_to_delete: return
    
    confirm = input(f"{Fore.RED}Are you sure you want to delete {key_to_delete}? (yes/no): {Fore.WHITE}").lower()
    if confirm == "yes" or confirm == "y":
        client.send(f"delete_key|{key_to_delete}".encode("utf-8"))
        resp = client.recv(1024).decode()
        if resp == "KEY_DELETED":
            print(f"\n{Fore.GREEN}Deleted key.{Fore.RESET}")
        else:
            print(f"\n{Fore.RED}Failed (Key not found/Error){Fore.RESET}")
    else:
        print(f"\n{Fore.RED}Cancelled{Fore.RESET}")
    time.sleep(2)

def remove_keys_all():
    client = get_client()
    print()
    confirm = input(f"{Fore.YELLOW} Are you sure you want to remove all keys? (yes/no): {Fore.WHITE}").lower()
    if confirm == "yes" or confirm == "y":
        client.send("r_all_keys".encode("utf-8"))
        print(f"\n{Fore.GREEN} All keys removed{Fore.RESET}")
    else:
        print(f"\n{Fore.RED}Cancelled{Fore.RESET}")
    time.sleep(2)

def mass_key():
    client = get_client()
    os.system("cls")
    print_banner("MASS KEY GENERATOR")
    print()
    
    Number_of_keys = int(input(f"{Fore.CYAN}┌─[{Fore.WHITE}Number of Keys{Fore.CYAN}]\n└──➤ {Fore.WHITE}"))
    Time_of_keys = input(f"{Fore.CYAN}┌─[{Fore.WHITE}Duration (e.g., 1 day, 1 week){Fore.CYAN}]\n└──➤ {Fore.WHITE}")
    data = f"mass_key|{Number_of_keys}|{Time_of_keys}"
    client.send(data.encode("utf-8"))
    
    try:
        keys_data = b""
        while True:
            part = client.recv(4096)
            if not part:
                break
            keys_data += part
            if b"<END_OF_KEYS>" in keys_data:
                break
        
        decoded = keys_data.decode("utf-8").replace("<END_OF_KEYS>", "")
        if decoded.strip():
            os.system("cls")
            print_banner("GENERATED KEYS")
            print(f"\n{Fore.WHITE}{decoded}{Fore.RESET}")
            input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to continue...{Fore.RESET}")
    except Exception as e:
        pass

def edit_key_menu(key_val=None):
    client = get_client()
    if not key_val:
        key_val = validate_input(f"\n{Fore.CYAN}Enter License Key to edit: {Fore.WHITE}")
    
    while True:
        os.system("cls")
        print_banner(f"EDIT KEY: {key_val}")
        print()
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Extend Expiration")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Pause Key")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Unpause Key")
        print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}Edit Note")
        print(f"{Fore.CYAN}  [5] ➤ {Fore.WHITE}Set Max Sessions")
        print(f"{Fore.CYAN}  [6] ➤ {Fore.WHITE}Set Grace Period")
        print(f"{Fore.CYAN}  [7] ➤ {Fore.WHITE}Reset HWID")
        print(f"{Fore.CYAN}  [8] ➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
        
        if choice == "1":
            print(f"\n{Fore.CYAN}  [1] ➤ {Fore.WHITE}1 Minute")
            print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}1 Day")
            print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}1 Week")
            print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}1 Month")
            print(f"{Fore.CYAN}  [5] ➤ {Fore.WHITE}1 Year")
            duration_opt = input(f"{Fore.CYAN}└──➤ Add Duration: {Fore.WHITE}")
            
            dur_map = {"1": "1 minute", "2": "1 day", "3": "1 week", "4": "1 month", "5": "1 year"}
            if duration_opt in dur_map:
                client.send(f"extend_key|{key_val}|{dur_map[duration_opt]}".encode())
                print(f"{Fore.GREEN}Request sent.{Fore.RESET}")
            else:
                print(f"{Fore.RED}Invalid option.{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "2":
            client.send(f"pause_key|{key_val}".encode())
            print(f"{Fore.YELLOW}Paused.{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "3":
            client.send(f"unpause_key|{key_val}".encode())
            print(f"{Fore.GREEN}Unpaused.{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "4":
            note = input(f"{Fore.CYAN}Enter new note: {Fore.WHITE}")
            client.send(f"add_key_note|{key_val}|{note}".encode())
            print(f"{Fore.GREEN}Note updated.{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "5":
            try:
                sess = int(input(f"{Fore.CYAN}Max Sessions (1-100): {Fore.WHITE}"))
                client.send(f"set_max_sessions|{sess}".encode())
            except: pass
            print(f"{Fore.YELLOW}Global setting - moved to project settings (not implemented per key yet){Fore.RESET}")
            time.sleep(1)

        elif choice == "6":
             print(f"{Fore.YELLOW}Global setting - moved to project settings{Fore.RESET}")
             time.sleep(1)
             
        elif choice == "7":
            client.send(f"hwid|{key_val}".encode())
            print(f"{Fore.GREEN}HWID reset request sent.{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "8":
            break

def Reset_hwid():
    client = get_client()
    print()
    hwid_to_remove = input(f"{Fore.CYAN}┌─[{Fore.WHITE}License Key{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
    data = f"hwid|{hwid_to_remove}"
    client.send(data.encode("utf-8"))

def key_management_menu():
    client = get_client()
    
    def fetch_keys():
        client.send("active_keys".encode("utf-8"))
        data = b""
        while True:
            part = client.recv(4096)
            if not part: break
            data += part
            if b"<END_OF_KEYS>" in data: break
        
        text = data.decode("utf-8").replace("<END_OF_KEYS>", "")
        keys = []
        for line in text.splitlines():
            if line.strip():
                keys.append(line.strip())
        return keys

    current_keys = fetch_keys()
    filtered_keys = current_keys
    page = 1
    per_page = 10
    search_query = ""

    while True:
        os.system("cls")
        print_banner("KEY MANAGEMENT")
        print()
        
        total_pages = (len(filtered_keys) + per_page - 1) // per_page
        if total_pages == 0: total_pages = 1
        if page > total_pages: page = total_pages
        if page < 1: page = 1
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        page_items = filtered_keys[start_idx:end_idx]
        
        print(f"{Fore.CYAN}  Total Keys: {Fore.YELLOW}{len(filtered_keys)}{Fore.CYAN} | Page: {Fore.WHITE}{page}/{total_pages}{Fore.RESET}")
        if search_query:
            print(f"{Fore.CYAN}  Filter: {Fore.MAGENTA}{search_query}{Fore.RESET}")
        print(f"{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        if not page_items:
             print(f"  {Fore.LIGHTBLACK_EX}No keys found.{Fore.RESET}")
        else:
            for item in page_items:
                match = re.match(r'Key:\s*([^,]+),\s*HWID:\s*([^,]+),\s*Expiration:\s*(.+)', item)
                if match:
                    key_val = match.group(1).strip()
                    hwid_val = match.group(2).strip()
                    exp_val = match.group(3).strip()
                    print(f"  {Fore.WHITE}Key: {Fore.YELLOW}{key_val}{Fore.WHITE}, HWID: {Fore.MAGENTA}{hwid_val}{Fore.WHITE}, Expiration: {Fore.GREEN}{exp_val}{Fore.RESET}")
                else:
                    print(f"  {item}")

        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        print(f"{Fore.CYAN}  [N] ➤ Next Page       [P] ➤ Prev Page")
        print(f"{Fore.CYAN}  [S] ➤ Search/Filter   [R] ➤ Refresh List")
        print(f"{Fore.CYAN}  [A] ➤ Add Key         [D] ➤ Delete Key")
        print(f"{Fore.CYAN}  [E] ➤ Edit Key (Exp)  [M] ➤ Mass Generate")
        print(f"{Fore.CYAN}  [X] ➤ Export Keys     [I] ➤ Import Keys")
        print(f"{Fore.CYAN}  [W] ➤ Wipe All Keys   [B] ➤ Back")
        print(f"{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Action: {Fore.WHITE}").upper()
        
        if choice == "N":
            if page < total_pages: page += 1
        elif choice == "P":
            if page > 1: page -= 1
        elif choice == "S":
            search_query = input(f"{Fore.CYAN}Enter search term (empty to clear): {Fore.WHITE}")
            if search_query:
                filtered_keys = [k for k in current_keys if search_query.lower() in k.lower()]
            else:
                filtered_keys = current_keys
            page = 1
        elif choice == "R":
            current_keys = fetch_keys()
            filtered_keys = [k for k in current_keys if search_query.lower() in k.lower()] if search_query else current_keys
        elif choice == "A":
            add_key()
            current_keys = fetch_keys()
            filtered_keys = current_keys
        elif choice == "D":
            remove_keys()
            current_keys = fetch_keys()
            filtered_keys = current_keys
        elif choice == "E":
            edit_key_menu()
            current_keys = fetch_keys()
            filtered_keys = current_keys
        elif choice == "M":
            mass_key()
            current_keys = fetch_keys()
            filtered_keys = current_keys
        elif choice == "X":
            fmt = input(f"{Fore.CYAN}Export format (csv/json): {Fore.WHITE}")
            client.send(f"export_keys|{fmt}".encode())
            data = b""
            while True:
                part = client.recv(4096)
                if not part: break
                data += part
                if b"<END_OF_EXPORT>" in data: break
            export_content = data.decode().replace("<END_OF_EXPORT>", "")
            fname = f"keys_export_{int(time.time())}.{fmt}"
            with open(fname, "w") as f:
                f.write(export_content)
            print(f"\n{Fore.GREEN}Exported to {fname}{Fore.RESET}")
            time.sleep(2)
        elif choice == "I":
            path = validate_input(f"{Fore.CYAN}Enter path to file: {Fore.WHITE}")
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        content = f.read()
                    l = len(content)
                    client.send(f"import_keys".encode())
                    time.sleep(0.1)
                    client.send(str(l).encode())
                    client.recv(1024) 
                    client.send(content.encode())
                    resp = client.recv(1024).decode()
                    print(f"\n{Fore.GREEN}Server response: {resp}{Fore.RESET}")
                except Exception as e:
                    print(f"\n{Fore.RED}Error: {e}{Fore.RESET}")
            else:
                print(f"\n{Fore.RED}File not found{Fore.RESET}")
            time.sleep(2)
            current_keys = fetch_keys()
            filtered_keys = current_keys
        elif choice == "W":
             remove_keys_all()
             current_keys = fetch_keys()
             filtered_keys = current_keys
        elif choice == "B":
            break
