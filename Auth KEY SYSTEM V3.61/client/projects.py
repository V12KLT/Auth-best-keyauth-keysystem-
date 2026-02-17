import os
import time
import datetime
import secrets
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner, validate_input
except ImportError:
    from connection import get_client
    from ui import print_banner, validate_input

project_name = ""
project_id = ""

def get_project_id():
    global project_id
    return project_id

def set_project_id(new_id):
    global project_id
    project_id = new_id

def get_project_name():
    global project_name
    return project_name

def set_project_name(new_name):
    global project_name
    project_name = new_name

def create_project():
    client = get_client()
    os.system("cls")
    print_banner("CREATE NEW PROJECT")
    print()
    
    project = input(f"{Fore.CYAN}┌─[{Fore.WHITE}Project Name{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
    client.send(project.encode("utf-8"))
    response = client.recv(1024).decode("utf-8")
    print(f"\n{Fore.GREEN}{response}{Fore.RESET}")
    time.sleep(2)

def select_project():
    global project_name, project_id
    client = get_client()
    try:
        projects = client.recv(4096).decode("utf-8")
        
        if not projects or projects == "NO_PROJECTS":
            print(f"{Fore.RED}No projects found! Create one first.{Fore.RESET}")
            time.sleep(2)
            return False
        
        project_list = []
        for proj in projects.split("|"):
            if ":" in proj:
                name, pid = proj.split(":")
                project_list.append((name, pid))
        
        if not project_list:
             print(f"{Fore.RED}No valid projects found.{Fore.RESET}")
             time.sleep(2)
             return False

        os.system("cls")
        print_banner("YOUR PROJECTS")
        print()
        
        for i, (name, pid) in enumerate(project_list, 1):
            print(f"{Fore.CYAN}  [{Fore.WHITE}{i}{Fore.CYAN}] ➤ {Fore.WHITE}{name}{Fore.RESET}")
        
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        try:
            choice = int(input(f"{Fore.CYAN}└──➤ Select project number: {Fore.WHITE}"))
            if 1 <= choice <= len(project_list):
                project_name, project_id = project_list[choice - 1]
                client.send("select_project".encode("utf-8"))
                time.sleep(0.1)
                client.send(project_id.encode("utf-8"))
                return True
            else:
                print(f"{Fore.RED}Invalid choice!{Fore.RESET}")
                time.sleep(2)
                return False
        except ValueError:
            print(f"{Fore.RED}Invalid input!{Fore.RESET}")
            time.sleep(2)
            return False
    except Exception as e:
        print(f"{Fore.RED}Error selecting project: {e}{Fore.RESET}")
        time.sleep(2)
        return False

def delete_project_ui():
    client = get_client()
    projects = client.recv(4096).decode("utf-8")
    if not projects:
        print(f"{Fore.RED}No projects found.{Fore.RESET}")
        time.sleep(2)
        return

    project_list = []
    for proj in projects.split("|"):
        if ":" in proj:
            name, pid = proj.split(":")
            project_list.append((name, pid))
    
    os.system("cls")
    print_banner("DELETE PROJECT")
    print()
    
    for i, (name, pid) in enumerate(project_list, 1):
        print(f"{Fore.CYAN}  [{Fore.WHITE}{i}{Fore.CYAN}] ➤ {Fore.WHITE}{name}{Fore.RESET}")
    
    print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
    try:
        choice = int(input(f"{Fore.CYAN}└──➤ Select project to DELETE: {Fore.WHITE}"))
        if 1 <= choice <= len(project_list):
            name, pid = project_list[choice - 1]
            confirm = input(f"{Fore.RED}Type '{name}' to confirm deletion: {Fore.WHITE}")
            if confirm == name:
                client.send("select_project".encode("utf-8"))
                client.send(pid.encode("utf-8"))
                
                client.send("delete_project".encode("utf-8"))
                resp = client.recv(1024).decode("utf-8")
                if resp == "PROJECT_DELETED":
                    print(f"\n{Fore.GREEN}Project deleted successfully.{Fore.RESET}")
                elif resp == "PERMISSION_DENIED":
                    print(f"\n{Fore.RED}Permission denied.{Fore.RESET}")
                time.sleep(2)
            else:
                print(f"{Fore.RED}Deletion cancelled.{Fore.RESET}")
                time.sleep(2)
    except:
        pass

def project_settings_menu():
    global project_id
    client = get_client()
    while True:
        os.system("cls")
        print_banner("PROJECT SETTINGS")
        print(f"\n{Fore.CYAN}  Current Project ID: {Fore.GREEN}{project_id}{Fore.RESET}")
        print()
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Rename Project")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Transfer Ownership")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Manage Permissions")
        print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}App Variables")
        print(f"{Fore.CYAN}  [5] ➤ {Fore.WHITE}Set Grace Period")
        print(f"{Fore.CYAN}  [6] ➤ {Fore.WHITE}Set Max Sessions")
        print(f"{Fore.CYAN}  [7] ➤ {Fore.WHITE}Delete Project")
        print(f"{Fore.CYAN}  [8] ➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
        
        if choice == "1":
            new_name = validate_input(f"\n{Fore.CYAN}New Project Name: {Fore.WHITE}", r'^[a-zA-Z0-9_-]+$', 3, 32)
            client.send(f"rename_project|{new_name}".encode())
            resp = client.recv(1024).decode()
            print(f"\n{Fore.BLUE}{resp}{Fore.RESET}")
            time.sleep(1)
            
        elif choice == "2":
            new_owner = validate_input(f"\n{Fore.CYAN}New Owner Username: {Fore.WHITE}")
            confirm = input(f"{Fore.RED}Are you sure? checking owner... (y/n): {Fore.WHITE}")
            if confirm.lower() == 'y':
                client.send(f"transfer_project|{new_owner}".encode())
                resp = client.recv(1024).decode()
                print(f"\n{Fore.BLUE}{resp}{Fore.RESET}")
                if resp == "SUCCESS":
                    return 
            time.sleep(1)
            
        elif choice == "3":
             while True:
                os.system("cls")
                print_banner("MANAGE PERMISSIONS")
                print()
                print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Add Permission (Admin/Viewer)")
                print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Remove Permission")
                print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Back")
                print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
                
                p_choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
                
                if p_choice == "1":
                    user = validate_input(f"\n{Fore.CYAN}Username: {Fore.WHITE}")
                    role = input(f"{Fore.CYAN}Role (admin/viewer): {Fore.WHITE}").lower()
                    if role not in ["admin", "viewer"]:
                        print(f"{Fore.RED}Invalid role.{Fore.RESET}")
                    else:
                        client.send(f"add_permission|{user}|{role}".encode())
                        print(f"{Fore.GREEN}Request sent.{Fore.RESET}")
                    time.sleep(1)
                elif p_choice == "2":
                    user = validate_input(f"\n{Fore.CYAN}Username to remove: {Fore.WHITE}")
                    client.send(f"remove_permission|{user}".encode())
                    print(f"{Fore.GREEN}Request sent.{Fore.RESET}")
                    time.sleep(1)
                elif p_choice == "3":
                    break

        elif choice == "4":
            variable_management_menu()
            
        elif choice == "5":
             try:
                 period = int(input(f"\n{Fore.CYAN}Enter Grace Period (seconds): {Fore.WHITE}"))
                 client.send(f"set_grace_period|{period}".encode())
                 print(f"{Fore.GREEN}Grace period updated for all keys.{Fore.RESET}")
             except:
                 print(f"{Fore.RED}Invalid input.{Fore.RESET}")
             time.sleep(1)

        elif choice == "6":
             try:
                 sess = int(input(f"\n{Fore.CYAN}Enter Max Sessions (1-100): {Fore.WHITE}"))
                 client.send(f"set_max_sessions|{sess}".encode())
                 print(f"{Fore.GREEN}Max sessions updated for all keys.{Fore.RESET}")
             except:
                 print(f"{Fore.RED}Invalid input.{Fore.RESET}")
             time.sleep(1)

        elif choice == "7":
            confirm = input(f"\n{Fore.RED}Type 'DELETE' to confirm project deletion: {Fore.WHITE}")
            if confirm == "DELETE":
                client.send("delete_project".encode())
                resp = client.recv(1024).decode()
                if resp == "PROJECT_DELETED":
                    print(f"\n{Fore.GREEN}Project deleted.{Fore.RESET}")
                    time.sleep(2)
                    return "DELETED"
                else:
                    print(f"\n{Fore.RED}{resp}{Fore.RESET}")
                    time.sleep(2)
        elif choice == "8":
            break

def Statistics():
    client = get_client()
    os.system("cls")
    print_banner("PROJECT STATISTICS")
    
    client.send("Statistics".encode("utf-8"))
    data = client.recv(4096).decode("utf-8")
    parts = data.split("|")

    online_count = "0"
    ips = "No IPs connected right now"
    number_of_keys = "0"
    number_of_keys_used = "0"

    try:
        if len(parts) > 0:
            online_count = parts[0]
        if len(parts) > 1:
            ips = parts[1]
        if len(parts) > 2:
            number_of_keys = parts[2]
        if len(parts) > 3:
            number_of_keys_used = parts[3]
    except Exception as e:
        pass

    print(f"\n{Fore.CYAN}  ➤ {Fore.WHITE}Online clients:  {Fore.GREEN}{online_count}{Fore.RESET}")
    time.sleep(0.2)

    print(f"{Fore.CYAN}  ➤ {Fore.WHITE}Connected IPs:   {Fore.CYAN}{ips}{Fore.RESET}")
    time.sleep(0.3)

    print(f"{Fore.CYAN}  ➤ {Fore.WHITE}Total keys:      {Fore.YELLOW}{number_of_keys}{Fore.RESET}")
    time.sleep(0.4)

    print(f"{Fore.CYAN}  ➤ {Fore.WHITE}Keys used:       {Fore.MAGENTA}{number_of_keys_used}{Fore.RESET}")

    input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to return...{Fore.RESET}")

def variable_management_menu():
    client = get_client()
    while True:
        os.system("cls")
        print_banner("APP VARIABLES")
        print()
        
        client.send("list_variables".encode())
        data = b""
        while True:
            part = client.recv(4096)
            if not part: break
            data += part
            if b"<END_OF_VARS>" in data: break
        
        decoded = data.decode().replace("<END_OF_VARS>", "").strip()
        vars = decoded.splitlines() if decoded else []
        
        print(f"{Fore.CYAN}  Current Variables:{Fore.RESET}")
        if vars:
            for v in vars:
                if ":" in v:
                    name, val = v.split(":", 1)
                    print(f"  {Fore.GREEN}• {Fore.WHITE}{name}: {Fore.BLUE}{val}{Fore.RESET}")
        else:
            print(f"  {Fore.LIGHTBLACK_EX}No variables set{Fore.RESET}")
            
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Set/Update Variable")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
        
        if choice == "1":
            var_name = validate_input(f"\n{Fore.CYAN}Variable Name: {Fore.WHITE}", r'^[a-zA-Z0-9_-]+$', 1, 64)
            var_value = input(f"{Fore.CYAN}Variable Value: {Fore.WHITE}")
            client.send(f"set_variable|{var_name}|{var_value}".encode())
            resp = client.recv(1024).decode()
            if resp == "VARIABLE_SET":
                print(f"{Fore.GREEN}Variable set successfully.{Fore.RESET}")
            else:
                print(f"{Fore.RED}Error: {resp}{Fore.RESET}")
            time.sleep(1)
        elif choice == "2":
            break

def recent_activity():
    client = get_client()
    os.system("cls")
    print_banner("RECENT ACTIVITY")
    
    client.send("recent_activity".encode("utf-8"))
    data = b""
    while True:
        part = client.recv(4024)
        if not part:
            break
        data += part
        if b"<END_OF_ACTIVITY>" in data:
            break
    
    decoded_data = data.decode("utf-8").replace("<END_OF_ACTIVITY>", "")
    print()
    if decoded_data.strip():
        print(Fore.WHITE + decoded_data + Fore.RESET)
    else:
        print(Fore.LIGHTBLACK_EX + "  No recent activity" + Fore.RESET)
    
    input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to return...{Fore.RESET}")

def ip_whitelist_menu():
    client = get_client()
    while True:
        os.system("cls")
        print_banner("IP WHITELIST MANAGEMENT")
        print()
        
        client.send("list_ips".encode("utf-8"))
        data = b""
        while True:
            part = client.recv(4096)
            if not part: break
            data += part
            if b"<END_OF_IPS>" in data: break
        
        decoded = data.decode("utf-8").replace("<END_OF_IPS>", "").strip()
        ips = decoded.splitlines() if decoded else []
        
        print(f"{Fore.CYAN}  Current Whitelisted IPs:{Fore.RESET}")
        if ips:
            for ip in ips:
                print(f"  {Fore.GREEN}• {Fore.WHITE}{ip}{Fore.RESET}")
        else:
            print(f"  {Fore.LIGHTBLACK_EX}No IPs whitelisted{Fore.RESET}")
            
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Add IP")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Remove IP")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
        
        if choice == "1":
            ip = validate_input(f"\n{Fore.CYAN}Enter IP to add: {Fore.WHITE}")
            client.send(f"add_ip|{ip}".encode())
        elif choice == "2":
            ip = validate_input(f"\n{Fore.CYAN}Enter IP to remove: {Fore.WHITE}")
            client.send(f"remove_ip|{ip}".encode())
        elif choice == "3":
            break

def analytics_menu():
    client = get_client()
    os.system("cls")
    print_banner("USAGE ANALYTICS")
    print()
    
    client.send("usage_analytics".encode("utf-8"))
    
    data = b""
    while True:
        part = client.recv(4096)
        if not part: break
        data += part
        break
    
    csv_text = data.decode("utf-8")
    lines = csv_text.splitlines()
    
    if len(lines) > 1:
        headers = lines[0].split(',')
        print(f"{Fore.CYAN}{headers[0]:<20} {headers[1]:<15} {headers[2]}{Fore.RESET}")
        print(f"{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) >= 3:
                ts = parts[0]
                try:
                    dt = datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
                except:
                    dt = ts
                print(f"{Fore.WHITE}{dt:<20} {Fore.YELLOW}{parts[1]:<15} {Fore.WHITE}{parts[2]}{Fore.RESET}")
    else:
        print(f"{Fore.RED}No analytics data available.{Fore.RESET}")
    
    input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to return...{Fore.RESET}")

def get_project_id_for_code():
    client = get_client()
    os.system("cls")
    print_banner("PROJECT ID")
    
    client.send("get_project_id".encode("utf-8"))
    proj_id = client.recv(1024).decode("utf-8")
    print(f"\n{Fore.CYAN}  ➤ {Fore.WHITE}Your Project ID: {Fore.GREEN}{proj_id}{Fore.RESET}")
    input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to continue...{Fore.RESET}")
