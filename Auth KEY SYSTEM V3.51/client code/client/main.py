import os
import time
import datetime
from colorama import Fore

try:
    from .config import load_past_logins, get_past_login_password, delete_past_login
    from .connection import get_client
    from .ui import print_banner
    from .auth import create_account, login_account, get_username
    from .projects import (
        create_project, select_project, delete_project_ui,
        project_settings_menu, ip_whitelist_menu, analytics_menu
    )
    from .keys import key_management_menu
    from .bans import ban_management_menu
except ImportError:
    from config import load_past_logins, get_past_login_password, delete_past_login
    from connection import get_client
    from ui import print_banner
    from auth import create_account, login_account, get_username
    from projects import (
        create_project, select_project, delete_project_ui,
        project_settings_menu, ip_whitelist_menu, analytics_menu
    )
    from keys import key_management_menu
    from bans import ban_management_menu

def manage_projects():
    client = get_client()
    username = get_username()
    while True:
        os.system("cls")
        print_banner("PROJECT MANAGEMENT")
        print()
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Create Project")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Select Project")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Delete Project")
        print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}Logout")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        proj_choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")
        
        if proj_choice == "1":
            client.send("create_project".encode("utf-8"))
            create_project()
        elif proj_choice == "2":
            client.send("list_projects".encode("utf-8"))
            if select_project():
                main_menu()
        elif proj_choice == "3":
             client.send("list_projects".encode("utf-8"))
             delete_project_ui()
        elif proj_choice == "4":
             client.send("logout".encode("utf-8"))
             return
        else:
            continue

def main_menu():
    client = get_client()
    
    def get_stats():
        client.send("Statistics".encode("utf-8"))
        try:
            data = client.recv(4096).decode("utf-8")
            parts = data.split("|")
            if len(parts) >= 4:
                return parts[0], parts[1], parts[2], parts[3]
        except:
            pass
        return "0", "N/A", "0", "0"

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    def center(text, width=80):
        return text.center(width)

    while True:
        clear()
        online, ips, keys, used = get_stats()
        
        main_color = Fore.CYAN
        secondary_color = Fore.LIGHTWHITE_EX
        accent_color = Fore.LIGHTBLACK_EX

        print(main_color + center(" ████╗  ██╗   ██╗████████╗██╗  ██╗", 80))
        print(main_color + center("██╔══██╗██╗   ██╗╚══██╔══╝██║  ██║", 80))
        print(main_color + center("███████║██║   ██║   ██║   ███████║", 80))
        print(main_color + center("██╔══██║██║   ██║   ██║   ██╔══██║", 80))
        print(main_color + center("██║  ██║╚██████╔╝   ██║   ██║  ██║", 80))
        print(main_color + center("╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝", 80))
        print(accent_color + "═" * 80)

        print(f"""
        {secondary_color}[{main_color}1{secondary_color}] ➤ {Fore.WHITE}Project Settings                   {secondary_color}[{main_color}5{secondary_color}] ➤ {Fore.WHITE}IP Whitelist
        {secondary_color}[{main_color}2{secondary_color}] ➤ {Fore.WHITE}Key Management                     {secondary_color}[{main_color}6{secondary_color}] ➤ {Fore.WHITE}Switch Project / Logout
        {secondary_color}[{main_color}3{secondary_color}] ➤ {Fore.WHITE}Ban Management                     
        {secondary_color}[{main_color}4{secondary_color}] ➤ {Fore.WHITE}Analytics & Logs                   
        
        {secondary_color}Online: {Fore.GREEN}{online}{Fore.WHITE} | Keys: {Fore.YELLOW}{keys}{Fore.WHITE} | Used: {Fore.MAGENTA}{used}{Fore.RESET}""")

        print(accent_color + "═" * 80)

        try:
            enter = int(input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}"))
        except ValueError:
            continue
        except Exception as e:
            pass

        if enter == 1:
            res = project_settings_menu()
            if res == "DELETED": return 
        elif enter == 2:
            key_management_menu()
        elif enter == 3:
            ban_management_menu()
        elif enter == 4:
            analytics_menu()
        elif enter == 5:
            ip_whitelist_menu()
        elif enter == 6:
            return 

def start():
    while True:
        os.system("cls")
        print_banner("AUTHENTICATION")
        print()
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Create Account")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Login")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Past Logins")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")

        if choice == "1":
            create_account()
        elif choice == "2":
            if login_account():
                manage_projects()
        elif choice == "3":
            while True:
                past_logins = load_past_logins()
                if not past_logins:
                    print(f"\n{Fore.RED}No past logins found{Fore.RESET}")
                    time.sleep(2)
                    break
                
                os.system("cls")
                print_banner("PAST LOGINS")
                print()
                for i, login in enumerate(past_logins, 1):
                    last_login = login.get('last_login', 0)
                    date_str = datetime.datetime.fromtimestamp(last_login).strftime('%Y-%m-%d %H:%M') if last_login else "Unknown"
                    print(f"{Fore.CYAN}  [{Fore.WHITE}{i}{Fore.CYAN}] ➤ {Fore.WHITE}{login.get('username', 'Unknown')} {Fore.LIGHTBLACK_EX}({date_str}){Fore.RESET}")
                print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
                print(f"{Fore.CYAN}  [L] ➤ {Fore.WHITE}Login to account")
                print(f"{Fore.CYAN}  [D] ➤ {Fore.WHITE}Delete account")
                print(f"{Fore.CYAN}  [0] ➤ {Fore.WHITE}Go back")
                print(f"{Fore.CYAN}{'─' * 80}{Fore.RESET}")
                
                action = input(f"{Fore.CYAN}└──➤ Action: {Fore.WHITE}").upper()
                
                if action == "0":
                    break
                elif action == "L":
                    try:
                        login_choice = int(input(f"{Fore.CYAN}└──➤ Select account number to login: {Fore.WHITE}"))
                        if 1 <= login_choice <= len(past_logins):
                            selected = past_logins[login_choice - 1]
                            user = selected.get("username")
                            pwd = get_past_login_password(user)
                            if user and pwd:
                                if login_account(user, pwd):
                                    manage_projects()
                            else:
                                print(f"\n{Fore.RED}Could not retrieve saved credentials{Fore.RESET}")
                                time.sleep(2)
                        else:
                            print(f"\n{Fore.RED}Invalid selection{Fore.RESET}")
                            time.sleep(2)
                    except ValueError:
                        print(f"\n{Fore.RED}Invalid input{Fore.RESET}")
                        time.sleep(1)
                elif action == "D":
                     try:
                        login_choice = int(input(f"{Fore.CYAN}└──➤ Select account number to delete details for: {Fore.WHITE}"))
                        if 1 <= login_choice <= len(past_logins):
                             selected = past_logins[login_choice - 1]
                             user = selected.get("username")
                             delete_past_login(user)
                             print(f"\n{Fore.GREEN}Deleted saved login.{Fore.RESET}")
                             time.sleep(1)
                     except:
                        pass
                        time.sleep(2)
        else:
            continue

if __name__ == "__main__":
    start()
