import os
import time
from colorama import Fore

try:
    from .config import save_past_login
    from .connection import connect_to_server, get_client, motherboard, start_heartbeat
    from .ui import print_banner, validate_input
except ImportError:
    from config import save_past_login
    from connection import connect_to_server, get_client, motherboard, start_heartbeat
    from ui import print_banner, validate_input

username = ""
session_token = None

def get_username():
    global username
    return username

def set_username(new_username):
    global username
    username = new_username

def get_session_token():
    global session_token
    return session_token

def set_session_token(token):
    global session_token
    session_token = token

def create_account():
    global username
    try:
        connect_to_server()  
    except Exception as e:
        print(f"{Fore.RED}Failed to connect to server: {e}{Fore.RESET}")
        return
    try:
        client = get_client()
        os.system("cls")
        print_banner("CREATE NEW ACCOUNT")
        print()
        
        client.send("create_account".encode("utf-8"))
        username = validate_input(f"{Fore.CYAN}┌─[{Fore.WHITE}Username{Fore.CYAN}]\n└──➤ {Fore.WHITE}", r'^[a-zA-Z0-9_-]+$', 3, 32)
        password = validate_input(f"{Fore.CYAN}┌─[{Fore.WHITE}Password{Fore.CYAN}]\n└──➤ {Fore.WHITE}", min_len=8)
        data = f"{username}|{password}|{motherboard}"
        client.send(data.encode("utf-8"))

        resp = client.recv(4096).decode("utf-8")
        print(f"\n{Fore.GREEN} {resp}{Fore.RESET}")
        time.sleep(2)
    except Exception as e:
        time.sleep(2)
    finally:
        try:
            client.close()
        except:
            pass

def login_account(prefill_user=None, prefill_pass=None):
    global username, session_token
    try:
        connect_to_server()  
    except Exception as e:
        print(f"{Fore.RED}Failed to connect to server: {e}{Fore.RESET}")
        return False
    try:
        client = get_client()
        os.system("cls")
        print_banner("LOGIN TO YOUR ACCOUNT")
        print()
        
        client.send("login_account".encode("utf-8"))
        if prefill_user and prefill_pass:
            username = prefill_user
            password = prefill_pass
            print(f"{Fore.CYAN}Logging in as: {Fore.WHITE}{username}{Fore.RESET}")
        else:
            username = validate_input(f"{Fore.CYAN}┌─[{Fore.WHITE}Username{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
            password = validate_input(f"{Fore.CYAN}┌─[{Fore.WHITE}Password{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"{username}|{password}|{motherboard}"
        client.send(data.encode("utf-8"))

        try:
            response = client.recv(4096).decode("utf-8")
        except Exception as e:
            print(f"{Fore.RED}No response from server: {e}{Fore.RESET}")
            return False

        if response.startswith("TOKEN|"):
            parts = response.split("|")
            if len(parts) >= 2:
                session_token = parts[1]
                save_past_login(username, password)
                os.system("cls")
                print(f"\n{Fore.GREEN} Login successful!{Fore.RESET}")
                start_heartbeat()
                time.sleep(1)
                return True

        parts = response.split("|")
        if len(parts) >= 2:
            print(f"\n{Fore.RED}{parts[1]}{Fore.RESET}")
        else:
            print(f"\n{Fore.RED}Login failed{Fore.RESET}")
        client.close()
        time.sleep(2)
        return False
    except Exception as e:
        return False
