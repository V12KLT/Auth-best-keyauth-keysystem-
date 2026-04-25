import os
import time
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner, validate_input
except ImportError:
    from connection import get_client
    from ui import print_banner, validate_input

def ban_pepole():
    client = get_client()
    os.system("cls")
    print_banner("BAN USER")
    print()
    
    print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Ban by IP")
    print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Ban by Key")
    print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Ban by HWID")
    print(f"\n{Fore.CYAN}{'─' * 60}{Fore.RESET}")
    
    ban_option = input(f"{Fore.CYAN}└──➤ Your choice: {Fore.WHITE}")
    
    if ban_option == "1":
        ip_to_ban = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}IP Address{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"ban_pepole|1|{ip_to_ban}"
        client.send(data.encode("utf-8"))
    elif ban_option == "2":
        key_to_ban = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}License Key{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"ban_pepole|2|{key_to_ban}"
        client.send(data.encode("utf-8"))
    elif ban_option == "3":
        hwid_to_ban = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}HWID{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"ban_pepole|3|{hwid_to_ban}"
        client.send(data.encode("utf-8"))

def remove_bans():
    client = get_client()
    os.system("cls")
    print_banner("REMOVE BANS")
    print()
    
    print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Remove ban by IP")
    print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Remove ban by Key")
    print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}Remove ban by HWID")
    print(f"\n{Fore.CYAN}{'─' * 60}{Fore.RESET}")
    
    ban_option = input(f"{Fore.CYAN}└──➤ Your choice: {Fore.WHITE}")
    
    if ban_option == "1":
        ip_to_remove = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}IP Address{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"remove_bans|1|{ip_to_remove}"
        client.send(data.encode("utf-8"))
    elif ban_option == "2":
        key_to_remove = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}License Key{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"remove_bans|2|{key_to_remove}"
        client.send(data.encode("utf-8"))
    elif ban_option == "3":
        hwid_to_remove = input(f"\n{Fore.CYAN}┌─[{Fore.WHITE}HWID{Fore.CYAN}]\n└──➤ {Fore.WHITE}")
        data = f"remove_bans|3|{hwid_to_remove}"
        client.send(data.encode("utf-8"))

def list_bans():
    client = get_client()
    os.system("cls")
    print_banner("BAN LIST")
    
    client.send("list_bans".encode("utf-8"))
    data = b""
    while True:
        part = client.recv(4024)
        if not part:
            break
        data += part
        if b"<END_OF_BANS>" in data:
            break
    
    decoded_data = data.decode("utf-8").replace("<END_OF_BANS>", "")
    print()
    if decoded_data.strip():
        print(Fore.WHITE + decoded_data + Fore.RESET)
    else:
        print(Fore.LIGHTBLACK_EX + "  No bans found" + Fore.RESET)
    
    input(f"\n{Fore.LIGHTBLACK_EX}Press ENTER to return...{Fore.RESET}")

def ban_management_menu():
    client = get_client()
    while True:
        os.system("cls")
        print_banner("BAN MANAGEMENT")
        print()
        print(f"{Fore.CYAN}  [1] ➤ {Fore.WHITE}Ban User")
        print(f"{Fore.CYAN}  [2] ➤ {Fore.WHITE}Remove Ban")
        print(f"{Fore.CYAN}  [3] ➤ {Fore.WHITE}List Bans")
        print(f"{Fore.CYAN}  [4] ➤ {Fore.WHITE}Ban CIDR Range")
        print(f"{Fore.CYAN}  [5] ➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}└──➤ Selection: {Fore.WHITE}")
        
        if choice == "1":
            ban_pepole()
        elif choice == "2":
            remove_bans()
        elif choice == "3":
            list_bans()
        elif choice == "4":
            cidr = validate_input(f"\n{Fore.CYAN}Enter CIDR (e.g. 192.168.1.0/24): {Fore.WHITE}")
            client.send(f"ban_cidr|{cidr}".encode())
            print(f"{Fore.GREEN}Request sent.{Fore.RESET}")
            time.sleep(1)
        elif choice == "5":
            break
