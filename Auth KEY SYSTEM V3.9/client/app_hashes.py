import os
import time
import hashlib
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner
except ImportError:
    from connection import get_client
    from ui import print_banner


def app_hashes_menu():
    client = get_client()

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    while True:
        clear()
        print_banner("APP INTEGRITY HASHES")
        print()
        print(f"{Fore.CYAN}  [1] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}List Hashes")
        print(f"{Fore.CYAN}  [2] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Add Hash (paste hex)")
        print(f"{Fore.CYAN}  [3] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Add Hash (hash a local file)")
        print(f"{Fore.CYAN}  [4] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Delete Hash")
        print(f"{Fore.CYAN}  [5] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Toggle Hash (Enable/Disable)")
        print(f"{Fore.CYAN}  [6] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")

        choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")

        if choice == "1":
            _list_hashes(client)
        elif choice == "2":
            _add_hash_manual(client)
        elif choice == "3":
            _add_hash_from_file(client)
        elif choice == "4":
            _delete_hash(client)
        elif choice == "5":
            _toggle_hash(client)
        elif choice == "6":
            return


def _list_hashes(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("LIST APP HASHES")
    print()
    client.send("list_app_hashes".encode("utf-8"))
    data = ""
    while "<END_OF_HASHES>" not in data:
        chunk = client.recv(4096).decode("utf-8")
        if not chunk:
            break
        data += chunk

    data = data.replace("\n<END_OF_HASHES>", "").replace("<END_OF_HASHES>", "").strip()
    if not data:
        print(f"{Fore.YELLOW}  No app hashes registered yet.{Fore.RESET}")
        print(f"\n{Fore.LIGHTBLACK_EX}  When no hashes are registered, the app hash check is disabled.{Fore.RESET}")
    else:
        for line in data.splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                hash_val, desc, status = parts[0], parts[1], parts[2]
                status_color = Fore.GREEN if status == "active" else Fore.RED
                print(f"  {status_color}●{Fore.WHITE} {hash_val[:16]}...{hash_val[-8:]}{Fore.RESET}")
                if desc:
                    print(f"    {Fore.LIGHTBLACK_EX}{desc}  [{status}]{Fore.RESET}")
                else:
                    print(f"    {Fore.LIGHTBLACK_EX}[{status}]{Fore.RESET}")
                print()
            else:
                print(f"  {Fore.WHITE}{line}{Fore.RESET}")

    print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
    input(f"{Fore.LIGHTBLACK_EX}  Press Enter to continue...{Fore.RESET}")


def _add_hash_manual(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("ADD APP HASH")
    print()

    hash_val = input(f"{Fore.CYAN}  SHA-256 hex (64 chars): {Fore.WHITE}").strip().lower()
    if len(hash_val) != 64 or not all(c in "0123456789abcdef" for c in hash_val):
        print(f"{Fore.RED}  Invalid SHA-256 hash. Must be 64 hex characters.{Fore.RESET}")
        time.sleep(2)
        return

    desc = input(f"{Fore.CYAN}  Description (e.g. v1.0.0): {Fore.WHITE}").strip()

    _send_add_hash(client, hash_val, desc)


def _add_hash_from_file(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("HASH LOCAL FILE")
    print()

    file_path = input(f"{Fore.CYAN}  Path to file (e.g. MyApp.exe): {Fore.WHITE}").strip().strip('"')
    if not file_path or not os.path.isfile(file_path):
        print(f"{Fore.RED}  File not found.{Fore.RESET}")
        time.sleep(2)
        return

    print(f"\n{Fore.CYAN}  Hashing...{Fore.RESET}")
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        hash_val = sha256.hexdigest()
    except Exception as e:
        print(f"{Fore.RED}  Could not hash file: {e}{Fore.RESET}")
        time.sleep(2)
        return

    print(f"\n  {Fore.WHITE}SHA-256: {Fore.YELLOW}{hash_val}{Fore.RESET}")
    desc = input(f"\n{Fore.CYAN}  Description (e.g. v1.0.0): {Fore.WHITE}").strip()

    _send_add_hash(client, hash_val, desc)


def _send_add_hash(client, hash_val, desc):
    client.send(f"add_app_hash|{hash_val}|{desc}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "HASH_ADDED":
        print(f"\n  {Fore.GREEN}Hash registered successfully!{Fore.RESET}")
    elif resp == "HASH_EXISTS":
        print(f"\n  {Fore.YELLOW}This hash is already registered.{Fore.RESET}")
    elif resp == "HASH_LIMIT_REACHED":
        print(f"\n  {Fore.YELLOW}Hash limit reached for this project.{Fore.RESET}")
    elif resp == "INVALID_HASH":
        print(f"\n  {Fore.RED}Invalid hash format.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _delete_hash(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("DELETE APP HASH")
    print()

    hash_val = input(f"{Fore.CYAN}  SHA-256 hex to delete: {Fore.WHITE}").strip().lower()
    if len(hash_val) != 64 or not all(c in "0123456789abcdef" for c in hash_val):
        print(f"{Fore.RED}  Invalid SHA-256 hash.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"delete_app_hash|{hash_val}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "HASH_DELETED":
        print(f"\n  {Fore.GREEN}Hash deleted.{Fore.RESET}")
    elif resp == "HASH_NOT_FOUND":
        print(f"\n  {Fore.RED}Hash not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _toggle_hash(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("TOGGLE APP HASH")
    print()

    hash_val = input(f"{Fore.CYAN}  SHA-256 hex to toggle: {Fore.WHITE}").strip().lower()
    if len(hash_val) != 64 or not all(c in "0123456789abcdef" for c in hash_val):
        print(f"{Fore.RED}  Invalid SHA-256 hash.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"toggle_app_hash|{hash_val}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "HASH_ENABLED":
        print(f"\n  {Fore.GREEN}Hash enabled.{Fore.RESET}")
    elif resp == "HASH_DISABLED":
        print(f"\n  {Fore.YELLOW}Hash disabled.{Fore.RESET}")
    elif resp == "HASH_NOT_FOUND":
        print(f"\n  {Fore.RED}Hash not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)
