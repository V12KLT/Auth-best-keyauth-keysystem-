import os
import json
import base64
import time
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner
except ImportError:
    from connection import get_client
    from ui import print_banner


def files_menu():
    client = get_client()

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    while True:
        clear()
        print_banner("SECURE FILE DELIVERY")
        print()
        print(f"{Fore.CYAN}  [1] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}List Files")
        print(f"{Fore.CYAN}  [2] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Upload File")
        print(f"{Fore.CYAN}  [3] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Delete File")
        print(f"{Fore.CYAN}  [4] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Toggle File (Enable/Disable)")
        print(f"{Fore.CYAN}  [5] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")

        choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")

        if choice == "1":
            _list_files(client)
        elif choice == "2":
            _upload_file(client)
        elif choice == "3":
            _delete_file(client)
        elif choice == "4":
            _toggle_file(client)
        elif choice == "5":
            return


def _list_files(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("LIST FILES")
    print()
    client.send("list_files".encode("utf-8"))
    data = ""
    while "<END_OF_FILES>" not in data:
        chunk = client.recv(4096).decode("utf-8")
        if not chunk:
            break
        data += chunk

    data = data.replace("\n<END_OF_FILES>", "").replace("<END_OF_FILES>", "").strip()
    if not data:
        print(f"{Fore.YELLOW}  No files uploaded yet.{Fore.RESET}")
    else:
        try:
            files = json.loads(data)
            for f in files:
                name = f.get("name", "?")
                desc = f.get("description", "")
                size = f.get("size", 0)
                active = f.get("active", True)
                downloads = f.get("downloads", 0)
                status = "active" if active else "disabled"
                status_color = Fore.GREEN if active else Fore.RED
                size_str = _format_size(size)
                print(f"  {status_color}●{Fore.WHITE} {name}{Fore.LIGHTBLACK_EX}  {desc}  ({size_str})  [{status}]  ↓{downloads}{Fore.RESET}")
        except (json.JSONDecodeError, TypeError):
            for line in data.splitlines():
                if line.strip():
                    print(f"  {Fore.WHITE}{line}{Fore.RESET}")

    print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
    input(f"{Fore.LIGHTBLACK_EX}  Press Enter to continue...{Fore.RESET}")


def _format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def _upload_file(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("UPLOAD FILE")
    print()

    file_path = input(f"{Fore.CYAN}  Path to file: {Fore.WHITE}").strip().strip('"')
    if not file_path or not os.path.isfile(file_path):
        print(f"{Fore.RED}  File not found.{Fore.RESET}")
        time.sleep(2)
        return

    name = input(f"{Fore.CYAN}  Name to store as (e.g. payload.dll): {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    desc = input(f"{Fore.CYAN}  Description (optional): {Fore.WHITE}").strip()

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except Exception as e:
        print(f"{Fore.RED}  Could not read file: {e}{Fore.RESET}")
        time.sleep(2)
        return

    b64 = base64.b64encode(raw).decode("utf-8")
    print(f"\n{Fore.CYAN}  Uploading {_format_size(len(raw))}...{Fore.RESET}")

    header = f"upload_file|{name}|{desc}|{len(b64)}"
    client.send(header.encode("utf-8"))

    ack = ""
    try:
        ack = client.recv(4096).decode("utf-8")
    except Exception:
        pass

    if ack != "READY":
        if ack.startswith("ERROR"):
            msg = ack.split("|", 1)[1] if "|" in ack else ack
            print(f"\n  {Fore.RED}{msg}{Fore.RESET}")
        else:
            print(f"\n  {Fore.RED}Server: {ack}{Fore.RESET}")
        time.sleep(2)
        return

    b64_bytes = b64.encode("utf-8")
    offset = 0
    chunk_size = 32768
    while offset < len(b64_bytes):
        end = min(offset + chunk_size, len(b64_bytes))
        client.send(b64_bytes[offset:end])
        offset = end

    resp = ""
    try:
        resp = client.recv(4096).decode("utf-8")
    except Exception:
        pass

    if resp.startswith("FILE_UPLOADED"):
        parts = resp.split("|")
        file_hash = parts[2] if len(parts) > 2 else ""
        print(f"\n  {Fore.GREEN}File uploaded successfully!{Fore.RESET}")
        if file_hash:
            print(f"  {Fore.LIGHTBLACK_EX}SHA256: {file_hash}{Fore.RESET}")
    elif resp.startswith("FILE_UPDATED"):
        print(f"\n  {Fore.GREEN}File replaced successfully!{Fore.RESET}")
    elif resp.startswith("ERROR"):
        msg = resp.split("|", 1)[1] if "|" in resp else resp
        print(f"\n  {Fore.RED}{msg}{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _delete_file(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("DELETE FILE")
    print()

    name = input(f"{Fore.CYAN}  File name: {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"delete_file|{name}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "FILE_DELETED":
        print(f"\n  {Fore.GREEN}File deleted.{Fore.RESET}")
    elif resp == "FILE_NOT_FOUND":
        print(f"\n  {Fore.RED}File not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _toggle_file(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("TOGGLE FILE")
    print()

    name = input(f"{Fore.CYAN}  File name: {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"toggle_file|{name}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "FILE_ENABLED":
        print(f"\n  {Fore.GREEN}File enabled.{Fore.RESET}")
    elif resp == "FILE_DISABLED":
        print(f"\n  {Fore.YELLOW}File disabled.{Fore.RESET}")
    elif resp == "FILE_NOT_FOUND":
        print(f"\n  {Fore.RED}File not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)
