import os
import time
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner
except ImportError:
    from connection import get_client
    from ui import print_banner


def webhooks_menu():
    client = get_client()

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    while True:
        clear()
        print_banner("SIGNED WEBHOOKS")
        print()
        print(f"{Fore.CYAN}  [1] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}List Webhooks")
        print(f"{Fore.CYAN}  [2] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Add Webhook")
        print(f"{Fore.CYAN}  [3] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Delete Webhook")
        print(f"{Fore.CYAN}  [4] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Toggle Webhook (Enable/Disable)")
        print(f"{Fore.CYAN}  [5] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")

        choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")

        if choice == "1":
            _list_webhooks(client)
        elif choice == "2":
            _add_webhook(client)
        elif choice == "3":
            _delete_webhook(client)
        elif choice == "4":
            _toggle_webhook(client)
        elif choice == "5":
            return


def _list_webhooks(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("LIST WEBHOOKS")
    print()
    client.send("list_webhooks".encode("utf-8"))
    data = ""
    while "<END_OF_WEBHOOKS>" not in data:
        chunk = client.recv(4096).decode("utf-8")
        if not chunk:
            break
        data += chunk

    data = data.replace("\n<END_OF_WEBHOOKS>", "").replace("<END_OF_WEBHOOKS>", "").strip()
    if not data:
        print(f"{Fore.YELLOW}  No webhooks configured yet.{Fore.RESET}")
    else:
        for line in data.splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                name, url, secret, status = parts[0], parts[1], parts[2], parts[3]
                status_color = Fore.GREEN if status == "active" else Fore.RED
                print(f"  {status_color}●{Fore.WHITE} {name}{Fore.RESET}")
                print(f"    {Fore.LIGHTBLACK_EX}URL:    {Fore.WHITE}{url}{Fore.RESET}")
                print(f"    {Fore.LIGHTBLACK_EX}Secret: {Fore.YELLOW}{secret}{Fore.RESET}")
                print(f"    {Fore.LIGHTBLACK_EX}Status: {status_color}{status}{Fore.RESET}")
                print()
            else:
                print(f"  {Fore.WHITE}{line}{Fore.RESET}")

    print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
    input(f"{Fore.LIGHTBLACK_EX}  Press Enter to continue...{Fore.RESET}")


def _add_webhook(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("ADD WEBHOOK")
    print()

    name = input(f"{Fore.CYAN}  Webhook name (alphanumeric, e.g. my-webhook): {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    url = input(f"{Fore.CYAN}  Target URL (must start with https://): {Fore.WHITE}").strip()
    if not url.startswith("https://"):
        print(f"{Fore.RED}  URL must start with https://{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"add_webhook|{name}|{url}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp.startswith("WEBHOOK_CREATED|"):
        secret = resp.split("|", 1)[1]
        print(f"\n  {Fore.GREEN}Webhook created!{Fore.RESET}")
        print(f"\n  {Fore.YELLOW}Secret (save this — it will not be shown again):{Fore.RESET}")
        print(f"\n  {Fore.WHITE}{secret}{Fore.RESET}\n")
        input(f"{Fore.LIGHTBLACK_EX}  Press Enter once you have saved the secret...{Fore.RESET}")
        return
    elif resp == "WEBHOOK_EXISTS":
        print(f"\n  {Fore.YELLOW}A webhook with that name already exists.{Fore.RESET}")
    elif resp == "WEBHOOK_LIMIT_REACHED":
        print(f"\n  {Fore.YELLOW}Webhook limit reached for this project.{Fore.RESET}")
    elif resp == "INVALID_WEBHOOK_NAME":
        print(f"\n  {Fore.RED}Invalid webhook name.{Fore.RESET}")
    elif resp == "INVALID_URL":
        print(f"\n  {Fore.RED}Invalid URL.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _delete_webhook(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("DELETE WEBHOOK")
    print()

    name = input(f"{Fore.CYAN}  Webhook name: {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"delete_webhook|{name}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "WEBHOOK_DELETED":
        print(f"\n  {Fore.GREEN}Webhook deleted.{Fore.RESET}")
    elif resp == "WEBHOOK_NOT_FOUND":
        print(f"\n  {Fore.RED}Webhook not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _toggle_webhook(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("TOGGLE WEBHOOK")
    print()

    name = input(f"{Fore.CYAN}  Webhook name: {Fore.WHITE}").strip()
    if not name:
        print(f"{Fore.RED}  Name cannot be empty.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"toggle_webhook|{name}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "WEBHOOK_ENABLED":
        print(f"\n  {Fore.GREEN}Webhook enabled.{Fore.RESET}")
    elif resp == "WEBHOOK_DISABLED":
        print(f"\n  {Fore.YELLOW}Webhook disabled.{Fore.RESET}")
    elif resp == "WEBHOOK_NOT_FOUND":
        print(f"\n  {Fore.RED}Webhook not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)
