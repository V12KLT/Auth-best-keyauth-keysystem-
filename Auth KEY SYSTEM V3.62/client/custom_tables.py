import os
import re
import json
import time
from colorama import Fore

try:
    from .connection import get_client
    from .ui import print_banner
except ImportError:
    from connection import get_client
    from ui import print_banner


def custom_tables_menu():
    client = get_client()

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    while True:
        clear()
        print_banner("CUSTOM TABLES")
        print()
        print(f"{Fore.CYAN}  [1] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}List Tables")
        print(f"{Fore.CYAN}  [2] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Create Table")
        print(f"{Fore.CYAN}  [3] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Browse Table Data")
        print(f"{Fore.CYAN}  [4] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Add Row")
        print(f"{Fore.CYAN}  [5] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Update Row")
        print(f"{Fore.CYAN}  [6] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Delete Row")
        print(f"{Fore.CYAN}  [7] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Delete Table")
        print(f"{Fore.CYAN}  [8] {Fore.LIGHTWHITE_EX}➤ {Fore.WHITE}Back")
        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")

        choice = input(f"{Fore.CYAN}└──➤ Your selection: {Fore.WHITE}")

        if choice == "1":
            _list_tables(client)
        elif choice == "2":
            _create_table(client)
        elif choice == "3":
            _browse_table(client)
        elif choice == "4":
            _add_row(client)
        elif choice == "5":
            _update_row(client)
        elif choice == "6":
            _delete_row(client)
        elif choice == "7":
            _delete_table(client)
        elif choice == "8":
            return


def _list_tables(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("CUSTOM TABLES")
    print()
    client.send("list_custom_tables".encode("utf-8"))
    data = ""
    while "<END_OF_TABLES>" not in data:
        chunk = client.recv(4096).decode("utf-8")
        if not chunk:
            break
        data += chunk

    data = data.replace("\n<END_OF_TABLES>", "").strip()
    if not data or data == "[]":
        print(f"{Fore.YELLOW}  No custom tables found.{Fore.RESET}")
    else:
        try:
            tables = json.loads(data)
            for t in tables:
                cols = ", ".join(t.get("columns", []))
                print(f"{Fore.CYAN}  ● {Fore.WHITE}{t['name']}{Fore.LIGHTBLACK_EX} ({cols}){Fore.RESET}")
        except json.JSONDecodeError:
            print(f"{Fore.RED}  Error parsing response.{Fore.RESET}")

    print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
    input(f"{Fore.LIGHTBLACK_EX}  Press Enter to continue...{Fore.RESET}")


def _create_table(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("CREATE TABLE")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name) or len(name) > 64:
        print(f"{Fore.RED}  Invalid table name. Use alphanumeric and underscore only (max 64 chars).{Fore.RESET}")
        time.sleep(2)
        return

    cols = input(f"{Fore.CYAN}  Columns (comma-separated): {Fore.WHITE}").strip()
    if not cols:
        print(f"{Fore.RED}  No columns provided.{Fore.RESET}")
        time.sleep(2)
        return

    col_list = [c.strip() for c in cols.split(",") if c.strip()]
    for c in col_list:
        if not re.match(r'^[a-zA-Z0-9_]+$', c) or len(c) > 64:
            print(f"{Fore.RED}  Invalid column name: {c}{Fore.RESET}")
            time.sleep(2)
            return

    if len(col_list) > 20:
        print(f"{Fore.RED}  Maximum 20 columns allowed.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"create_custom_table|{name}|{','.join(col_list)}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    messages = {
        "TABLE_CREATED": (Fore.GREEN, "Table created successfully!"),
        "TABLE_EXISTS": (Fore.YELLOW, "A table with that name already exists."),
        "TABLE_LIMIT_REACHED": (Fore.YELLOW, "Maximum number of tables reached (10)."),
        "INVALID_TABLE_NAME": (Fore.RED, "Invalid table name."),
        "INVALID_COLUMNS": (Fore.RED, "Invalid columns."),
        "INVALID_COLUMN_NAME": (Fore.RED, "Invalid column name."),
    }
    color, msg = messages.get(resp, (Fore.RED, f"Server response: {resp}"))
    print(f"\n  {color}{msg}{Fore.RESET}")
    time.sleep(2)


def _browse_table(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("BROWSE TABLE")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"{Fore.RED}  Invalid table name.{Fore.RESET}")
        time.sleep(2)
        return

    page = 0
    while True:
        client.send(f"get_custom_rows|{name}|{page}".encode("utf-8"))
        data = ""
        while "<END_OF_ROWS>" not in data:
            chunk = client.recv(4096).decode("utf-8")
            if not chunk:
                break
            data += chunk

        data = data.replace("\n<END_OF_ROWS>", "").strip()
        os.system("cls" if os.name == "nt" else "clear")
        print_banner(f"TABLE: {name} (Page {page + 1})")
        print()

        if not data or data == "[]":
            print(f"{Fore.YELLOW}  No rows found.{Fore.RESET}")
            print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
            input(f"{Fore.LIGHTBLACK_EX}  Press Enter to go back...{Fore.RESET}")
            return

        try:
            rows = json.loads(data)
            for row in rows:
                row_data = row.get("data", {})
                fields = " | ".join([f"{k}={v}" for k, v in row_data.items()])
                print(f"{Fore.CYAN}  ID:{Fore.WHITE}{row['id']}{Fore.LIGHTBLACK_EX} ➤ {Fore.WHITE}{fields}{Fore.RESET}")
        except json.JSONDecodeError:
            print(f"{Fore.RED}  Error parsing data.{Fore.RESET}")

        print(f"\n{Fore.CYAN}{'─' * 80}{Fore.RESET}")
        nav = input(f"{Fore.CYAN}  [N]ext page / [P]rev page / [B]ack: {Fore.WHITE}").strip().lower()
        if nav == "n":
            page += 1
        elif nav == "p" and page > 0:
            page -= 1
        else:
            return


def _add_row(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("ADD ROW")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"{Fore.RED}  Invalid table name.{Fore.RESET}")
        time.sleep(2)
        return

    print(f"\n{Fore.LIGHTBLACK_EX}  Enter data as JSON, e.g. {{\"user\":\"john\",\"password\":\"pass123\"}}{Fore.RESET}")
    raw = input(f"{Fore.CYAN}  Data: {Fore.WHITE}").strip()

    try:
        json.loads(raw)
    except json.JSONDecodeError:
        print(f"{Fore.RED}  Invalid JSON.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"add_custom_row|{name}|{raw}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp.startswith("ROW_ADDED"):
        row_id = resp.split("|")[1] if "|" in resp else "?"
        print(f"\n  {Fore.GREEN}Row added (ID: {row_id}){Fore.RESET}")
    elif resp == "TABLE_NOT_FOUND":
        print(f"\n  {Fore.RED}Table not found.{Fore.RESET}")
    elif resp == "INVALID_DATA":
        print(f"\n  {Fore.RED}Invalid data format.{Fore.RESET}")
    elif resp == "ROW_LIMIT_REACHED":
        print(f"\n  {Fore.YELLOW}Row limit reached (10,000).{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _update_row(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("UPDATE ROW")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"{Fore.RED}  Invalid table name.{Fore.RESET}")
        time.sleep(2)
        return

    row_id = input(f"{Fore.CYAN}  Row ID: {Fore.WHITE}").strip()
    try:
        int(row_id)
    except ValueError:
        print(f"{Fore.RED}  Invalid row ID.{Fore.RESET}")
        time.sleep(2)
        return

    print(f"\n{Fore.LIGHTBLACK_EX}  Enter updated fields as JSON, e.g. {{\"password\":\"newpass\"}}{Fore.RESET}")
    raw = input(f"{Fore.CYAN}  Data: {Fore.WHITE}").strip()

    try:
        json.loads(raw)
    except json.JSONDecodeError:
        print(f"{Fore.RED}  Invalid JSON.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"update_custom_row|{name}|{row_id}|{raw}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    messages = {
        "ROW_UPDATED": (Fore.GREEN, "Row updated successfully!"),
        "TABLE_NOT_FOUND": (Fore.RED, "Table not found."),
        "ROW_NOT_FOUND": (Fore.RED, "Row not found."),
        "INVALID_DATA": (Fore.RED, "Invalid data format."),
    }
    color, msg = messages.get(resp, (Fore.RED, f"Server: {resp}"))
    print(f"\n  {color}{msg}{Fore.RESET}")
    time.sleep(2)


def _delete_row(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("DELETE ROW")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"{Fore.RED}  Invalid table name.{Fore.RESET}")
        time.sleep(2)
        return

    row_id = input(f"{Fore.CYAN}  Row ID: {Fore.WHITE}").strip()
    try:
        int(row_id)
    except ValueError:
        print(f"{Fore.RED}  Invalid row ID.{Fore.RESET}")
        time.sleep(2)
        return

    client.send(f"delete_custom_row|{name}|{row_id}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "ROW_DELETED":
        print(f"\n  {Fore.GREEN}Row deleted.{Fore.RESET}")
    elif resp == "ROW_NOT_FOUND":
        print(f"\n  {Fore.RED}Row not found.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)


def _delete_table(client):
    os.system("cls" if os.name == "nt" else "clear")
    print_banner("DELETE TABLE")
    print()

    name = input(f"{Fore.CYAN}  Table name: {Fore.WHITE}").strip()
    if not name or not re.match(r'^[a-zA-Z0-9_]+$', name):
        print(f"{Fore.RED}  Invalid table name.{Fore.RESET}")
        time.sleep(2)
        return

    confirm = input(f"{Fore.RED}  This will delete the table and ALL its data. Type '{name}' to confirm: {Fore.WHITE}").strip()
    if confirm != name:
        print(f"{Fore.YELLOW}  Cancelled.{Fore.RESET}")
        time.sleep(1)
        return

    client.send(f"delete_custom_table|{name}".encode("utf-8"))
    resp = client.recv(4096).decode("utf-8")

    if resp == "TABLE_DELETED":
        print(f"\n  {Fore.GREEN}Table deleted.{Fore.RESET}")
    else:
        print(f"\n  {Fore.RED}Server: {resp}{Fore.RESET}")
    time.sleep(2)
