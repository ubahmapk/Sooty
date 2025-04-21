import json
from collections import OrderedDict

import httpx
from rich import print as rprint

from config import get_config_vars


def get_haveibeenpwned_api_key() -> str:
    """Retrieve the Have I Been Pwned API key from the configuration."""

    configvars: OrderedDict = get_config_vars()
    hibp_api_key: str = configvars.get("HIBP_API_KEY", "")

    return hibp_api_key


def hibp_email_report(email_address: str, hibp_api_key) -> dict:
    url: str = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_address}"
    user_agent: str = "Sooty"
    headers: dict = {
        "Content-Type": "application/json",
        "hibp-api-key": hibp_api_key,
        "user-agent": user_agent,
    }

    try:
        response: httpx.Response = httpx.get(url, headers=headers)
        response.raise_for_status()
    except httpx.HTTPError as e:
        print(f" Error retrieving Have I Been Pwned Data: {e}")
        return {}

    try:
        report: dict = response.json()
    except (ValueError, json.JSONDecodeError):
        print(" Unable to decode JSON response")
        return {}

    if not report:
        print(" No  Entries found in Database")
        return {}

    return report


def get_hibp_breach_report(breach_name: str, hibp_api_key: str = "") -> dict:
    user_agent: str = "Sooty"
    headers: dict = {
        "Content-Type": "application/json",
        "hibp-api-key": hibp_api_key,
        "user-agent": user_agent,
    }

    breach_url: str = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"

    try:
        breach_response: httpx.Response = httpx.get(breach_url, headers=headers)
        breach_response.raise_for_status()
    except httpx.HTTPError as e:
        print(f" Error retrieving breach report: {e}")
        return {}

    try:
        breach_report: dict = breach_response.json()
    except (ValueError, json.JSONDecodeError) as e:
        print(f" Unable to decode JSON response: {e}")
        return {}

    return breach_report


def print_hibp_breach_report(breach_report: dict) -> None:
    breach_list: list = []

    print()
    print(f"   Title:        {breach_report.get('Title', '')}")
    print(f"   Domain:       {breach_report.get('Domain', '')}")
    print(f"   Breach Date:  {breach_report.get('BreachDate', '')}")
    print(f"   Pwn Count:    {breach_report.get('PwnCount', '')}")

    for breach_entry in breach_report.get("DataClasses", []):
        breach_list.append(breach_entry)

    if len(breach_list):
        print("   Data leaked: %s" % breach_list)

    return None


def print_hibp_email_report(email_report: dict, hibp_api_key: str = "") -> None:
    rprint("[bold] The account has been found in the following breaches: ")
    for entry in email_report:
        report: dict = get_hibp_breach_report(entry.get("Name"), hibp_api_key)
        print_hibp_breach_report(report) if report else None

    return None


def hibp_menu() -> None:
    print()
    print(" --------------------------------- ")
    rprint("[green] H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")
    print()

    hibp_api_key: str = get_haveibeenpwned_api_key()

    if not hibp_api_key:
        rprint("[red] Missing configuration for HIBP_API_KEY in the config.yaml file.")
        return None

    email_account: str = str(input(" Enter email: ").strip())
    email_report: dict = hibp_email_report(email_account, hibp_api_key)

    if not email_report:
        rprint("[green] No breaches found for this account.")
        return None

    print_hibp_email_report(email_report, hibp_api_key)

    return None
