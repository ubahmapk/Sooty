from collections import OrderedDict

import requests
from requests.exceptions import HTTPError
from rich import print as rprint

from config import get_config_vars


class FileSelectionError(Exception):
    """User cancelled file selection."""

    pass


def read_vt_api_key_from_config() -> str:
    configvars: OrderedDict = get_config_vars()

    vt_api_key: str = configvars.get("VT_API_KEY", "")

    return vt_api_key


def vt_hash_rating(vt_api_key: str, file_hash: str) -> None:
    # VT Hash Checker

    if not vt_api_key:
        rprint("[red] Error: No VT API Key provided")
        return None

    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": vt_api_key, "resource": file_hash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except ValueError:
        rprint("[red] Error: Invalid API Key")
        return None

    print()
    try:
        if result["response_code"] == 0:
            rprint("[yellow] Hash was not found in Malware Database")
        elif result["response_code"] == 1:
            print(" VirusTotal Report: " + str(result["positives"]) + "/" + str(result["total"]) + " detections found")
            print(f"   Report Link: https://www.virustotal.com/gui/file/{file_hash}/detection")
        else:
            print("[yellow] No Reponse")
    except TypeError:
        rprint("[red] Error: Invalid Hash")
        return None

    return None


def vt_search_file_hash(vt_api_key: str, file_hash: str) -> None:
    if not vt_api_key:
        rprint("[red] Error: No VT API Key provided")
        return None

    url = "https://www.virustotal.com/vtapi/v2/file/report"

    params = {"apikey": vt_api_key, "resource": file_hash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except ValueError:
        print("Error: Invalid API Key")
        return None

    if result["response_code"] == 0:
        print(" Hash was not found in Malware Database")
    elif result["response_code"] == 1:
        print(" VirusTotal Report: " + str(result["positives"]) + "/" + str(result["total"]) + " detections found")
        print("   Report Link: " + "https://www.virustotal.com/gui/file/" + file_hash + "/detection")
    else:
        print("No Response")

    return None


def vt_url_report(vt_api_key: str, wIP: str) -> None:
    if not vt_api_key:
        rprint("[red] Error: No VT API Key provided")
        return None

    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": vt_api_key, "resource": wIP}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
    except HTTPError as e:
        print(f"HTTP error occurred: {e}")
        return None

    positive_count: int = 0  # Total positives found in VT
    total_scans: int = 0  # Total number of scans

    try:
        report = response.json()
    except ValueError:
        print("Unable to decode JSON data from VT response")
        return None

    for each in report:
        total_scans = report["total"]
        if report["positives"] != 0:
            positive_count = positive_count + 1
        avg = positive_count / total_scans
        print("   No of Databases Checked: " + str(total_scans))
        print("   No of Reportings: " + str(positive_count))
        print("   Average Score:    " + str(avg))
        print("   VirusTotal Report Link: " + report["permalink"])


if __name__ == "__main__":
    vt_api_key: str = read_vt_api_key_from_config()
