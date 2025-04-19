import time
from collections import OrderedDict

import requests
from rich import print as rprint
from rich.progress import track

from config import get_config_vars


def get_urlscanio_api_key() -> str:
    """Get the URLSCAN.IO API key from the config file."""

    configvars: OrderedDict = get_config_vars()
    urlscan_io_key: str = configvars.get("URLSCAN_IO_KEY", "")

    if not urlscan_io_key:
        rprint("[red] Please set the URLSCAN_IO_KEY in your config file.")
        return ""

    return urlscan_io_key


def urlscanio() -> None:
    print()
    print(" --------------------------------- ")
    rprint("[green]        U R L S C A N . I O        ")
    print(" --------------------------------- ")
    print()

    urlscan_io_key: str = get_urlscanio_api_key()

    if not urlscan_io_key:
        rprint("[red] Please set the URLSCAN_IO_KEY in your config file.")
        return None

    url_to_scan: str = str(input(" Enter url: ").strip())

    type_prompt = str(input('\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '))
    scan_type = "public" if type_prompt == "1" else "private"

    headers = {
        "Content-Type": "application/json",
        "API-Key": urlscan_io_key,
    }

    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type)
    ).json()

    if "successful" not in response["message"]:
        print(response["message"])
        return

    print("\nNow scanning %s. Check back in around 1 minute." % url_to_scan)
    uuid_variable: str = str(response["uuid"])  # uuid, this is the factor that identifies the scan
    print(f"Scan UUID: {uuid_variable}")
    print(f"Scan Result URL: https://urlscan.io/result/{uuid_variable}/")

    # The scan takes awhile, if we try to retrieve the scan too soon, it will return an error.
    print()
    for _ in track(range(45), description="Waiting..."):
        time.sleep(1)

    while True:
        # retrieving the scan using the uuid for this scan
        scan_results = requests.get(f"https://urlscan.io/api/v1/result/{uuid_variable}/").json()

        try:
            task_url = scan_results["task"]["url"]
            verdicts_overall_score = scan_results["verdicts"]["overall"]["score"]
            verdicts_overall_malicious = scan_results["verdicts"]["overall"]["malicious"]
            task_report_URL = scan_results["task"]["reportURL"]
        except KeyError:
            print("Scan not complete yet. Waiting for 30 seconds...")
            for _ in track(range(45), description="Waiting..."):
                time.sleep(1)

            continue

        break

    print("\nurlscan.io Report:")
    print("\nURL: " + task_url)
    print("\nOverall Verdict: " + str(verdicts_overall_score))
    print("Malicious: " + str(verdicts_overall_malicious))
    print("urlscan.io: " + str(scan_results["verdicts"]["urlscan"]["score"]))
    if scan_results["verdicts"]["urlscan"]["malicious"]:
        print("Malicious: " + str(scan_results["verdicts"]["urlscan"]["malicious"]))  # True
    if len(scan_results["verdicts"]["urlscan"]["categories"]) > 0:
        print("Categories: ")
        for line in scan_results["verdicts"]["urlscan"]["categories"]:
            print("\t" + str(line))  # phishing
    for line in scan_results["verdicts"]["engines"]["verdicts"]:
        print(str(line["engine"]) + " score: " + str(line["score"]))  # googlesafebrowsing
        print("Categories: ")
        for item in line["categories"]:
            print("\t" + item)  # social_engineering
    print("\nSee full report for more details: " + str(task_report_URL))
    print("")

    return None


if __name__ == "__main__":
    urlscanio()
