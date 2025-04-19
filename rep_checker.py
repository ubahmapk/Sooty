from collections import OrderedDict

import requests
from netaddr import AddrFormatError, IPAddress
from pydantic import ValidationError
from pydantic.dataclasses import dataclass
from requests.exceptions import HTTPError
from rich import print as rprint

from config import get_config_vars, versionNo
from dns_menu import whois


class EmailRepReportError(Exception):
    """Custom exception for EmailRep API errors."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"EmailRepError: {self.message}"


@dataclass
class EmailRepDetails:
    """Class to represent the details of the EmailRep report."""

    blacklisted: bool
    malicious_activity: bool
    malicious_activity_recent: bool
    credentials_leaked: bool
    credentials_leaked_recent: bool
    data_breach: bool
    first_seen: str
    last_seen: str
    domain_exists: bool
    domain_reputation: str
    new_domain: bool
    days_since_domain_creation: int
    suspicious_tld: bool
    spam: bool
    free_provider: bool
    disposable: bool
    deliverable: bool
    accept_all: bool
    valid_mx: bool
    primary_mx: str
    spoofable: bool
    spf_strict: bool
    dmarc_enforced: bool
    profiles: list


@dataclass
class EmailRepReport:
    """Class to represent the EmailRep report."""

    email: str
    reputation: str
    suspicious: bool
    references: int
    details: EmailRepDetails
    summary: str

    @property
    def domain(self) -> str:
        """Extract the domain from the email address."""
        return self.email.split("@")[1]

    def print_report(self):
        print(f"Email:       {self.email}")
        print(f"Reputation:  {self.reputation}")
        print(f"Suspicious:  {self.suspicious}")
        print(f"Spotted:     {self.references} Times")
        print(f"Blacklisted: {self.details.blacklisted}")
        print(f"Last Seen:   {self.details.last_seen}")
        print(f"Known Spam:  {self.details.spam}")
        print()

        print("-------------")
        print("Domain Report")
        print("-------------")
        print(f"Domain:        @{self.domain}")
        print(f"Domain Exists: {self.details.domain_exists}")
        print(f"Domain Rep:    {self.details.domain_reputation}")
        print(f"Domain Age:    {self.details.days_since_domain_creation} Days")
        print(f"New Domain:    {self.details.new_domain}")
        print(f"Deliverable:   {self.details.deliverable}")
        print(f"Free Provider: {self.details.free_provider}")
        print(f"Disposable:    {self.details.disposable}")
        print(f"Spoofable:     {self.details.spoofable}")
        print()

        print("-------------------------")
        print("Malicious Activity Report")
        print("-------------------------")
        print(f"Malicious Activity: {self.details.malicious_activity}")
        print(f"Recent Activity:    {self.details.malicious_activity_recent}")
        print(f"Credentials Leaked: {self.details.credentials_leaked}")
        print(f"Found in breach:    {self.details.data_breach}")
        print()

        if self.details.profiles:
            print("---------------------")
            print("Social Media Profiles")
            print("---------------------")
            for profile in self.details.profiles:
                print(f" - {profile}")
            print()

        if self.summary:
            print("---------------------")
            print("Summary of Report")
            print("---------------------")
            rprint(self.summary)
            print()

        return None


def get_email_rep_api_key() -> str:
    """Retrieve the EmailRep API key from the configuration."""

    configvars: OrderedDict = get_config_vars()
    emailrep_api_key: str = configvars.get("EMAILREP_API_KEY", "")

    return emailrep_api_key


def get_haveibeenpwned_api_key() -> str:
    """Retrieve the Have I Been Pwned API key from the configuration."""

    configvars: OrderedDict = get_config_vars()
    hibp_api_key: str = configvars.get("HIBP_API_KEY", "")

    return hibp_api_key


def analyze_email() -> None:
    """Analyze an email address.

    Use the EmailRep API to check the reputation of the email address.
    Use Have I Been Pwned API to check if the email address has been involved
    in any data breaches.
    """

    email: str = input("Enter email address to analyze: ").strip()
    if not email:
        print("[red] No email address provided.")
        return None

    emailrep_api_key: str = get_email_rep_api_key()
    if not emailrep_api_key:
        print("[red] No API key present for the EmailRep service.")
        return None

    report: dict = submit_email_for_analysis(email, emailrep_api_key)
    print_emailrep_report(report)

    return None


def submit_email_for_analysis(email: str, emailrep_api_key: str) -> dict:
    """Analyze the given email address using the EmailRep API."""

    user_agent: str = f"Sooty/{versionNo}"
    url: str = f"https://emailrep.io/{email}?summary=true"

    headers = {
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }

    if emailrep_api_key:
        headers.update({"Key": emailrep_api_key})

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.HTTPError as e:
        raise EmailRepReportError(f"Request failed: {e}") from e

    try:
        report_data: dict = response.json()
    except ValueError:
        raise EmailRepReportError("Invalid JSON response from the API.") from None

    return report_data


def print_emailrep_report(raw_report_data: dict) -> None:
    """Print the emailrep analysis report."""

    try:
        report: EmailRepReport = EmailRepReport(**raw_report_data)
    except ValidationError:
        print("Unable to parse report data")
        return None

    rprint("[green] Email Analysis Report ")
    report.print_report()

    return None


def retrieve_hibp_breach_data(email: str) -> None:
    """Retrieve breach data from Have I Been Pwned API."""

    hibp_api_key: str = get_haveibeenpwned_api_key()

    if not hibp_api_key:
        print("No API key present for the Have I Been Pwned service.")
        return None

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"Content-Type": "application/json", "hibp-api-key": hibp_api_key, "user-agent": f"Sooty/{versionNo}"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.HTTPError as e:
        raise EmailRepReportError(f"Request failed: {e}") from e

    if response.status_code == 404:
        print("No breaches found for this email.")
        return None

    breach_data = response.json()
    return breach_data


def print_hibp_report(report: dict) -> None:
    """
    lr = len(report)
    if lr != 0:
        print("\nThe account has been found in the following breaches: ")
        for each in range(lr):
            breach = "https://haveibeenpwned.com/api/v3/breach/%s" % report[each]["Name"]
            breachReq = requests.get(breach, headers=headers)
            breachResponse = breachReq.json()
            breachList = []
            print("   Title:        %s" % breachResponse["Title"])
            print("   Breach Date:  %s" % breachResponse["BreachDate"])

        for each in breachResponse["DataClasses"]:
            breachList.append(each)
            print("   Data leaked: %s" % breachList, "\n")
    """
    return None


def tor_ip_report(ip: str) -> None:
    """Check if the given IP address is a Tor exit node."""

    # Returns a list of IP addresses that are Tor exit nodes
    url: str = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"

    try:
        request = requests.get(url)
        request.raise_for_status()
    except HTTPError as e:
        print(f"Request failed: {e}")
        return None

    print("\n TOR Exit Node Report: ")
    nodes_list: list[str] = request.text.split("\n")
    if ip in nodes_list:
        rprint(f"[red]  {ip} is a TOR Exit Node")
    else:
        rprint(f"[green]  {ip} is NOT a TOR Exit Node")

    return None


def get_abuseipdb_api_key() -> str:
    """Retrieve the AbuseIPDB API key from the configuration."""

    configvars: OrderedDict = get_config_vars()
    ab_api_key: str = configvars.get("AB_API_KEY", "")

    return ab_api_key


def abuseipdb_report(ip: str, ab_api_key: str) -> None:
    """Check the IP address against AbuseIPDB."""

    if not ab_api_key:
        print("No API key present for the AbuseIPDB service.")
        return None

    url: str = "https://api.abuseipdb.com/api/v2/check"
    days: str = "180"
    querystring: dict = {"ipAddress": ip, "maxAgeInDays": days}
    headers = {"Accept": "application/json", "Key": ab_api_key}

    try:
        response = requests.get(url=url, headers=headers, params=querystring)
        response.raise_for_status()
    except requests.HTTPError as e:
        print(f"Request failed: {e}")
        return None

    try:
        req = response.json()
    except ValueError:
        print("Invalid JSON response from the API.")
        return None

    print("\n ABUSEIPDB Report:")
    print("   IP:          " + str(req["data"]["ipAddress"]))
    print("   Reports:     " + str(req["data"]["totalReports"]))
    print("   Abuse Score: " + str(req["data"]["abuseConfidenceScore"]) + "%")
    print("   Last Report: " + str(req["data"]["lastReportedAt"]))

    return None


def ip_reputation_check() -> None:
    rawInput = input("Enter IP Address: ")
    try:
        ip_address: IPAddress = IPAddress(rawInput)
    except AddrFormatError:
        print("Invalid IP address format.")
        return None

    ip: str = str(ip_address)
    whois(ip)
    tor_ip_report(ip)
    ab_api_key: str = get_abuseipdb_api_key()
    abuseipdb_report(ip, ab_api_key)

    # print("\n\nChecking against IP blacklists: ")
    # iplists.main(ip)

    return None


def reputation_checker_switch(choice: str) -> bool:
    print()
    if choice == "1":
        analyze_email()
        return True
    if choice == "2":
        print("URL Reputation Checker")
        # Add URL reputation checker logic here
        return True
    if choice == "3":
        ip_reputation_check()
        return True
    if choice == "0":
        return False

    rprint("[red] Invalid choice. Please try again.")
    return True


def reputation_checker_menu():
    while True:
        print()
        print(" --------------------------------- ")
        rprint("[green] R E P U T A T I O N     C H E C K ")
        print(" --------------------------------- ")
        print()
        print(" 1. Email Reputation")
        print(" 2. URL Reputation")
        print(" 3. IP Reputation")
        print()
        print(" 0. Return to Main Menu")
        print()

        msg: str = "Select an option (1-3) or 0 to return to main menu: "
        if not reputation_checker_switch(input(msg)):
            break


if __name__ == "__main__":
    reputation_checker_menu()
