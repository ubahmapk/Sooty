import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

import requests
import strictyaml
from dacite import from_dict


def local_configvars(config_file: str) -> dict:
    """Load config.yaml from the current directory."""

    try:
        with open(config_file) as f:
            configvars: dict = strictyaml.load(f.read())
    except FileNotFoundError:
        print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")
        sys.exit(1)

    return configvars


@dataclass(slots=True)
class OpenPort:
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None

    def __str__(self):
        print(f"Port {self.port}")
        print(f"Vulnerability: {self.is_vulnerability}")
        print(f"Product Name: {self.product_name}")
        print(f"Product Version: {self.product_version}")
        print(f"Protocol: {self.protocol}")
        print(f"Socket Type: {self.socket_type}")
        print(f"Confirmed Time: {self.confirmed_time}")


@dataclass(slots=True)
class IDSAlert:
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None

    def __str__(self):
        print(f"Classification: {self.classification}")
        print(f"Confirmed Time: {self.confirmed_time}")
        print(f"Message: {self.message}")
        print(f"Source System: {self.source_system}")
        print(f"URL: {self.url}")


@dataclass(slots=True)
class CurrentOpenedPorts:
    count: int
    data: list[OpenPort] = field(default_factory=list)


@dataclass(slots=True)
class IDSAlerts:
    count: int
    data: list[IDSAlert] = field(default_factory=list)


@dataclass(slots=True)
class Issues:
    is_vpn: bool = False
    is_proxy: bool = False
    is_cloud: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_darkweb: bool = False
    is_scanner: bool = False
    is_snort: bool = False
    is_anonymous_vpn: bool = False

    def __str__(self):
        print(f"VPN: {self.is_vpn}")
        print(f"Proxy: {self.is_proxy}")
        print(f"Cloud: {self.is_cloud}")
        print(f"Tor: {self.is_tor}")
        print(f"Hosting: {self.is_hosting}")
        print(f"Mobile: {self.is_mobile}")
        print(f"DarkWeb: {self.is_darkweb}")
        print(f"Scanner: {self.is_scanner}")
        print(f"Snort: {self.is_snort}")
        print(f"Anonymous VPN: {self.is_anonymous_vpn}")


@dataclass(slots=True)
class WhoisRecord:
    as_name: str | None = None
    as_no: str | None = None
    city: str | None = None
    region: str | None = None
    org_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    org_country_code: str | None = None
    confirmed_time: str | None = None

    def __str__(self):
        print(f"AS Name: {self.as_name}")
        print(f"AS Number: {self.as_no}")
        print(f"City: {self.city}")
        print(f"Region: {self.region}")
        print(f"Organization Name: {self.org_name}")
        print(f"Postal Code: {self.postal_code}")
        print(f"Latitude: {self.latitude}")
        print(f"Longitude: {self.longitude}")
        print(f"Organization Country Code: {self.org_country_code}")
        print(f"Confirmed Time: {self.confirmed_time}")


@dataclass(slots=True)
class Whois:
    count: int = 0
    data: list[WhoisRecord] = field(default_factory=list)


@dataclass(slots=True)
class SuspiciousInfoReport:
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts = field(default_factory=list)
    ids: IDSAlerts | None = None
    ip: str | None = None
    issues: Issues | None = None
    representative_domain: str | None = None
    score: dict[str, str] = field(default_factory=dict)
    status: int | None = None
    whois: dict[any, any] = field(default_factory=dict)


def retrieve_api_key(configvars) -> str:
    """Retrieve the API key from the config file"""

    try:
        api_key: str = configvars.data["CRIMINALIP_API_KEY"]
    except KeyError:
        api_key = ""

    if not api_key:
        print("No API key found for CriminalIP in config file.")

    return api_key


def make_full_request(headers: dict[str, str], url: str, params: dict[str, str]) -> requests.Response:
    """Full function to make a request to the Criminal IP API"""

    base_url: str = "https://api.criminalip.com"
    full_url: str = f"{base_url}{url}"

    try:
        response: requests.Response = requests.get(headers=headers, url=full_url, params=params)
    except requests.exceptions.RequestException as e:
        print(f"HTTP Error retrieving IP report from Criminal IP: {e}")
        exit(1)

    return response


def print_suspicious_info_report(report: SuspiciousInfoReport) -> None:
    """Print the results of a Suspicious Info Report"""

    print(f"IP: {report.ip}")
    print(f"Status: {report.status}")
    print(f"Score: {report.score}")
    print(f"Abuse Record Count: {report.abuse_record_count}")

    if report.current_opened_port.count:
        print("Current Open Ports")
        print(f"Open Port Count: {report.current_opened_port.count}")
        for port in report.current_opened_port.data:
            print(f"{port}")
            print()

    if report.ids.count:
        print("IDS Alerts")
        print(f"IDS Alert Count: {report.ids.count}")
        for alert in report.ids.data:
            print(f"{alert}")
        print()

    print(f"Representative Domain: {report.representative_domain}")

    if report.whois and report.whois.count:
        print("Whois")
        print(f"Whois Count: {report.whois.count}")
        for record in report.whois.data:
            print(f"{record}")
            print()

    if report.issues:
        print("Issues")
        print(report.issues)
        print()

    return None


def main(api_key: str, ip: str) -> None:
    """Main function for the CriminalIP module"""

    headers: dict[str, str] = {
        "x-api-key": f"{api_key}",
    }
    params: dict[str, str] = {"ip": ip}

    request_suspicious_info_report: Callable = partial(make_full_request, headers, url="/v2/feature/ip/suspicious-info")

    report_data: requests.Response = request_suspicious_info_report(params=params)
    suspicious_info_report: SuspiciousInfoReport = from_dict(data_class=SuspiciousInfoReport, data=report_data.json())

    print_suspicious_info_report(suspicious_info_report)

    """
    request_full_ip_report: Callable = partial(
        make_full_request, headers, url="/v1/asset/ip/report"
    )
    request_summary_ip_report: Callable = partial(
        make_full_request, headers, url="/v1/asset/ip/report/summary"
    )
    """


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        exit(1)

    configvars: dict = local_configvars("../config.yaml")
    api_key: str = retrieve_api_key(configvars)
    ip: str = sys.argv[1]

    main(api_key, ip)
