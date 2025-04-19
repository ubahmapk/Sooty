import re
import socket

from ipwhois import IPWhois
from rich import print


def reverse_dns_lookup() -> None:
    try:
        ip = str(input(" Enter IP to check: ").strip())
        hostname, aliaslist, _ = socket.gethostbyaddr(ip)
        print()
        print(f"{hostname=}")
        print(f"{aliaslist=}")
    except EOFError:
        pass
    except OSError:
        print(" [red]Hostname not found")

    return None


def strip_to_raw_domain(domain: str) -> str:
    domain = re.sub("http://", "", domain)
    domain = re.sub("https://", "", domain)

    return domain


def dns_lookup() -> None:
    domain = str(input(" Enter Domain Name to check: ").strip())
    domain = strip_to_raw_domain(domain)

    try:
        hostname: str = socket.gethostbyname(domain)
        print()
        print(f" Hostname: [green]{hostname}")
    except OSError:
        print(" [red]Hostname not found")

    return None


def whois(domain_or_ip: str) -> None:
    """
    If the DNS resolution fails, the input is either a non-existent domain
    or an invalid IP
    """
    try:
        ip: str = socket.gethostbyname(domain_or_ip)
    except OSError:
        print(" [red]Invalid IP address or domain.")
        return None

    whois_client: IPWhois = IPWhois(ip)
    response: dict = whois_client.lookup_rdap()

    # TODO: Use data models for improved parsing and printing
    # TODO: Re-implement saving results to file
    print(response)

    return None


def dns_switch(choice: str) -> bool:
    print()
    if choice == "1":
        reverse_dns_lookup()
        return True
    if choice == "2":
        dns_lookup()
        return True
    if choice == "3":
        domain_or_ip: str = str(input(" Enter IP / Domain: ").strip())
        whois(domain_or_ip)
        return True
    if choice == "0":
        return False

    print("\n[red] Invalid option selected")
    return True


def dns_menu() -> None:
    while True:
        print()
        print(" --------------------------------- ")
        print("[green]          D N S    T O O L S        ")
        print(" --------------------------------- ")
        print()
        print(" 1: Reverse DNS Lookup")
        print(" 2: DNS Lookup")
        print(" 3: WHOIS Lookup")
        print()
        print(" 0: Exit to Main Menu")
        print()

        if not dns_switch(input(" What would you like to do? ")):
            break

    return None


if __name__ == "__main__":
    dns_menu()
