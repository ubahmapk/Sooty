import hashlib
from collections import OrderedDict
from pathlib import Path
from typing import Literal

import requests
from rich import print as rprint

from config import get_config_vars


class FileSelectionError(Exception):
    """User cancelled file selection."""

    pass


def read_vt_api_key_from_config() -> str:
    configvars: OrderedDict = get_config_vars()

    vt_api_key: str = configvars.get("VT_API_KEY", "")

    return vt_api_key


def get_valid_file_path() -> Path:
    """Prompt user for file path and validate it exists."""
    try:
        while True:
            file_path: str = input(" Enter the path to your file: ").strip()
            path: Path = Path(file_path)

            if not path.is_file():
                print(f"\n[red]Error: '{file_path}' is not a file")

            return path
    except KeyboardInterrupt:
        raise FileSelectionError from None


def get_file_hash(
    filepath: Path, algorithm: Literal["md5", "sha1", "sha256", "sha512"] = "sha256", chunk_size: int = 8192
) -> str:
    """
    Calculate hash of a file using specified algorithm.

    Args:
        filepath: Path object pointing to file to hash
        algorithm: Hash algorithm to use (default: sha256)
        chunk_size: Size of chunks to read (default: 8KB)

    Returns:
        Hexadecimal string of file hash

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If algorithm is invalid
    """
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    valid_algorithms = {"md5", "sha1", "sha256", "sha512"}
    if algorithm not in valid_algorithms:
        raise ValueError(f"Invalid algorithm. Must be one of: {', '.join(valid_algorithms)}")

    hasher = getattr(hashlib, algorithm)()

    with filepath.open("rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


def print_hashes(filepath: Path) -> None:
    """Print hashes of a file using different algorithms."""
    print(f" MD5:    {get_file_hash(filepath, 'md5')}")
    print(f" SHA1:   {get_file_hash(filepath, 'sha1')}")
    print(f" SHA256: {get_file_hash(filepath, 'sha256')}")
    print(f" SHA512: {get_file_hash(filepath, 'sha512')}")

    return None


def hash_file() -> None:
    try:
        file_path: Path = get_valid_file_path()
    except (PermissionError, OSError):
        rprint("\n[red] Error accessing file")
        return None
    except FileSelectionError:
        rprint("\n[red] Error: File selection cancelled")
        return None

    print_hashes(file_path)
    return None


def hash_text() -> None:
    userinput = input(" Enter the text to be hashed (MD5): ")
    print()
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())

    return None


def hash_rating() -> None:
    # VT Hash Checker
    print()
    file_hash = str(input(" Enter Hash of file: ").strip())
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


def hash_file_and_search_vt() -> None:
    try:
        filename: Path = get_valid_file_path()
    except FileSelectionError:
        rprint("\n[red] Error: File selection cancelled")
        return None

    file_hash: str = get_file_hash(filename, "sha256")
    print_hashes(filename)
    print()

    # VT Hash Checker
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


def hash_switch(choice) -> bool:
    if choice == "1":
        hash_file()
        return True
    if choice == "2":
        hash_text()
        return True
    if choice == "3":
        if not vt_api_key:
            rprint("\n[red] Error: No VirusTotal API Key found in config.yaml")
            return True
        hash_rating()
        return True
    if choice == "4":
        if not vt_api_key:
            rprint("\n[red] Error: No VirusTotal API Key found in config.yaml")
            return True
        hash_file_and_search_vt()
        return True
    if choice == "0":
        return False

    print("\n[red] Invalid option selected")
    return True


def hash_menu() -> None:
    while True:
        print()
        print(" --------------------------------- ")
        rprint("[green] H A S H I N G   F U N C T I O N S ")
        print(" --------------------------------- ")
        print()
        print(" 1: Hash a file")
        print(" 2: Input and hash text")
        print(" 3: Check a hash for known malicious activity")
        print(" 4: Hash a file, check a hash for known malicious activity")
        print()
        print(" 0: Exit to Main Menu")
        print()

        if not hash_switch(input(" What would you like to do? ")):
            break


if __name__ == "__main__":
    vt_api_key: str = read_vt_api_key_from_config()
    hash_menu()
