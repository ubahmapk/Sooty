import hashlib
from pathlib import Path
from typing import Literal

from rich import print as rprint

from virus_total import read_vt_api_key_from_config, vt_hash_rating, vt_search_file_hash


class FileSelectionError(Exception):
    """User cancelled file selection."""

    pass


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


def hash_file_and_search_vt() -> None:
    try:
        filename: Path = get_valid_file_path()
    except FileSelectionError:
        rprint("\n[red] Error: File selection cancelled")
        return None

    file_hash: str = get_file_hash(filename, "sha256")
    print_hashes(filename)

    vt_api_key: str = read_vt_api_key_from_config()
    vt_search_file_hash(file_hash, vt_api_key)

    return None


def search_vt_for_hash() -> None:
    try:
        file_hash: str = input(" Enter the hash to search for: ").strip()
    except KeyboardInterrupt:
        rprint("\n[red] Error: Hash selection cancelled")
        return None

    vt_api_key: str = read_vt_api_key_from_config()
    vt_hash_rating(vt_api_key, file_hash)

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


def hash_switch(choice) -> bool:
    if choice == "1":
        hash_file()
        return True
    if choice == "2":
        hash_text()
        return True
    if choice == "3":
        search_vt_for_hash()
        return True
    if choice == "4":
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
    hash_menu()
