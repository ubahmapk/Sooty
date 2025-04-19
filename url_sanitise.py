import re

from rich import print as rprint


def url_sanitise() -> None:
    print()
    print(" --------------------------------- ")
    rprint("[green] U R L   S A N I T I S E   T O O L ")
    print(" --------------------------------- ")
    print()
    url = str(input("Enter URL to sanitize: ").strip())
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)

    return None


if __name__ == "__main__":
    url_sanitise()
