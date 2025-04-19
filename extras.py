from rich import print

# from Sooty import mainMenu, versionNo
versionNo = "0.1.0"


def contributors() -> None:
    print(" CONTRIBUTORS")
    print(" Aaron J Copley for his code to decode ProofPoint URL's")
    print(" James Duarte for adding a hash and auto-check option to the hashing function ")
    print(" mrpnkt for adding the missing whois requirement to requirements.txt")
    print(" Gurulhu for adding the Base64 Decoder to the Decoders menu.")
    print(" AndThenEnteredAlex for adding the URLScan Function from URLScan.io")
    print(" Eric Kelson for fixing pywin32 requirement not necessary on Linux systems in requirements.txt.")
    print(" Jenetiks for removing and tidying up duplicate imports that had accumulated over time.")
    print(" Nikosch86 for fixing an issue with Hexdigest not storing hashes correctly")
    print(
        " Naveci for numerous bug fixes, QoL improvements, and Cisco Password 7 Decoding, and introduced a workflow to helps with issues in future. Phishtank support has now also been added."  # noqa: E501
    )
    print(" Paralax for fixing typos in the readme")
    print(" MrMeeseeks2014 fox fixing a bug relating to hash uploads")

    return None


def extrasVersion() -> None:
    print(" Current Version: " + versionNo)

    return None


def wikiLink() -> None:
    print("\n The Sooty Wiki can be found at the following link:")
    print(" https://github.com/TheresAFewConors/Sooty/wiki")

    return None


def ghLink() -> None:
    print("\n The Sooty Repo can be found at the following link:")
    print(" https://github.com/TheresAFewConors/Sooty")

    return None


def aboutSooty() -> None:
    print(" SOOTY is a tool developed and targeted to help automate some tasks that SOC Analysts perform.")

    return None


def extrasSwitch(choice):
    print()
    if choice == "1":
        aboutSooty()
        return True
    if choice == "2":
        contributors()
        return True
    if choice == "3":
        extrasVersion()
        return True
    if choice == "4":
        wikiLink()
        return True
    if choice == "5":
        ghLink()
        return True
    if choice == "0":
        return False

    print("\n[red] Invalid option selected")
    return True


def extras_menu() -> None:
    while True:
        print()
        print(" --------------------------------- ")
        print("[green]            E X T R A S            ")
        print(" --------------------------------- ")
        print()
        print(" OPTION 1: About SOOTY ")
        print(" OPTION 2: Contributors ")
        print(" OPTION 3: Version")
        print(" OPTION 4: Wiki")
        print(" OPTION 5: GitHub Repo")
        print()
        print(" OPTION 0: Exit to Main Menu")
        print()

        if not extrasSwitch(input(" What would you like to do? ")):
            break

    return None


if __name__ == "__main__":
    extras_menu()
