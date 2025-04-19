import base64
import html
import re
import urllib.parse

import requests
from rich import print as rprint
from unfurl import core

# from Sooty import linksFoundList

linksFoundList: list = []


def url_decoder() -> None:
    print()
    print(" --------------------------------- ")
    rprint("[green]       U R L   D E C O D E R      ")
    print(" --------------------------------- ")
    print()
    url = str(input(" Enter URL: ").strip())
    decodedUrl = urllib.parse.unquote(url)
    print(decodedUrl)

    return None


def decodev1(rewrittenurl) -> None:
    match = re.search(r"u=(.+?)&k=", rewrittenurl)
    if match:
        urlencodedurl = match.group(1)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

    return None


def decodev2(rewrittenurl) -> None:
    match = re.search(r"u=(.+?)&[dc]=", rewrittenurl)
    if match:
        specialencodedurl = match.group(1)
        trans = str.maketrans("-_", "%/")
        urlencodedurl = specialencodedurl.translate(trans)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

    return None


def decodev3(rewrittenurl) -> None:
    match = re.search(r"v3/__(?P<url>.+?)__;", rewrittenurl)
    if match:
        url = match.group("url")
        if re.search(r"\*(\*.)?", url):
            url = re.sub(r"\*", "+", url)
            if url not in linksFoundList:
                linksFoundList.append(url)

    return None


def base64_decoder() -> None:
    url = str(input(" Enter URL: ").strip())

    try:
        b64: str = str(base64.b64decode(url))
        decoded_string: str = re.split("'", b64)[1]
        print(f" B64 String:     {url}")
        print(f" Decoded String: {decoded_string}")
    # TODO: Research errors raised by base64 Decode for various error conditions
    except:  # noqa: E722
        print(" No Base64 Encoded String Found")

    return None


def cisco7_decoder() -> None:
    print()
    pw = input(" Enter Cisco Password 7: ").strip()

    key = [
        0x64,
        0x73,
        0x66,
        0x64,
        0x3B,
        0x6B,
        0x66,
        0x6F,
        0x41,
        0x2C,
        0x2E,
        0x69,
        0x79,
        0x65,
        0x77,
        0x72,
        0x6B,
        0x6C,
        0x64,
        0x4A,
        0x4B,
        0x44,
        0x48,
        0x53,
        0x55,
        0x42,
    ]

    try:
        # the first 2 characters of the password are the starting index in the key array
        index = int(pw[:2], 16)

        # the remaining values are the characters in the password, as hex bytes
        pw_text = pw[2:]
        pw_hex_values = [pw_text[start : start + 2] for start in range(0, len(pw_text), 2)]

        # XOR those values against the key values, starting at the index, and convert to ASCII
        pw_chars = [chr(key[index + i] ^ int(pw_hex_values[i], 16)) for i in range(0, len(pw_hex_values))]

        pw_plaintext = "".join(pw_chars)
        print(f"Password: {pw_plaintext}")

    except Exception as e:
        print(e)

    return None


def unfurl_url() -> None:
    # TODO: Figure out what we're trying to do at all with unfurl
    print()
    url_to_unfurl = str(input(" Enter URL to Unfurl: ")).strip()

    try:
        unfurl_instance = core.Unfurl()
        unfurl_instance.add_to_queue(data_type="url", key=None, value=url_to_unfurl)
        unfurl_instance.parse_queue()

        print(unfurl_instance.generate_text_tree())
    except TypeError:
        print("[red] Invalid URL provided or Unfurl is just broken right now")

    return None


def safelinks_decoder() -> None:
    """Return a "safe" version of a URL link.

    Uses Microsoft's SafeLinks service to evaluate URLs
    """

    print()
    print(" --------------------------------- ")
    rprint("[green] S A F E L I N K S   D E C O D E R  ")
    print(" --------------------------------- ")
    print()

    url: str = str(input(" Enter URL: ").strip())
    unquoted_url: str = urllib.parse.unquote(url)
    safe_url = unquoted_url.replace("https://nam02.safelinks.protection.outlook.com/?url=", "")

    print(f"{safe_url!s}")

    return None


def unshorten_url() -> None:
    """Use Unshorten.me to expand a short URL."""

    print()
    print(" --------------------------------- ")
    rprint("[green]   U R L   U N S H O R T E N E R  ")
    print(" --------------------------------- ")
    print()

    link: str = str(input(" Enter URL: ").strip())
    req = requests.get(str("https://unshorten.me/s/" + link))

    print(req.text)

    return None


def proofpoint_decoder() -> None:
    print()
    print(" ----------------------------------- ")
    print("[green] P R O O F P O I N T   D E C O D E R ")
    print(" ----------------------------------- ")
    print()

    rewrittenurl: str = str(input(" Enter ProofPoint Link: ").strip())
    match = re.search(r"https://urldefense.proofpoint.com/(v[0-9])/", rewrittenurl)
    matchv3 = re.search(r"urldefense.com/(v3)/", rewrittenurl)
    if match:
        if match.group(1) == "v1":
            decodev1(rewrittenurl)
            for each in linksFoundList:
                print("\n Decoded Link: %s" % each)
                linksFoundList.clear()
        elif match.group(1) == "v2":
            decodev2(rewrittenurl)
            for each in linksFoundList:
                print("\n Decoded Link: %s" % each)
                linksFoundList.clear()

    if matchv3 is not None:
        if matchv3.group(1) == "v3":
            decodev3(rewrittenurl)
            for each in linksFoundList:
                print("\n Decoded Link: %s" % each)
                linksFoundList.clear()
        else:
            print(" No valid URL found in input: ", rewrittenurl)

    return None


def decoder_switch(choice) -> bool:
    print()
    if choice == "1":
        proofpoint_decoder()
        return True
    if choice == "2":
        url_decoder()
        return True
    if choice == "3":
        safelinks_decoder()
        return True
    if choice == "4":
        unshorten_url()
        return True
    if choice == "5":
        base64_decoder()
        return True
    if choice == "6":
        cisco7_decoder()
        return True
    if choice == "7":
        unfurl_url()
        return True
    if choice == "0":
        return False

    print("\n[red] Invalid option selected")
    return True


def decoder_menu() -> None:
    while True:
        print()
        print(" --------------------------------- ")
        rprint("[green]           D E C O D E R S        ")
        print(" --------------------------------- ")
        print()
        print(" 1: ProofPoint Decoder")
        print(" 2: URL Decoder")
        print(" 3: Office SafeLinks Decoder")
        print(" 4: URL unShortener")
        print(" 5: Base64 Decoder")
        print(" 6: Cisco Password 7 Decoder")
        print(" 7: Unfurl URL")
        print()
        print(" 0: Exit to Main Menu")
        print()

        if not decoder_switch(input(" What would you like to do? ")):
            break

    return None


if __name__ == "__main__":
    decoder_menu()
