#!/usr/bin/env python3
"""
Title:      Sooty
Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
Author:     Connor Jackson
Version:    1.3.2
GitHub URL: https://github.com/TheresAFewConors/Sooty
"""

import os
import re
import time
import tkinter
from pathlib import Path

import requests
import strictyaml
from rich import print as rprint

from decoder import decoder_menu
from dns_menu import dns_menu
from extras import extras_menu
from hash_menu import hash_menu
from Modules import TitleOpen, criminalip, phishtank
from url_sanitise import url_sanitise

try:
    import win32com.client
except ModuleNotFoundError:
    print("Cant install Win32com package")

versionNo = "1.3.2"

configfile: Path = Path("config.yaml")
try:
    with configfile.open() as f:
        configvars = strictyaml.load(f.read())
except FileNotFoundError:
    print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")

linksFoundList = []
linksRatingList = []
linksSanitized = []
linksDict = {}


def phishingSwitch(choice):
    if choice == "1":
        analyzePhish()
    if choice == "2":
        analyzeEmailInput()
    if choice == "3":
        emailTemplateGen()
    if choice == "4":
        phishtankModule()
    if choice == "9":
        haveIBeenPwned()
    else:
        mainMenu()


def titleLogo():
    TitleOpen.titleOpen()
    os.system("cls||clear")


def urlscanio():
    print("\n --------------------------------- ")
    print("\n        U R L S C A N . I O        ")
    print("\n --------------------------------- ")
    url_to_scan = str(input("\nEnter url: ").strip())

    type_prompt = str(input('\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '))
    scan_type = "public" if type_prompt == "1" else "private"

    headers = {
        "Content-Type": "application/json",
        "API-Key": configvars.data["URLSCAN_IO_KEY"],
    }

    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type)
    ).json()

    if "successful" not in response["message"]:
        print(response["message"])
        return

    print("\nNow scanning %s. Check back in around 1 minute." % url_to_scan)
    uuid_variable = str(response["uuid"])  # uuid, this is the factor that identifies the scan
    time.sleep(
        45
    )  # sleep for 45 seconds. The scan takes awhile, if we try to retrieve the scan too soon, it will return an error.
    scan_results = requests.get(
        "https://urlscan.io/api/v1/result/%s/" % uuid_variable
    ).json()  # retrieving the scan using the uuid for this scan

    task_url = scan_results["task"]["url"]
    verdicts_overall_score = scan_results["verdicts"]["overall"]["score"]
    verdicts_overall_malicious = scan_results["verdicts"]["overall"]["malicious"]
    task_report_URL = scan_results["task"]["reportURL"]

    print("\nurlscan.io Report:")
    print("\nURL: " + task_url)
    print("\nOverall Verdict: " + str(verdicts_overall_score))
    print("Malicious: " + str(verdicts_overall_malicious))
    print("urlscan.io: " + str(scan_results["verdicts"]["urlscan"]["score"]))
    if scan_results["verdicts"]["urlscan"]["malicious"]:
        print("Malicious: " + str(scan_results["verdicts"]["urlscan"]["malicious"]))  # True
    if scan_results["verdicts"]["urlscan"]["categories"]:
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


def phishingMenu():
    print("\n --------------------------------- ")
    print("          P H I S H I N G          ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Analyze an Email ")
    print(" OPTION 2: Analyze an Email Address for Known Activity")
    print(" OPTION 3: Generate an Email Template based on Analysis")
    print(" OPTION 4: Analyze an URL with Phishtank")
    print(" OPTION 9: HaveIBeenPwned")
    print(" OPTION 0: Exit to Main Menu")
    phishingSwitch(input())


def analyzePhish():
    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding="Latin-1") as f:
            msg = f.read()

        # Fixes issue with file name / dir name exceptions
        file = file.replace("//", "/")  # dir
        file2 = file.replace(" ", "")  # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(" Error Opening File")

    print("\n Extracting Headers...")
    try:
        print("   FROM:      ", str(msg.SenderName), ", ", str(msg.SenderEmailAddress))
        print("   TO:        ", str(msg.To))
        print("   SUBJECT:   ", str(msg.Subject))
        print("   NameBehalf:", str(msg.SentOnBehalfOfName))
        print("   CC:        ", str(msg.CC))
        print("   BCC:       ", str(msg.BCC))
        print("   Sent On:   ", str(msg.SentOn))
        print("   Created:   ", str(msg.CreationTime))
        s = str(msg.Body)
    except:
        print("   Header Error")
        f.close()

    print("\n Extracting Links... ")
    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r"https://urldefense.proofpoint.com/(v[0-9])/", b[0])
            if match:
                if match.group(1) == "v1":
                    decodev1(b[0])
                elif match.group(1) == "v2":
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(" No Links Found...")
    except:
        print("   Links Error")
        f.close()

    for each in linksFoundList:
        print("   %s" % each)

    print("\n Extracting Emails Addresses... ")
    try:
        match = r"([\w0-9._-]+@[\w0-9._-]+\.[\w0-9_-]+)"
        emailList = list()
        a = re.findall(match, s, re.M | re.I)

        for b in a:
            if b not in emailList:
                emailList.append(b)
                print(" ", b)
            if len(emailList) == 0:
                print("   No Emails Found")

        if len(a) == 0:
            print("   No Emails Found...")
    except:
        print("   Emails Error")
        f.close()

    print("\n Extracting IP's...")
    try:
        ipList = []
        foundIP = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s)
        ipList.append(foundIP)

        if not ipList:
            for each in ipList:
                print(each)
        else:
            print("   No IP Addresses Found...")
    except:
        print("   IP error")

    try:
        analyzeEmail(msg.SenderEmailAddress)
    except:
        print("")

    phishingMenu()


def haveIBeenPwned():
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = str(input(" Enter email: ").strip())
        haveIBeenPwnedPrintOut(acc)
    except:
        print("")
    phishingMenu()


def haveIBeenPwnedPrintOut(acc):
    try:
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/%s" % acc
        userAgent = "Sooty"
        headers = {
            "Content-Type": "application/json",
            "hibp-api-key": configvars.data["HIBP_API_KEY"],
            "user-agent": userAgent,
        }

        try:
            req = requests.get(url, headers=headers)
        except (requests.HTTPError, requests.RequestException, requests.Timeout, requests.ConnectionError):
            print(" Error retrieving Have I Been Pwned Data")
            return

        try:
            response = req.json()
        except requests.JSONDecodeError:
            print(" Unable to decode JSON response")
            return

        lr = len(response)

        if not lr:
            print(" No  Entries found in Database")
            return

        print("\n The account has been found in the following breaches: ")
        for each in range(lr):
            breach = "https://haveibeenpwned.com/api/v3/breach/%s" % response[each]["Name"]
            breachReq = requests.get(breach, headers=headers)
            breachResponse = breachReq.json()

            breachList = []
            print("\n   Title:        %s" % breachResponse["Title"])
            print("   Domain:       %s" % breachResponse["Domain"])
            print("   Breach Date:  %s" % breachResponse["BreachDate"])
            print("   Pwn Count:    %s" % breachResponse["PwnCount"])
            for each in breachResponse["DataClasses"]:
                breachList.append(each)
            print("   Data leaked: %s" % breachList)
    except:
        print("")


def analyzeEmailInput():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
    try:
        email = str(input(" Enter Email Address to Analyze: ").strip())
        analyzeEmail(email)
        phishingMenu()
    except:
        print("   Error Scanning Email Address")


def virusTotalAnalyze(result, sanitizedLink):
    linksDict["%s" % sanitizedLink] = str(result["positives"])
    # print(str(result['positives']))


def emailTemplateGen():
    print("\n--------------------")
    print("  Phishing Response")
    print("--------------------")

    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding="Latin-1") as f:
            msg = f.read()
        file = file.replace("//", "/")  # dir
        file2 = file.replace(" ", "")  # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(" Error importing email for template generator")

    url = "https://emailrep.io/"
    email = msg.SenderEmailAddress
    url = url + email
    responseRep = requests.get(url)
    req = responseRep.json()
    f = msg.To.split(" ", 1)[0]

    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r"https://urldefense.proofpoint.com/(v[0-9])/", b[0])
            if match:
                if match.group(1) == "v1":
                    decodev1(b[0])
                elif match.group(1) == "v2":
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(" No Links Found...")
    except:
        print("   Links Error")
        f.close()

    for each in linksFoundList:
        x = re.sub(r"\.", "[.]", each)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        sanitizedLink = x

    if "API Key" not in configvars.data["VT_API_KEY"]:
        try:  # EAFP
            url = "https://www.virustotal.com/vtapi/v2/url/report"
            for each in linksFoundList:
                link = each
                params = {"apikey": configvars.data["VT_API_KEY"], "resource": link}
                response = requests.get(url, params=params)
                result = response.json()
                if result["response_code"] == 0:
                    print(" [Warn] URL not found in VirusTotal database!")
                    continue
                if response.status_code == 200:
                    virusTotalAnalyze(result, sanitizedLink)

        except:
            print("\n Threshold reached for VirusTotal: \n   60 seconds remaining...")
            time.sleep(15)
            print("   45 seconds remaining...")
            time.sleep(15)
            print("   30 seconds remaining...")
            time.sleep(15)
            print("   15 seconds remaining...")
            time.sleep(15)
            virusTotalAnalyze(result, sanitizedLink)
    else:
        print("No API Key set, results will not show malicious links")

    rc = "potentially benign"
    threshold = "1"

    if (
        req["details"]["spam"]
        or req["suspicious"]
        or req["details"]["blacklisted"]
        or req["details"]["malicious_activity"]
    ):
        rc = "potentially suspicious"

    for key, value in linksDict.items():
        if int(value) >= int(threshold):
            rc = "potentially malicious"

    if responseRep.status_code == 200:
        print(
            "\nHi %s," % f,
        )
        print("\nThanks for your recent submission.")
        print("\nI have completed my analysis of the submitted mail and have classed it is as %s." % rc)
        print("\nThe sender has a reputation score of %s," % req["reputation"], "for the following reasons: ")

        if req["details"]["spam"]:
            print(" - The sender has been reported for sending spam in the past.")
        if req["suspicious"]:
            print(" - It has been marked as suspicious on reputation checking websites.")
        if req["details"]["free_provider"]:
            print(" - The sender is using a free provider.")
        if req["details"]["days_since_domain_creation"] < 365:
            print(" - The domain is less than a year old.")
        if req["details"]["blacklisted"]:
            print(" - It has been blacklisted on several sites.")
        if req["details"]["data_breach"]:
            print(" - Has been seen in data breaches")
        if req["details"]["credentials_leaked"]:
            print(" - The credentials have been leaked for this address")
        if req["details"]["malicious_activity"]:
            print(" - This sender has been flagged for malicious activity.")

        malLink = 0  # Controller for mal link text
        for each in linksDict.values():
            if int(threshold) <= int(each):
                malLink = 1

        if malLink == 1:
            print("\nThe following potentially malicious links were found embedded in the body of the mail:")
            for key, value in linksDict.items():
                if int(value) >= int(threshold):
                    print(" - %s" % key)

        print("\nAs such, I would recommend the following: ")

        if "suspicious" in rc:
            print(" - Delete and Ignore the mail for the time being.")

        if "malicious" in rc:
            print(" - If you clicked any links or entered information into any displayed webpages let us know asap.")

        if "spam" in rc:
            print(" - If you were not expecting the mail, please delete and ignore.")
            print(" - We would advise you to use your email vendors spam function to block further mails.")

        if "task" in rc:
            print(" - If you completed any tasks asked of you, please let us know asap.")
            print(" - If you were not expecting the mail, please delete and ignore.")

        if "benign" in rc:
            print(" - If you were not expecting this mail, please delete and ignore.")
            print(
                "\nIf you receive further mails from this sender, you can use your mail vendors spam function to block further mails."
            )

        if "suspicious" or "malicious" or "task" in rc:
            print(
                "\nI will be reaching out to have this sender blocked to prevent the sending of further mails as part of our remediation effort."
            )
            print("For now, I would recommend to simply delete and ignore this mail.")
            print("\nWe appreciate your diligence in reporting this mail.")

        print("\nRegards,")


def criminalipMenu():
    api_key: str = configvars.data.get("CRIMINAL_IP_API_KEY", None)

    if api_key:
        url = input(" Enter the IP to be checked: ").strip()
        criminalip.main(api_key, url)
    else:
        print("Missing configuration for criminalip in the config.yaml file.")


def phishtankModule():
    if "phishtank" in configvars.data:
        url = input(" Enter the URL to be checked: ").strip()
        download, appname, api = (
            configvars.data["phishtank"]["download"],
            configvars.data["phishtank"]["appname"],
            configvars.data["phishtank"]["api"],
        )
        phishtank.main(download, appname, api, url)
    else:
        print("Missing configuration for phishtank in the config.yaml file.")


def criminalipModule():
    pass


def switch_menu(choice: int) -> bool:
    if choice == 0:
        return False

    if choice < 0 or choice > 9 or not isinstance(choice, int):
        rprint("[red] Invalid choice. Please try again.")
        return True

    if choice == 1:
        url_sanitise()
    elif choice == 2:
        decoder_menu()
    elif choice == 3:
        repChecker()
    elif choice == 4:
        dns_menu()
    elif choice == 5:
        hash_menu()
    elif choice == 6:
        phishingMenu()
    elif choice == 7:
        urlscanio()
    elif choice == 8:
        criminalipMenu()
    elif choice == 9:
        extras_menu()

    return True


def mainMenu() -> None:
    while True:
        print()
        print(" --------------------------------- ")
        rprint("[green]           S  O  O  T  Y           ")
        print(" --------------------------------- ")
        print()
        print(" 1: Sanitise URL For emails")
        print(" 2: Decoders (PP, URL, SafeLinks)")
        print(" 3: Reputation Checker")
        print(" 4: DNS Tools")
        print(" 5: Hashing Function")
        print(" 6: Phishing Analysis")
        print(" 7: URL scan")
        print(" 8: Criminal IP")
        print(" 9: Extras")
        print()
        print(" 0: Exit Tool")

        if not switch_menu(int(input(" What would you like to do? "))):
            break

    return None


if __name__ == "__main__":
    titleLogo()
    mainMenu()
