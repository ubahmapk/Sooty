import re
from datetime import datetime
from pathlib import Path

from rich import print as rprint


def analyzeEmail(email):
    try:
        url = "https://emailrep.io/"
        userAgent = "Sooty"
        summary = "?summary=true"
        url = url + email + summary
        if "API Key" not in configvars.data["EMAILREP_API_KEY"]:
            erep_key = configvars.data["EMAILREP_API_KEY"]
            headers = {
                "Content-Type": "application/json",
                "Key": configvars.data["EMAILREP_API_KEY"],
                "User-Agent": userAgent,
            }
            response = requests.get(url, headers=headers)
        else:
            response = requests.get(url)
        req = response.json()
        emailDomain = re.split("@", email)[1]

        print("\n Email Analysis Report ")
        if response.status_code == 400:
            print(" Invalid Email / Bad Request")
        if response.status_code == 401:
            print(" Unauthorized / Invalid API Key (for Authenticated Requests)")
        if response.status_code == 429:
            print(" Too many requests, ")
        if response.status_code == 200:
            now = datetime.now()  # current date and time
            today = now.strftime("%m-%d-%Y")
            if not os.path.exists("output/" + today):
                os.makedirs("output/" + today)
            f = open("output/" + today + "/" + str(email) + ".txt", "w+")
            f.write("\n --------------------------------- ")
            f.write("\n   Email Analysis Report : ")
            f.write("\n ---------------------------------\n ")

            print("   Email:       %s" % req["email"])
            print("   Reputation:  %s" % req["reputation"])
            print("   Suspicious:  %s" % req["suspicious"])
            print("   Spotted:     %s" % req["references"] + " Times")
            print("   Blacklisted: %s" % req["details"]["blacklisted"])
            print("   Last Seen:   %s" % req["details"]["last_seen"])
            print("   Known Spam:  %s" % req["details"]["spam"])

            f.write("  Email:       %s" % req["email"])
            f.write("\n   Reputation:  %s" % req["reputation"])
            f.write("\n   Suspicious:  %s" % req["suspicious"])
            f.write("\n   Spotted:     %s" % req["references"] + " Times")
            f.write("\n   Blacklisted: %s" % req["details"]["blacklisted"])
            f.write("\n   Last Seen:   %s" % req["details"]["last_seen"])
            f.write("\n   Known Spam:  %s" % req["details"]["spam"])

            print("\n Domain Report ")
            print("   Domain:        @%s" % emailDomain)
            print("   Domain Exists: %s" % req["details"]["domain_exists"])
            print("   Domain Rep:    %s" % req["details"]["domain_reputation"])
            print("   Domain Age:    %s" % req["details"]["days_since_domain_creation"] + " Days")
            print("   New Domain:    %s" % req["details"]["new_domain"])
            print("   Deliverable:   %s" % req["details"]["deliverable"])
            print("   Free Provider: %s" % req["details"]["free_provider"])
            print("   Disposable:    %s" % req["details"]["disposable"])
            print("   Spoofable:     %s" % req["details"]["spoofable"])

            f.write("\n\n --------------------------------- ")
            f.write("\n   Domain Report ")
            f.write("\n --------------------------------- \n")
            f.write("\n   Domain:        @%s" % emailDomain)
            f.write("\n   Domain Exists: %s" % req["details"]["domain_exists"])
            f.write("\n   Domain Rep:    %s" % req["details"]["domain_reputation"])
            f.write("\n   Domain Age:    %s" % req["details"]["days_since_domain_creation"] + " Days")
            f.write("\n   New Domain:    %s" % req["details"]["new_domain"])
            f.write("\n   Deliverable:   %s" % req["details"]["deliverable"])
            f.write("\n   Free Provider: %s" % req["details"]["free_provider"])
            f.write("\n   Disposable:    %s" % req["details"]["disposable"])
            f.write("\n   Spoofable:     %s" % req["details"]["spoofable"])

            print("\n Malicious Activity Report ")
            print("   Malicious Activity: %s" % req["details"]["malicious_activity"])
            print("   Recent Activity:    %s" % req["details"]["malicious_activity_recent"])
            print("   Credentials Leaked: %s" % req["details"]["credentials_leaked"])
            print("   Found in breach:    %s" % req["details"]["data_breach"])

            f.write("\n\n --------------------------------- ")
            f.write("\n   Malicious Activity Report ")
            f.write("\n --------------------------------- \n")
            f.write("\n   Malicious Activity: %s" % req["details"]["malicious_activity"])
            f.write("\n   Recent Activity:    %s" % req["details"]["malicious_activity_recent"])
            f.write("\n   Credentials Leaked: %s" % req["details"]["credentials_leaked"])
            f.write("\n   Found in breach:    %s" % req["details"]["data_breach"])

            if req["details"]["data_breach"]:
                try:
                    url = "https://haveibeenpwned.com/api/v3/breachedaccount/%s" % email
                    headers = {
                        "Content-Type": "application/json",
                        "hibp-api-key": configvars.data["HIBP_API_KEY"],
                        "user-agent": userAgent,
                    }

                    try:
                        reqHIBP = requests.get(url, headers=headers)
                        response = reqHIBP.json()
                        lr = len(response)
                        if lr != 0:
                            print("\nThe account has been found in the following breaches: ")
                            for each in range(lr):
                                breach = "https://haveibeenpwned.com/api/v3/breach/%s" % response[each]["Name"]
                                breachReq = requests.get(breach, headers=headers)
                                breachResponse = breachReq.json()
                                breachList = []
                                print("   Title:        %s" % breachResponse["Title"])
                                print("   Breach Date:  %s" % breachResponse["BreachDate"])
                                f.write("\n   Title:        %s" % breachResponse["Title"])
                                f.write("\n   Breach Date:  %s" % breachResponse["BreachDate"])

                                for each in breachResponse["DataClasses"]:
                                    breachList.append(each)
                                print("   Data leaked: %s" % breachList, "\n")
                                f.write("\n   Data leaked: %s" % breachList, "\n")
                    except:
                        print(" Error")
                except:
                    print(" No API Key Found")
            print("\n Profiles Found ")
            f.write("\n\n --------------------------------- ")
            f.write("\n   Profiles Found ")
            f.write("\n --------------------------------- \n")

            if len(req["details"]["profiles"]) != 0:
                profileList = req["details"]["profiles"]
                for each in profileList:
                    print("   - %s" % each)
                    f.write("\n   - %s" % each)
            else:
                print("   No Profiles Found For This User")
                f.write(" \n  No Profiles Found For This User")

            print("\n Summary of Report: ")
            f.write("\n\n --------------------------------- ")
            f.write("\n   Summary of Report: ")
            f.write("\n ---------------------------------\n ")
            repSum = req["summary"]
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                print("   %s" % each)
                f.write("\n   %s" % each)
            f.close()

    except:
        print(" Error Analyzing Submitted Email")
        f.write("\n Error Analyzing Submitted Email")
        f.close()


def repChecker():
    print()
    print(" --------------------------------- ")
    rprint("[green] R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    print()

    rawInput = input("Enter IP, URL or Email Address: ").split()
    ip = str(rawInput[0])

    s = re.findall(r"\S+@\S+", ip)
    if s:
        print(" Email Detected...")
        analyzeEmail("".join(s))
    else:
        whoIsPrint(ip)
        wIP = socket.gethostbyname(ip)
        today = datetime.now().strftime("%m-%d-%Y")
        outputdir: Path = Path(f"output/{today}")

        if not outputdir.exists:
            Path.mkdir(outputdir)

        with Path.open(outputdir / f"{rawInput!s}.txt", "a+") as f:
            print("\n VirusTotal Report:")
            f.write("\n --------------------------------- ")
            f.write("\n VirusTotal Report:")
            f.write("\n --------------------------------- \n")

            url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {"apikey": configvars.data["VT_API_KEY"], "resource": wIP}
            response = requests.get(url, params=params)
            pos: int = 0  # Total positives found in VT
            tot: int = 0  # Total number of scans

            if response.status_code != 200:
                print(" There's been an error, check your API Key or VirusTotal may be down")

            try:
                result = response.json()
                for each in result:
                    tot = result["total"]
                    if result["positives"] != 0:
                        pos = pos + 1
                    avg = pos / tot
                    print("   No of Databases Checked: " + str(tot))
                    print("   No of Reportings: " + str(pos))
                    print("   Average Score:    " + str(avg))
                    print("   VirusTotal Report Link: " + result["permalink"])
                    f.write("\n\n No of Databases Checked: " + str(tot))
                    f.write("\n No of Reportings: " + str(pos))
                    f.write("\n Average Score: " + str(avg))
                    f.write("\n VirusTotal Report Link: " + result["permalink"])
            except ValueError:
                print("Unable to decode JSON data from VT response")

    try:
        TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
        req = requests.get(TOR_URL)
        print("\n TOR Exit Node Report: ")
        f.write("\n\n --------------------------------- ")
        f.write("\n TOR Exit Node Report: ")
        f.write("\n --------------------------------- \n")
        if req.status_code == 200:
            tl = req.text.split("\n")
            c = 0
            for i in tl:
                if wIP == i:
                    print("  " + i + " is a TOR Exit Node")
                    f.write("\n " + "  " + i + " is a TOR Exit Node")
                    c = c + 1
            if c == 0:
                print("  " + wIP + " is NOT a TOR Exit Node")
                f.write("\n " + wIP + " is NOT a TOR Exit Node")
        else:
            print("   TOR LIST UNREACHABLE")
            f.write("\n TOR LIST UNREACHABLE")
    except Exception as e:
        print("There is an error with checking for Tor exit nodes:\n" + str(e))

    print("\n Checking BadIP's... ")
    f.write("\n\n ---------------------------------")
    f.write("\n BadIP's Report : ")
    f.write("\n --------------------------------- \n")

    try:
        BAD_IPS_URL = "https://www.badips.com/get/info/" + wIP
        response = requests.get(BAD_IPS_URL)
        if response.status_code == 200:
            result = response.json()
            print("  " + str(result["suc"]))
            print("  Total Reports : " + str(result["ReporterCount"]["sum"]))
            print("\n  IP has been reported in the following Categories:")
            f.write("  " + str(result["suc"]))
            f.write("\n  Total Reports : " + str(result["ReporterCount"]["sum"]))
            f.write("\n  IP has been reported in the following Categories:")
            for each in result["LastReport"]:
                timeReport = datetime.fromtimestamp(result["LastReport"].get(each))
                print("   - " + each + ": " + str(timeReport))
                f.write("\n   - " + each + ": " + str(timeReport))
        else:
            print("  Error reaching BadIPs")
    except:
        print("  IP not found")  # Defaults to IP not found - not actually accurate
        f.write("\n  IP not found")

    print("\n ABUSEIPDB Report:")
    f.write("\n\n ---------------------------------")
    f.write("\n ABUSEIPDB Report:")
    f.write("\n ---------------------------------\n")

    try:
        AB_URL = "https://api.abuseipdb.com/api/v2/check"
        days = "180"

        querystring = {"ipAddress": wIP, "maxAgeInDays": days}

        headers = {"Accept": "application/json", "Key": configvars.data["AB_API_KEY"]}
        response = requests.request(method="GET", url=AB_URL, headers=headers, params=querystring)
        if response.status_code == 200:
            req = response.json()

            print("   IP:          " + str(req["data"]["ipAddress"]))
            print("   Reports:     " + str(req["data"]["totalReports"]))
            print("   Abuse Score: " + str(req["data"]["abuseConfidenceScore"]) + "%")
            print("   Last Report: " + str(req["data"]["lastReportedAt"]))
            f.write("\n\n IP:        " + str(req["data"]["ipAddress"]))
            f.write("\n Reports:     " + str(req["data"]["totalReports"]))
            f.write("\n Abuse Score: " + str(req["data"]["abuseConfidenceScore"]) + "%")
            f.write("\n Last Report: " + str(req["data"]["lastReportedAt"]))
            f.close()

        else:
            print("   Error Reaching ABUSE IPDB")
    except:
        print("   IP Not Found")

    print("\n\nChecking against IP blacklists: ")
    iplists.main(rawInput)

    mainMenu()
