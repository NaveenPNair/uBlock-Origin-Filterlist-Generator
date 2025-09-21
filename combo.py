import requests
import os
import urllib.parse
import re
import datetime
import publicsuffixlist


psl = publicsuffixlist.PublicSuffixList()

LIST_FILENAME = "list.txt"
STATUS_FILENAME = "status.txt"
DOMAIN_FILENAME = "domains.txt"

# Define filter lists to combine
lists = {
    "Bypass Paywalls Clean filter": "https://gitflic.ru/project/magnolia1234/bypass-paywalls-clean-filters/blob/raw?file=bpc-paywall-filter.txt",
    "Browse websites without logging in": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/BrowseWebsitesWithoutLoggingIn.txt",
    "FMHY Unsafe sites filterlist - Plus": "https://raw.githubusercontent.com/fmhy/FMHYFilterlist/main/filterlist.txt",
    "Hide YouTube Shorts": "https://raw.githubusercontent.com/gijsdev/ublock-hide-yt-shorts/master/list.txt",
    "Anti-paywall filters": "https://raw.githubusercontent.com/liamengland1/miscfilters/master/antipaywall.txt",
    "yokoffing's Annoyance List": "https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt",
    "Adult Annoyances List": "https://raw.githubusercontent.com/yokoffing/filterlists/refs/heads/main/adult_annoyance_list.txt",
    "Huge AI Blocklist": "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/main/list.txt",
    "Dandelion Sprout's Anti-Malware List": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
    "The malicious website blocklist": "https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_lite.txt",
    "iam-py-test's antitypo list": "https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/antitypo.txt",
    "Actually Legitimate URL Shortener Tool": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "uBlock Sync": "https://gist.githubusercontent.com/NaveenPNair/d327b1d05009923291698201c41357f7/raw/e16a42775bec6cf8a3d221dd0385268474270736/uBlock%2520Sync.txt"
}

donelines = []
donedomains = []

# Download external lists with basic error handling
try:
    excludes = requests.get("https://raw.githubusercontent.com/iam-py-test/allowlist/main/filter.txt", timeout=30).text.split("\n")
except:
    print("Warning: Could not download excludes list, continuing without it")
    excludes = []

try:
    subdomains = requests.get("https://raw.githubusercontent.com/iam-py-test/tracker_analytics/main/kdl.txt", timeout=30).text.split("\n")
    subdomains += requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt", timeout=30).text.split("\n")
    subdomains += requests.get("https://raw.githubusercontent.com/iam-py-test/cloudflare-usage/main/cnames.txt", timeout=30).text.split("\n")
except:
    print("Warning: Could not download subdomains list, continuing without it")
    subdomains = []

try:
    dead = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/refs/heads/main/dead.mwbcheck.txt", timeout=30).text.split("\n")
except:
    print("Warning: Could not download dead domains list, continuing without it")
    dead = []

# IP address detection patterns
is_ip_v4 = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
is_ip_v6 = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
is_ip_v4_reg = re.compile(is_ip_v4)
is_ip_v6_reg = re.compile(is_ip_v6)

def isipdomain(domain):
    if re.search(is_ip_v4_reg, domain):
        return True
    if re.search(is_ip_v6_reg, domain):
        return True
    return False

def extdomain(line):
    try:
        domain = ""
        if line.startswith("||") and line.endswith("^$all"):
            domain = line[2:-5]
        if line.startswith("||") and line.endswith("^$doc"):
            domain = line[2:-5]
        if line.startswith("||") and line.endswith("^$document"):
            domain = line[2:-10]
        if line.startswith("||") and line.endswith("^$3p"):
            domain = line[2:-5]
        elif line.startswith("||") and line.endswith("^$all,~inline-font,~inline-script"):
            domain = line[2:-33]
        elif line.startswith("||") and line.endswith("^"):
            domain = line[2:-1]
        elif line.startswith("||") and line.endswith("^$all,~inline-font"):
            domain = line[2:-18]
        elif line.startswith("||") and line.endswith("^$doc,popup"):
            domain = line[2:-11]
        elif line.startswith("||") and line.endswith("^$all,~inline-script"):
            domain = line[2:-20]
        return domain
    except:
        return ""

mainlist = """! Title: Custom uBlock Origin Combo List
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/NaveenPNair/uBlock-Origin-Filterlist-Generator
! Combined from {} filter lists

""".format(datetime.date.today().strftime("%d/%m/%Y"), len(lists))

eadd = 0
ered = 0

def parselist(l, curl=""):
    global donedomains
    global donelines
    global eadd
    global ered
    plist = ""
    for line in l:
        line = line.strip()
        edomain = extdomain(line)
        if (line.startswith("!") or line.startswith("#")) and "include" not in line:
            continue
        elif line.startswith("[Adblock") and line.endswith("]"):
            continue
        elif line in donelines:
            ered += 1
        elif line in excludes:
            continue
        elif line == "":
            continue
        elif edomain != "" and edomain in donedomains:
            continue
        elif edomain in dead and edomain != "" and edomain != None:
            continue
        elif line.startswith("!#include "):
            try:
                incpath = urllib.parse.urljoin(curl, line[10:], allow_fragments=True)
                inccontents = requests.get(incpath, timeout=30).text.replace("\r", "").split("\n")
                endcontents = parselist(inccontents, incpath)
                plist += "{}\n".format(endcontents)
            except Exception as err:
                print("Warning: Could not include", line, "Error:", err)
        else:
            plist += "{}\n".format(line)
            eadd += 1
            donelines.append(line)
            if edomain != "" and edomain != " ":
                donedomains.append(edomain)
    return plist

# Process each filter list
for clist in lists:
    print(f"Processing: {clist}")
    try:
        l = requests.get(lists[clist], timeout=30).text.split("\n")
        mainlist += parselist(l, lists[clist])
        print(f"✓ Successfully processed: {clist}")
    except Exception as err:
        print(f"✗ Error processing {clist}: {err}")

# Write the combined list
try:
    with open(LIST_FILENAME, "w", encoding="UTF-8") as f:
        f.write(mainlist)
    print(f"✓ Written combined list to {LIST_FILENAME}")
except Exception as err:
    print(f"✗ Error writing list file: {err}")

# Extract just domains
justdomains = []
for d in donedomains:
    if "/" not in d and "." in d and "*" not in d and d != "" and d.endswith(".") == False and isipdomain(d) == False:
        justdomains.append(d)

try:
    with open(DOMAIN_FILENAME, "w", encoding="UTF-8") as f:
        f.write("\n".join(justdomains))
    print(f"✓ Written domain list to {DOMAIN_FILENAME}")
except Exception as err:
    print(f"✗ Error writing domain file: {err}")

# Add subdomains
subsfound = 0
domainplussub = justdomains.copy()
for sub in subdomains:
    try:
        maindomain = psl.privatesuffix(sub)
        if maindomain in domainplussub and sub not in domainplussub:
            subsfound += 1
            domainplussub.append(sub)
    except Exception as err:
        print(f"Warning: Error processing subdomain {sub}: {err}")

# Write domains with subdomains
try:
    with open("domains_subdomains.txt", "w", encoding="UTF-8") as f:
        f.write("\n".join(domainplussub))
    print(f"✓ Written domains+subdomains to domains_subdomains.txt")
except Exception as err:
    print(f"✗ Error writing domains+subdomains file: {err}")

# Write status
try:
    with open(STATUS_FILENAME, 'w') as status:
        status.write("""Stats:
{} entries added
{} redundant entries removed  
{} domains extracted
{} subdomains added
{} filter lists processed successfully
""".format(eadd, ered, len(donedomains), subsfound, len(lists)))
    print(f"✓ Written stats to {STATUS_FILENAME}")
except Exception as err:
    print(f"✗ Error writing status file: {err}")

print("\n" + "="*50)
print("COMBO LIST GENERATION COMPLETE")
print("="*50)
print(f"Total entries: {eadd}")
print(f"Unique domains: {len(donedomains)}")
print(f"Output file: {LIST_FILENAME}")