import requests
import os
import urllib.parse
import re
import datetime
import publicsuffixlist
import sys


psl = publicsuffixlist.PublicSuffixList()

LIST_FILENAME = "list.txt"
STATUS_FILENAME = "status.txt"
DOMAIN_FILENAME = "domains.txt"

# Define filter lists to combine
lists = {
    "HaGeZi's Pro DNS Blocklist": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
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

# External lists for filtering (also must all succeed)
external_lists = {
    "excludes": "https://raw.githubusercontent.com/iam-py-test/allowlist/main/filter.txt",
    "subdomains_1": "https://raw.githubusercontent.com/iam-py-test/tracker_analytics/main/kdl.txt",
    "subdomains_2": "https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt",
    "subdomains_3": "https://raw.githubusercontent.com/iam-py-test/cloudflare-usage/main/cnames.txt",
    "dead": "https://raw.githubusercontent.com/iam-py-test/my_filters_001/refs/heads/main/dead.mwbcheck.txt"
}

def download_all_sources():
    """Download all sources and return data, or None if any fails"""
    downloaded_data = {}
    failed_sources = []
    
    print("="*60)
    print("STARTING DOWNLOAD OF ALL FILTER SOURCES")
    print("="*60)
    
    # Download main filter lists
    print(f"\n📋 Downloading {len(lists)} main filter lists:")
    for name, url in lists.items():
        print(f"  ⬇️  {name}")
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # Raises exception for HTTP errors
            downloaded_data[name] = response.text.split("\n")
            print(f"  ✅ Success - {len(downloaded_data[name])} lines")
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed_sources.append(f"Main filter: {name}")
    
    # Download external lists
    print(f"\n🔧 Downloading {len(external_lists)} external filter lists:")
    for name, url in external_lists.items():
        print(f"  ⬇️  {name}")
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            downloaded_data[name] = response.text.split("\n")
            print(f"  ✅ Success - {len(downloaded_data[name])} lines")
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed_sources.append(f"External list: {name}")
    
    # Check if all downloads succeeded
    if failed_sources:
        print("\n" + "="*60)
        print("❌ DOWNLOAD FAILED - STOPPING WORKFLOW")
        print("="*60)
        print("The following sources could not be downloaded:")
        for source in failed_sources:
            print(f"  • {source}")
        print("\n🛑 Workflow stopped to prevent incomplete filter list generation.")
        print("💡 The workflow will retry in 4 hours automatically.")
        print("🔄 Or you can manually trigger it when sources are back online.")
        return None, failed_sources
    
    print("\n" + "="*60)
    print("✅ ALL SOURCES DOWNLOADED SUCCESSFULLY")
    print("="*60)
    return downloaded_data, []

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

def parselist(l, curl="", downloaded_data=None):
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
        elif line in downloaded_data["excludes"]:
            continue
        elif line == "":
            continue
        elif edomain != "" and edomain in donedomains:
            continue
        elif edomain in downloaded_data["dead"] and edomain != "" and edomain != None:
            continue
        elif line.startswith("!#include "):
            try:
                incpath = urllib.parse.urljoin(curl, line[10:], allow_fragments=True)
                inccontents = requests.get(incpath, timeout=30).text.replace("\r", "").split("\n")
                endcontents = parselist(inccontents, incpath, downloaded_data)
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

# Main execution
def main():
    global donelines, donedomains, eadd, ered
    
    # Download all sources first
    downloaded_data, failed_sources = download_all_sources()
    
    # If any downloads failed, exit without writing files
    if downloaded_data is None:
        sys.exit(0)  # Exit gracefully (success code so workflow doesn't show as failed)
    
    # All downloads succeeded, proceed with processing
    print("\n🔄 Processing downloaded filter lists...")
    
    donelines = []
    donedomains = []
    eadd = 0
    ered = 0
    
    mainlist = """! Title: Custom uBlock Origin Combo List
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/NaveenPNair/uBlock-Origin-Filterlist-Generator
! Combined from {} filter lists

""".format(datetime.date.today().strftime("%d/%m/%Y"), len(lists))

    # Process each filter list
    for clist in lists:
        print(f"📝 Processing: {clist}")
        mainlist += parselist(downloaded_data[clist], lists[clist], downloaded_data)
        print(f"✅ Processed: {clist}")

    # Combine subdomains
    subdomains = downloaded_data["subdomains_1"] + downloaded_data["subdomains_2"] + downloaded_data["subdomains_3"]
    
    # Write all output files
    print("\n💾 Writing output files...")
    
    # Write the combined list
    with open(LIST_FILENAME, "w", encoding="UTF-8") as f:
        f.write(mainlist)
    print(f"✅ Written combined list to {LIST_FILENAME}")

    # Extract just domains
    justdomains = []
    for d in donedomains:
        if "/" not in d and "." in d and "*" not in d and d != "" and d.endswith(".") == False and isipdomain(d) == False:
            justdomains.append(d)

    with open(DOMAIN_FILENAME, "w", encoding="UTF-8") as f:
        f.write("\n".join(justdomains))
    print(f"✅ Written domain list to {DOMAIN_FILENAME}")

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
    with open("domains_subdomains.txt", "w", encoding="UTF-8") as f:
        f.write("\n".join(domainplussub))
    print(f"✅ Written domains+subdomains to domains_subdomains.txt")

    # Write status
    with open(STATUS_FILENAME, 'w') as status:
        status.write("""Stats:
{} entries added
{} redundant entries removed  
{} domains extracted
{} subdomains added
{} filter lists processed successfully
""".format(eadd, ered, len(donedomains), subsfound, len(lists)))
    print(f"✅ Written stats to {STATUS_FILENAME}")

    print("\n" + "="*60)
    print("🎉 COMBO LIST GENERATION COMPLETE")
    print("="*60)
    print(f"📊 Total entries: {eadd}")
    print(f"🌐 Unique domains: {len(donedomains)}")
    print(f"📁 Main output: {LIST_FILENAME}")
    print("🚀 Files ready for commit and push!")

if __name__ == "__main__":
    main()