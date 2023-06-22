import argparse
import socket
import os

from gevent import monkey

monkey.patch_all()

import requests
from gevent.pool import Pool

requests.packages.urllib3.disable_warnings()


RATE_LIMIT = 5  # Default rate limit in requests per second
OUTPUT_DIRECTORY = "C:\\Users\\mosic\\OneDrive\\Desktop\\Amazon\\Amazon Results\\"  # Specify the desired output directory here
USER_AGENT = "amazonvrpresearcher_whenallelsefails@hacker1"


def main(domain, url):
    domainsFound = {}
    domainsNotFound = {}
    print("[+]: Downloading domain list from crt.sh...")
    response = collectResponse(domain)
    print("[+]: Download of domain list complete.")
    domains = collectDomains(response)
    print("[+]: Parsed %s domain(s) from list." % len(domains))
    if len(domains) == 0:
        exit(1)

    pool = Pool(RATE_LIMIT)
    greenlets = [pool.spawn(resolve, domain) for domain in domains]
    pool.join(timeout=1)
    for greenlet in greenlets:
        result = greenlet.value
        if result:
            for ip in result.values():
                if ip != 'none':
                    domainsFound.update(result)
                else:
                    domainsNotFound.update(result)

    output_directory = OUTPUT_DIRECTORY

    if domain:
        print("\n[+]: Domains found:")
        printDomains(domains)

        domain_output_file = os.path.join(output_directory, "domain_output.txt")
        saveToFile(domain_output_file, domains)
        print("\n[+]: Domains found (saved to file):", domain_output_file)

    if url:
        print("\n[+]: IP addresses found:")
        printIPAddresses(domainsFound)

        ip_output_file = os.path.join(output_directory, "ip_output.txt")
        saveToFile(ip_output_file, domainsFound.values())
        print("\n[+]: IP addresses found (saved to file):", ip_output_file)

    print("\n[+]: Domains with no DNS record:")
    printDomains(domainsNotFound)


def resolve(domain):
    try:
        return {domain: socket.gethostbyname(domain)}
    except:
        return {domain: "none"}


def printDomains(domains):
    for domain in sorted(domains):
        print(domain)


def printIPAddresses(domains):
    for domain, ip in sorted(domains.items()):
        print("%s\t%s" % (ip, domain))


def collectResponse(domain):
    url = 'https://crt.sh/?q=' + domain + '&output=json'
    headers = {'User-Agent': USER_AGENT}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except:
        print("[!]: Connection to server failed.")
        exit(1)
    try:
        domains = response.json()
        return domains
    except:
        print("[!]: The server did not respond with valid JSON.")
        exit(1)


def collectDomains(response):
    domains = set()
    for domain in response:
        domains.add(domain['common_name'])
        if '\n' in domain['name_value']:
            domlist = domain['name_value'].split()
            for dom in domlist:
                domains.add(dom)
        else:
            domains.add(domain['name_value'])
    return domains


def saveToFile(filename, data):
    try:
        with open(filename, 'w') as f:
            for item in data:
                f.write("%s\n" % item)
    except IOError:
        print("[!]: Error saving data to file.")



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", type=str, required=True,
                        help="domain to query for CT logs, e.g.: domain.com")
    parser.add_argument("-u", "--urls", default=False, action="store_true",
                         help="output results with https:// urls for domains that resolve, one per line.")
    args = parser.parse_args()



    main(args.domain, args.urls)