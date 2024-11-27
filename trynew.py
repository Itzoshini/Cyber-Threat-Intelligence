import requests
from bs4 import BeautifulSoup
import collections
import re

# Fix for Python 3.10+ compatibility
if not hasattr(collections, 'Callable'):
    import collections.abc
    collections.Callable = collections.abc.Callable

def get_jquery_version(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')
        
        jquery_link = None
        for script in script_tags:
            if script.get('src') and 'jquery' in script.get('src'):
                jquery_link = script.get('src')
                break
        
        if not jquery_link:
            print("jQuery link not found.")
            return None
        
        if not jquery_link.startswith('http'):
            jquery_link = requests.compat.urljoin(url, jquery_link)

        jquery_response = requests.get(jquery_link)
        jquery_response.raise_for_status()
        
        version_match = re.search(r'jQuery v?(\d+\.\d+\.\d+)', jquery_response.text)
        
        if version_match:
            return version_match.group(1)
        else:
            print("jQuery version not found.")
            return None
    
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return None

def check_exploit_availability(cve_id):
    url = "https://cve.mitre.org/data/refs/refmap/source-SUSE.html"
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_entry = soup.find(string=lambda text: cve_id in text)
        
        return cve_entry is not None
    else:
        print("Failed to retrieve the CVE reference page.")
        return False

def fetch_vulnerabilities(jquery_version):
    url = f'https://security.snyk.io/package/npm/jquery/{jquery_version}'
    
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        vulnerabilities = soup.find_all('a', href=lambda href: href and 'vuln' in href)

        exclude_keywords = ['npm', 'MIT', 'Report', 'Snyk Container', 'Disclosed Vulnerabilities', 'Snyk Vulnerability Database']

        if vulnerabilities:
            print(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n")
            
            for vulnerability in vulnerabilities:
                vuln_title = vulnerability.text.strip()
                vuln_link = "https://security.snyk.io" + vulnerability['href']
                
                if vuln_link.startswith("https://security.snyk.iovuln"):
                    vuln_link = vuln_link.replace("https://security.snyk.iovuln", "https://security.snyk.io/vuln")

                if not any(keyword in vuln_title for keyword in exclude_keywords):
                    print(f"Vulnerability: {vuln_title}")
                    print(f"Details: {vuln_link}\n")
                    
                    vuln_response = requests.get(vuln_link)
                    if vuln_response.status_code == 200:
                        vuln_soup = BeautifulSoup(vuln_response.content, 'html.parser')
                        cve_ids = vuln_soup.find_all(string=re.compile(r'\bCVE-\d{4}-\d{1,7}\b'))

                        if cve_ids:
                            for cve_id in cve_ids:
                                if "window.__NUXT__" not in cve_id:
                                    cve_id = cve_id.strip()
                                    print(f"CVE ID: {cve_id}")

                                    # Check for exploit availability
                                    if check_exploit_availability(cve_id):
                                        print(f"Exploit available for {cve_id}\n")
                                    else:
                                        print(f"Exploit not available for {cve_id}\n")
                        else:
                            print("No CVE details found.\n")
                    else:
                        print(f"Failed to retrieve CVE details. Status code: {vuln_response.status_code}\n")
        else:
            print("No vulnerabilities found on this page.")
    else:
        print(f"Failed to retrieve the webpage. Status code: {response.status_code}")

# Get the URL from user input to find the jQuery version
dynamic_url = input("Enter the dynamic URL: ")
jquery_version = get_jquery_version(dynamic_url)

if jquery_version:
    print(f"Detected jQuery version: {jquery_version}")
    fetch_vulnerabilities(jquery_version)
