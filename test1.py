import requests
from bs4 import BeautifulSoup
import collections
import re

# Fix for Python 3.10+ compatibility
if not hasattr(collections, 'Callable'):
    import collections.abc
    collections.Callable = collections.abc.Callable

# URL of the Snyk page
url = 'https://security.snyk.io/package/npm/jquery/2.1.0-beta2'

# Fetch the webpage content
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find vulnerabilities that contain 'vuln' in the URL
    vulnerabilities = soup.find_all('a', href=lambda href: href and 'vuln' in href)

    # Define keywords to exclude from the results
    exclude_keywords = ['npm', 'MIT', 'Report', 'Snyk Container', 'Disclosed Vulnerabilities', 'Snyk Vulnerability Database']

    # Output vulnerability data
    if vulnerabilities:
        print(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n")
        
        # Loop through and print each vulnerability, excluding unwanted ones
        for vulnerability in vulnerabilities:
            vuln_title = vulnerability.text.strip()  # Vulnerability name/title
            vuln_link = "https://security.snyk.io" + vulnerability['href']  # Full link to vulnerability details
            
            # Ensure the link starts with /vuln
            if vuln_link.startswith("https://security.snyk.iovuln"):
                vuln_link = vuln_link.replace("https://security.snyk.iovuln", "https://security.snyk.io/vuln")

            # Skip vulnerabilities containing excluded keywords
            if not any(keyword in vuln_title for keyword in exclude_keywords):
                print(f"Vulnerability: {vuln_title}")
                print(f"Details: {vuln_link}\n")
                
                # Fetch the CVE details from the vulnerability link
                vuln_response = requests.get(vuln_link)
                if vuln_response.status_code == 200:
                    vuln_soup = BeautifulSoup(vuln_response.content, 'html.parser')

                    # Use regex to find CVE IDs in the page content
                    cve_ids = vuln_soup.find_all(string=re.compile(r'\bCVE-\d{4}-\d{1,7}\b'))

                    # Capture the relevant details and filter out any result containing "window.__NUXT__"
                    if cve_ids:
                        for cve_id in cve_ids:
                            if "window.__NUXT__" not in cve_id:  # Exclude unwanted content
                                print(f"CVE ID: {cve_id.strip()}")
                    else:
                        print("No CVE details found.\n")
                else:
                    print(f"Failed to retrieve CVE details. Status code: {vuln_response.status_code}\n")
    else:
        print("No vulnerabilities found on this page.")
else:
    print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
