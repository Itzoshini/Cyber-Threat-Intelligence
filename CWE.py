from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import collections
import re

# Fix for Python 3.10+ compatibility
if not hasattr(collections, 'Callable'):
    import collections.abc
    collections.Callable = collections.abc.Callable

app = Flask(__name__)

def fetch_vulnerabilities(package_name, package_version):
    # Construct the URL dynamically
    url = f'https://security.snyk.io/package/npm/{package_name}/{package_version}'

    # Fetch the webpage content
    response = requests.get(url)

    vulnerabilities_list = []  # To store vulnerability data

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
            for vulnerability in vulnerabilities:
                vuln_title = vulnerability.text.strip()  # Vulnerability name/title
                vuln_link = "https://security.snyk.io" + vulnerability['href']  # Full link to vulnerability details
                
                # Ensure the link starts with /vuln
                if vuln_link.startswith("https://security.snyk.iovuln"):
                    vuln_link = vuln_link.replace("https://security.snyk.iovuln", "https://security.snyk.io/vuln")

                # Skip vulnerabilities containing excluded keywords
                if not any(keyword in vuln_title for keyword in exclude_keywords):
                    cve_ids_list = []
                    cwe_ids_list = []

                    # Fetch the CVE and CWE details from the vulnerability link
                    vuln_response = requests.get(vuln_link)
                    if vuln_response.status_code == 200:
                        vuln_soup = BeautifulSoup(vuln_response.content, 'html.parser')

                        # Use regex to find CVE IDs in the page content
                        cve_ids = vuln_soup.find_all(string=re.compile(r'\bCVE-\d{4}-\d{1,7}\b'))

                        # Attempt to find CWE IDs in structured elements (e.g., tables or lists)
                        cwe_elements = vuln_soup.find_all('a', href=re.compile(r'.*cwe.*'))
                        
                        # Capture the relevant details and filter out any unwanted content
                        if cve_ids:
                            for cve_id in cve_ids:
                                if "window.NUXT" not in cve_id:  # Exclude unwanted content
                                    cve_ids_list.append(cve_id.strip())

                        # Capture CWE IDs from the identified links or tags
                        if cwe_elements:
                            for cwe_element in cwe_elements:
                                cwe_id = cwe_element.text.strip()
                                if "CWE-" in cwe_id:  # Make sure it's a valid CWE ID
                                    cwe_ids_list.append(cwe_id)

                    vulnerabilities_list.append({
                        'vuln_title': vuln_title,
                        'vuln_link': vuln_link,
                        'cve_ids': cve_ids_list,
                        'cwe_ids': cwe_ids_list
                    })
        return vulnerabilities_list
    else:
        return None

@app.route('/')
def index():
    return render_template('cwe.html')
@app.route('/results', methods=['POST'])
def results():
    # Try to read the jQuery version from the file
    try:
        with open('jquery_version.txt', 'r') as f:
            package_version = f.read().strip()  # Get the version from the file
    except FileNotFoundError:
        return render_template('cwe1.html', package_name='jquery', package_version='N/A', vulnerabilities=[])

    package_name = 'jquery'  # Default package name to 'jquery'

    vulnerabilities = fetch_vulnerabilities(package_name, package_version)

    return render_template('cwe1.html', package_name=package_name, package_version=package_version, vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)
    