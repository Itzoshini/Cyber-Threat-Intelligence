from flask import Flask, render_template, request, redirect, url_for,jsonify
import requests
from bs4 import BeautifulSoup
import collections
import re

# Fix for Python 3.10+ compatibility
if not hasattr(collections, 'Callable'):
    import collections.abc
    collections.Callable = collections.abc.Callable

app = Flask(__name__)

# Function to extract jQuery version from the provided URL
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
            return None, "jQuery link not found."

        if not jquery_link.startswith('http'):
            jquery_link = requests.compat.urljoin(url, jquery_link)

        jquery_response = requests.get(jquery_link)
        jquery_response.raise_for_status()
        
        version_match = re.search(r'jQuery v?(\d+\.\d+\.\d+)', jquery_response.text)
        if version_match:
            return version_match.group(1), None
        else:
            return None, "jQuery version not found."
    
    except requests.RequestException as e:
        return None, f"Error fetching URL: {e}"

# Function to check for exploit availability
def check_exploit_availability(cve_id):
    url = "https://cve.mitre.org/data/refs/refmap/source-SUSE.html"
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_entry = soup.find(string=lambda text: cve_id in text)
        return cve_entry is not None
    else:
        return False

# Function to fetch vulnerabilities for jQuery version
def fetch_vulnerabilities(jquery_version):
    url = f'https://security.snyk.io/package/npm/jquery/{jquery_version}'
    response = requests.get(url)
    vulnerabilities_data = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        vulnerabilities = soup.find_all('a', href=lambda href: href and 'vuln' in href)
        exclude_keywords = ['npm', 'MIT', 'Report', 'Snyk Container', 'Disclosed Vulnerabilities', 'Snyk Vulnerability Database']

        for vulnerability in vulnerabilities:
            vuln_title = vulnerability.text.strip()
            vuln_link = "https://security.snyk.io" + vulnerability['href']
            
            if vuln_link.startswith("https://security.snyk.iovuln"):
                vuln_link = vuln_link.replace("https://security.snyk.iovuln", "https://security.snyk.io/vuln")

            if not any(keyword in vuln_title for keyword in exclude_keywords):
                vuln_data = {
                    'vuln_title': vuln_title,
                    'vuln_link': vuln_link,
                    'cve_ids': []
                }

                # Fetch CVE details from the vulnerability page
                vuln_response = requests.get(vuln_link)
                if vuln_response.status_code == 200:
                    vuln_soup = BeautifulSoup(vuln_response.content, 'html.parser')
                    cve_ids = vuln_soup.find_all(string=re.compile(r'\bCVE-\d{4}-\d{1,7}\b'))

                    for cve_id in cve_ids:
                        if "window.__NUXT__" not in cve_id:
                            cve_id = cve_id.strip()
                            exploit_available = check_exploit_availability(cve_id)
                            vuln_data['cve_ids'].append({
                                'cve_id': cve_id,
                                'exploit_available': exploit_available
                            })
                vulnerabilities_data.append(vuln_data)
        return vulnerabilities_data, None
    else:
        return None, f"Failed to retrieve the webpage. Status code: {response.status_code}"
def check_rapid7_metasploit(cve_id):
    """Check Rapid7/Metasploit database for exploit availability"""
    try:
        url = f"https://www.rapid7.com/db/search?q={cve_id}&type=nexpose"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return cve_id.lower() in response.text.lower()
        
    except Exception as e:
        print(f"Rapid7 check failed: {e}")
        return False

def check_vulners_db(cve_id):
    """Check Vulners database for exploit availability"""
    try:
        url = f"https://vulners.com/search?query={cve_id}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        exploit_keywords = ['exploit-db', 'metasploit', 'packetstorm']
        return any(keyword in response.text.lower() for keyword in exploit_keywords)
        
    except Exception as e:
        print(f"Vulners check failed: {e}")
        return False

def check_exploit_availability(cve_id):
    """Check multiple sources for exploit availability"""
    rapid7_result = check_rapid7_metasploit(cve_id)
    vulners_result = check_vulners_db(cve_id)
    return rapid7_result or vulners_result

def fetch_cve_details(cve_id):
    """Fetch CVE details from NVD"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        if 'vulnerabilities' not in data or not data['vulnerabilities']:
            return None
            
        vuln = data['vulnerabilities'][0]['cve']
        
        cve_info = {
            'description': '',
            'cvss_score': '',
            'exploit_available': False,
            'vulnerability_types': [],
            'references': []
        }
        
        cve_info['exploit_available'] = check_exploit_availability(cve_id)
        
        if 'descriptions' in vuln:
            for desc in vuln['descriptions']:
                if desc['lang'] == 'en':
                    cve_info['description'] = desc['value']
                    break
        
        metrics = vuln.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cve_info['cvss_score'] = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            cve_info['cvss_score'] = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            cve_info['cvss_score'] = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        
        if 'references' in vuln:
            cve_info['references'] = [ref['url'] for ref in vuln['references']]
            
        return format_output(cve_id, cve_info)
        
    except requests.RequestException as e:
        return f"Request failed: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def format_output(cve_id, cve_info):
    output = []
    output.append(f"CVE ID: {cve_id}")
    output.append(f"\nExploit Available: {'Yes' if cve_info['exploit_available'] else 'No'}")
    output.append("(Checked: Rapid7/Metasploit, Vulners)")
    
    if cve_info['cvss_score']:
        output.append(f"\nCVSS Score: {cve_info['cvss_score']}")
    
    if cve_info['description']:
        output.append(f"\nDescription:\n{cve_info['description']}")
    
    if cve_info['references']:
        output.append("\nReferences:")
        for ref in cve_info['references']:
            output.append(f"- {ref}")
            
    return "\n".join(output)

def validate_cve_format(cve_id):
    """Validate CVE ID format with stricter rules"""
    pattern = r'^CVE-(\d{4})-(\d{4,7})$'
    match = re.match(pattern, cve_id, re.IGNORECASE)
    
    if not match:
        return False
        
    year = int(match.group(1))
    current_year = 2024
    
    if year < 1999 or year > current_year:
        return False
        
    return True

def fetch_cvss_score(cve_id):
    # CIRCL API URL for the CVE details
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    
    try:
        response = requests.get(url)
        print(f"Response Code: {response.status_code}")  # Debug: Print response code
        response.raise_for_status()  # Raise an error for bad responses
    except requests.HTTPError as http_err:
        if response.status_code == 404:
            return "CVE ID not found."
        return f"HTTP error occurred: {http_err}"
    except requests.RequestException as e:
        return f"Error fetching CVE data: {e}"

    data = response.json()
    print(data)  # Debug: Print the response data

    # Check if CVE data is present
    if 'summary' in data:
        cvss_data = data.get('cvss', None)

        if isinstance(cvss_data, dict):  # Check if cvss_data is a dictionary
            return f"CVSS Score: {cvss_data.get('base_score', 'Score not available')}"
        elif isinstance(cvss_data, float):  # Check if it's a float
            return f"CVSS Score: {cvss_data}"

    return "CVSS Score not found."



# Main page route
@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('page1.html')  # Serve your page1.html as the home page

# Form submission route for extracting jQuery version
@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        jquery_version, error = get_jquery_version(url)
        
        if jquery_version:
            return redirect(url_for('vulnerabilities', version=jquery_version))
        else:
            return render_template('index.html', error=error)

    return render_template('index.html')

# Route for displaying vulnerabilities of the jQuery version
@app.route('/vulnerabilities/<version>', methods=['GET'])
def vulnerabilities(version):
    vulnerabilities, fetch_error = fetch_vulnerabilities(version)
    if vulnerabilities:
        return render_template('vulnerabilities.html', version=version, vulnerabilities=vulnerabilities)
    else:
        return render_template('vulnerabilities.html', version=version, error=fetch_error)

# Route for CVE details
@app.route('/cve/<path:vuln_link>')
def cve_details(vuln_link):
    response = requests.get(vuln_link)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        cve_ids = soup.find_all(string=re.compile(r'\bCVE-\d{4}-\d{1,7}\b'))
        return render_template('cve.html', cve_ids=cve_ids)
    else:
        return render_template('cve.html', error=f"Error retrieving CVE details. Status code: {response.status_code}")

# Route for "Explore More Scoring System"
@app.route('/explore_scoring_system')
def explore_scoring_system():
    return render_template('page2.html')

# Route for "Check Public Exploit"
@app.route('/check-public-exploit')
def check_public_exploit():
    return render_template('ex.html')

@app.route('/search', methods=['POST'])
def search():
    cve_id = request.form.get('cve_id').strip().upper()
    
    if not cve_id:
        return jsonify({"error": "Please enter a CVE ID."}), 400
    
    if not validate_cve_format(cve_id):
        return jsonify({"error": "Invalid CVE ID format. Please use format: CVE-YYYY-NNNN."}), 400
    
    result = fetch_cve_details(cve_id)
    
    if result:
        return jsonify({"result": result})
    else:
        return jsonify({"error": "No information found or an error occurred while fetching the data."}), 404
    
@app.route('/cvss.html', methods=['GET', 'POST'])
def cvss():
    cvss_score = None
    error_message = None

    if request.method == 'POST':
        cve_id = request.form.get('cve_id').strip()

        if not cve_id:
            error_message = "Please enter a CVE ID."
        elif not cve_id.startswith("CVE-"):
            error_message = "CVE ID must start with 'CVE-'."
        else:
            cvss_score = fetch_cvss_score(cve_id)

    return render_template('cvss.html', cvss_score=cvss_score, error_message=error_message)


    

if __name__ == '__main__':
    app.run(debug=True)
