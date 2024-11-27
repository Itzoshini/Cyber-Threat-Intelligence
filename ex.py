from flask import Flask, render_template, request, jsonify
import requests
import re

app = Flask(__name__)

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

@app.route('/')
def index():
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

if __name__ == '__main__':
    app.run(debug=True)
