from flask import Flask, render_template, request
import requests

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
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