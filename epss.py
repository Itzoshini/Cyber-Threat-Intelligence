from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Function to get EPSS score
def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and len(data['data']) > 0:
                epss_score = data['data'][0].get('epss', 'No score available')
                return epss_score
            else:
                return f"No EPSS data found for CVE ID: {cve_id}"
        else:
            return f"Failed to retrieve EPSS score. Status code: {response.status_code}"
    except Exception as e:
        return f"Error occurred: {str(e)}"

# Route for the homepage
@app.route('/')
def index():
    return render_template('epss.html')

# Route to handle form submission
@app.route('/fetch_epss', methods=['POST'])
def fetch_epss():
    cve_id = request.form['cve_id']
    if not cve_id:
        return render_template('epss.html', error="Please enter a valid CVE ID.")

    epss_score = get_epss_score(cve_id)
    return render_template('epss.html', cve_id=cve_id, epss_score=epss_score)

if __name__ == '__main__':
    app.run(debug=True)