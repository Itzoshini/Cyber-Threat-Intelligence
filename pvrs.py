from flask import Flask, render_template, request

app = Flask(__name__)

# Function to calculate PV-RSS score based on input parameters
def calculate_pvrss(cvss_score, exploit_available, severity_level):
    weight_cvss = 0.6
    weight_exploit = 0.3
    weight_severity = 0.1

    severity_mapping = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    exploit_value = 1 if exploit_available.lower() == 'yes' else 0
    severity_value = severity_mapping.get(severity_level, 1)

    pvrss_score = (cvss_score * weight_cvss) + (exploit_value * weight_exploit) + (severity_value * weight_severity)
    return round(pvrss_score, 2)

# Route to display the form
@app.route('/')
def form():
    return render_template('pvrs.html')

# Route to handle form submission and display result
@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        cvss_score = float(request.form['cvss_score'])
        exploit_available = request.form['exploit_available']
        severity_level = request.form['severity_level']

        if cvss_score < 0 or cvss_score > 10:
            return "CVSS Score should be between 0 and 10."

        # Calculate PV-RSS score
        pvrss_score = calculate_pvrss(cvss_score, exploit_available, severity_level)
        return render_template('pvrss_result.html', pvrss_score=pvrss_score)

    except ValueError:
        return "Please enter valid inputs."

if __name__ == '__main__':
    app.run(debug=True)
