from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

class VPRCalculator:
    def __init__(self, cvss_score, exploitability, threat_intel, vulnerability_age, asset_criticality):
        self.cvss_score = cvss_score               # CVSS score (0-10)
        self.exploitability = exploitability       # Exploitability factor (0-1)
        self.threat_intel = threat_intel           # Threat intel factor (0-1)
        self.vulnerability_age = vulnerability_age  # Age factor (0-1)
        self.asset_criticality = asset_criticality  # Asset criticality (0-1)

    def calculate_vpr(self):
        """
        Calculate the Vulnerability Priority Rating (VPR).
        Formula: VPR = CVSS Score * (0.3 * Exploitability + 0.3 * Threat Intel + 
                                      0.2 * Vulnerability Age + 0.2 * Asset Criticality)
        """
        vpr_score = self.cvss_score * (
            0.3 * self.exploitability +
            0.3 * self.threat_intel +
            0.2 * self.vulnerability_age +
            0.2 * self.asset_criticality
        )
        return round(vpr_score, 2)

@app.route('/', methods=['GET', 'POST'])
def index():
    vpr_score = None
    if request.method == 'POST':
        try:
            # Get input values from the form
            cvss_score = float(request.form['cvss_score'])
            exploitability = float(request.form['exploitability'])
            threat_intel = float(request.form['threat_intel'])
            vulnerability_age = float(request.form['vulnerability_age'])
            asset_criticality = float(request.form['asset_criticality'])

            # Validate input ranges
            if not (0 <= cvss_score <= 10 and 0 <= exploitability <= 1 and 0 <= threat_intel <= 1 
                    and 0 <= vulnerability_age <= 1 and 0 <= asset_criticality <= 1):
                raise ValueError("Input values are out of range.")

            # Create an instance of the VPRCalculator
            calculator = VPRCalculator(cvss_score, exploitability, threat_intel, vulnerability_age, asset_criticality)

            # Calculate the VPR
            vpr_score = calculator.calculate_vpr()
        except ValueError as e:
            return render_template('vpr.html', error=str(e), vpr_score=None)

    return render_template('vpr.html', vpr_score=vpr_score)

if __name__ == '__main__':
    app.run(debug=True)
