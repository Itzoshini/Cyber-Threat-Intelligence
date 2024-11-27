from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

class ThreatIntelligenceRiskScorer:
    def init(self, severity, likelihood, impact, confidence):
        self.severity = severity
        self.likelihood = likelihood
        self.impact = impact
        self.confidence = confidence

    # Calculate risk score based on a simple formula
    def calculate_risk_score(self):
        risk_score = (self.severity * self.likelihood * self.impact) * self.confidence
        return round(risk_score, 2)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        try:
            # Get inputs from form
            severity = float(request.form.get("severity"))
            likelihood = float(request.form.get("likelihood"))
            impact = float(request.form.get("impact"))
            confidence = float(request.form.get("confidence"))

            # Validate inputs
            if not (0 <= severity <= 10) or not (0 <= likelihood <= 10) or not (0 <= impact <= 10) or not (0 <= confidence <= 1):
                raise ValueError("Inputs out of range")

            # Create a threat scorer object and calculate the risk score
            scorer = ThreatIntelligenceRiskScorer(severity, likelihood, impact, confidence)
            risk_score = scorer.calculate_risk_score()

            return render_template("tris.html", risk_score=risk_score)

        except ValueError:
            flash("Please enter valid numbers within the specified ranges.")
            return redirect(url_for("home"))

    return render_template("tris.html", risk_score=None)

if __name__ == "__main__":
    app.run(debug=True)