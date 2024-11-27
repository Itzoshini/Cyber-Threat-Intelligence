from flask import Flask, request, render_template

app = Flask(__name__)

def calculate_rps(exploitability_score, impact_score, fix_availability_score, time_to_remediate_score):
    """Calculate the Remediation Prediction Score."""
    if time_to_remediate_score <= 0:
        raise ValueError("Time to remediate must be greater than zero.")
    
    rps = (exploitability_score + impact_score + fix_availability_score) / time_to_remediate_score
    return rps

@app.route('/')
def home():
    return render_template('rps.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        exploitability = float(request.form['exploitability'])
        impact = float(request.form['impact'])
        fix_availability = float(request.form['fix_availability'])
        time_to_remediate = float(request.form['time_to_remediate'])

        rps = calculate_rps(exploitability, impact, fix_availability, time_to_remediate)
        return render_template('results.html', rps=rps)

    except ValueError as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(debug=True)