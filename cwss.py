from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            # Get form data
            technical_impact = float(request.form['technical_impact'])
            acquired_privilege = float(request.form['acquired_privilege'])
            acquired_layer = float(request.form['acquired_layer'])
            internal_control = float(request.form['internal_control'])
            required_privilege = float(request.form['required_privilege'])
            access_vector = float(request.form['access_vector'])
            auth_strength = float(request.form['auth_strength'])
            business_impact = float(request.form['business_impact'])

            # CWSS formula (simplified)
            base_finding_score = (technical_impact * 0.6 + 
                                  acquired_privilege * 0.2 + 
                                  acquired_layer * 0.1 + 
                                  internal_control * 0.1)

            attack_surface_score = (required_privilege * 0.4 + 
                                    access_vector * 0.4 + 
                                    auth_strength * 0.2)

            environmental_score = business_impact * 0.7
            
            cwss_score = base_finding_score * 0.4 + attack_surface_score * 0.3 + environmental_score * 0.3
            
            return render_template('cwss.html', cwss_score=round(cwss_score, 2))

        except ValueError:
            flash("Please enter valid numbers.", "error")
            return redirect(url_for('index'))

    return render_template('cwss.html', cwss_score=None)

if __name__ == '__main__':
    app.run(debug=True)
