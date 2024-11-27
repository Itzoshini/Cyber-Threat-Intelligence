from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def fetch_vulnerabilities():
    """
    Fetches vulnerabilities from the data source.
    Replace this stub with actual data extraction logic.
    
    Returns:
    - list of dict: List containing vulnerability data.
    """
    # Example data extraction logic; replace this with actual implementation.
    vulnerabilities = [
        {
            'vulnerability_status': 'Vulnerable',
            'cve_score': '9.8',
            'cwe_score': '89',
            'epss': '0.1',
            'pvrss': '0.2',
            'cvss': '3.1',
            'rps': 'High',
            'mitigation': 'Update to the latest version.'
        },
        {
            'vulnerability_status': 'Not Vulnerable',
            'cve_score': 'N/A',
            'cwe_score': 'N/A',
            'epss': 'N/A',
            'pvrss': 'N/A',
            'cvss': 'N/A',
            'rps': 'Low',
            'mitigation': 'No action required.'
        },
        # Add more data as needed
    ]
    return vulnerabilities

def generate_pdf_report(vulnerabilities, filename='vulnerability_report.pdf'):
    """
    Generates a PDF report of vulnerabilities.
    
    Parameters:
    - vulnerabilities (list of dict): List containing vulnerability data.
    - filename (str): Name of the output PDF file.
    """
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 50, "Vulnerability Report")

    # Table header
    c.setFont("Helvetica-Bold", 12)
    header = ['Vulnerability Status', 'CVE Score', 'CWE Score', 'EPSS', 'PVRSS', 'CVSS', 'RPS', 'Mitigation']
    y = height - 100
    x_positions = [50, 150, 250, 350, 450, 550, 650, 750]
    
    for x, title in zip(x_positions, header):
        c.drawString(x, y, title)

    # Table rows
    c.setFont("Helvetica", 10)
    y -= 20
    for vuln in vulnerabilities:
        c.drawString(x_positions[0], y, vuln.get('vulnerability_status', 'N/A'))
        c.drawString(x_positions[1], y, vuln.get('cve_score', 'N/A'))
        c.drawString(x_positions[2], y, vuln.get('cwe_score', 'N/A'))
        c.drawString(x_positions[3], y, vuln.get('epss', 'N/A'))
        c.drawString(x_positions[4], y, vuln.get('pvrss', 'N/A'))
        c.drawString(x_positions[5], y, vuln.get('cvss', 'N/A'))
        c.drawString(x_positions[6], y, vuln.get('rps', 'N/A'))
        c.drawString(x_positions[7], y, vuln.get('mitigation', 'N/A'))
        y -= 20

    c.save()
    print(f'Report generated: {filename}')

# Main workflow
if __name__ == "__main__":
    vulnerabilities_data = fetch_vulnerabilities()  # Extract data
    generate_pdf_report(vulnerabilities_data)  # Generate PDF report
