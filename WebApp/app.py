from flask import Flask, render_template, request, send_file
import os
from mitreattack.stix20 import MitreAttackData
from fpdf import FPDF

app = Flask(__name__)

# Locate MITRE data
def get_mitre_file():
    possible_paths = ["enterprise-attack.json", "../enterprise-attack.json"]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

MITRE_FILE = get_mitre_file()

# Globals
mitre_data = None
malware_catalog = [] 

# UI glossary
glossary_defs = {
    "APT": "Advanced Persistent Threat. A prolonged, targeted attack.",
    "C2": "Command and Control. communicating with compromised systems.",
    "Exfiltration": "Stealing data from a network.",
    "Lateral Movement": "Moving through a network to find targets.",
    "MITRE ATT&CK": "Knowledge base of adversary behavior.",
    "Phishing": "Tricking victims into opening malicious files/links.",
    "Ransomware": "Malware that locks files until a ransom is paid.",
    "STIX": "Structured Threat Information Expression.",
    "TTPs": "Tactics, Techniques, and Procedures.",
    "Zero-Day": "A vulnerability unknown to the vendor."
}

# Init database
if MITRE_FILE:
    print(f"[+] Loading MITRE Data from: {MITRE_FILE}...")
    try:
        mitre_data = MitreAttackData(MITRE_FILE)
        malware_objs = mitre_data.get_objects_by_type("malware")
        tool_objs = mitre_data.get_objects_by_type("tool")
        all_names = [obj['name'] for obj in malware_objs] + [obj['name'] for obj in tool_objs]
        malware_catalog = sorted(list(set(all_names))) 
        print(f"[+] Database Loaded. Found {len(malware_catalog)} artifacts.")
    except Exception as e:
        print(f"[-] Error loading DB: {e}")
else:
    print("[-] CRITICAL: enterprise-attack.json not found!")

# Fix encoding/bad chars
def clean_text(text):
    if not text: return ""
    replacements = {'\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"', '\u2013': '-', '\u2014': '-', '\u2026': '...'}
    for k, v in replacements.items(): text = text.replace(k, v)
    return text.encode('latin-1', 'replace').decode('latin-1')

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error = None
    search_term = ""

    if request.method == 'POST':
        search_term = request.form.get('malware', '').strip()
        
        if not mitre_data:
            error = "Database not loaded."
        elif not search_term:
            error = "Please enter a malware name."
        else:
            software_list = mitre_data.get_software_by_alias(search_term)
            
            if software_list:
                target = software_list[0]
                techniques = mitre_data.get_techniques_used_by_software(target['id'])
                
                clean_techs = []
                phase_counts = {}
                defenses_seen = set() # Dedup set
                defenses_list = []    # Final PDF list

                for t in techniques:
                    # Get Tech ID
                    mitre_id = "Unknown"
                    for ref in t['object'].get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            mitre_id = ref.get('external_id')
                            break
                    
                    # Get Phase
                    phase = "Unknown"
                    if 'kill_chain_phases' in t['object'] and len(t['object']['kill_chain_phases']) > 0:
                        phase = t['object']['kill_chain_phases'][0]['phase_name']
                    
                    phase_counts[phase] = phase_counts.get(phase, 0) + 1
                    platforms = t['object'].get('x_mitre_platforms', ['Unknown'])

                    # Lookup mitigations
                    related_mitigations = mitre_data.get_mitigations_mitigating_technique(t['id'])
                    
                    for m in related_mitigations:
                        m_name = m['object']['name']
                        # Get Mitigation ID
                        m_ext_id = "Unknown"
                        for ref in m['object'].get('external_references', []):
                            if ref.get('source_name') == 'mitre-attack':
                                m_ext_id = ref.get('external_id')
                                break
                        
                        if m_name not in defenses_seen:
                            defenses_seen.add(m_name)
                            m_desc = m['object'].get('description', 'No description')
                            # Truncate for PDF
                            clean_desc = clean_text(m_desc)[:200] + "..." 
                            defenses_list.append(f"[{m_ext_id}] {m_name}: {clean_desc}")

                    clean_techs.append({
                        "id": mitre_id,
                        "name": t['object']['name'],
                        "description": t['object'].get('description', 'No description')[:300] + "...",
                        "full_desc": t['object'].get('description', 'No description'),
                        "phase": phase,
                        "platforms": ", ".join(platforms)
                    })
                
                # Sort by kill chain order
                kill_chain_order = {
                    "reconnaissance": 1, "resource-development": 2, "initial-access": 3, "execution": 4, 
                    "persistence": 5, "privilege-escalation": 6, "defense-evasion": 7, "credential-access": 8, 
                    "discovery": 9, "lateral-movement": 10, "collection": 11, "command-and-control": 12, 
                    "exfiltration": 13, "impact": 14, "unknown": 99
                }
                clean_techs.sort(key=lambda x: kill_chain_order.get(x['phase'].lower().replace(' ', '-'), 99))
                
                # Sort defenses A-Z
                defenses_list.sort()
                
                # Calculate risk
                count = len(techniques)
                risk_level = "LOW"
                if count > 10: risk_level = "MEDIUM"
                if count > 20: risk_level = "HIGH"
                if count > 40: risk_level = "CRITICAL"

                results = {
                    "name": target['name'],
                    "id": target['id'],
                    "count": count,
                    "risk": risk_level,
                    "techniques": clean_techs,
                    "chart_data": phase_counts,
                    "defenses": defenses_list
                }
                
                generate_pdf_report(target['name'], clean_techs, defenses_list)
            else:
                error = f"No results found for '{search_term}'. Please select from the catalog."

    return render_template('index.html', results=results, error=error, search_term=search_term, catalog=malware_catalog, glossary=glossary_defs)

@app.route('/download_playbook/<name>')
def download_playbook(name):
    filename = f"{name}_Playbook.pdf"
    if os.path.exists(filename): return send_file(filename, as_attachment=True)
    return "Error: File not found."

def generate_pdf_report(name, techniques, defenses):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_fill_color(240, 240, 240)
        pdf.rect(0, 0, 210, 297, 'F')
        
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 10, f"Threat Report: {clean_text(name)}", ln=True, align="C")
        pdf.ln(5)
        pdf.set_font("Arial", "I", 12)
        pdf.cell(0, 10, "Generated by MITRE ATT&CK Mapping System", ln=True, align="C")
        pdf.line(10, 45, 200, 45)
        pdf.ln(20)

        # Page 1: Playbook
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(128, 0, 0)
        pdf.cell(0, 10, "PART 1: ADVERSARY PLAYBOOK", ln=True)
        pdf.ln(5)

        for i, t in enumerate(techniques, 1):
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(0, 51, 102)
            pdf.cell(0, 8, f"Step {i}: {clean_text(t['name'])} ({clean_text(t['id'])})", ln=True)
            
            pdf.set_font("Arial", "I", 10)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 6, f"Phase: {clean_text(t['phase'])}", ln=True)
            
            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 5, clean_text(t['description']))
            pdf.ln(4)

        # Page 2: Defenses
        pdf.add_page()
        pdf.set_fill_color(240, 240, 240)
        pdf.rect(0, 0, 210, 297, 'F')
        
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(0, 100, 0)
        pdf.cell(0, 10, "PART 2: DEFENSE BLUEPRINT (FROM MITRE)", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 8, "The following mitigations are sourced directly from the MITRE ATT&CK Enterprise Matrix based on the observed techniques:")
        pdf.ln(10)

        # Cap at 20 items to save space
        for d in defenses[:20]:
            pdf.set_font("Arial", "B", 10)
            pdf.cell(10, 6, ">>", ln=0)
            pdf.set_font("Arial", "", 10)
            pdf.multi_cell(0, 6, clean_text(d))
            pdf.ln(2)
            
        filename = f"{name}_Playbook.pdf"
        pdf.output(filename)
    except Exception as e: print(f"[-] PDF Generation Failed: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=5000)