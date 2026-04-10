from flask import Flask, render_template, request, send_file
import os
import json
import re
from fpdf import FPDF

app = Flask(__name__)



MITRE_FILE = os.path.join(os.path.dirname(__file__), 'mitre_data', 'enterprise-attack.json')


TYPE_MAP = {
    'intrusion-set': 'Actors',
    'malware':       'Malwares',
    'tool':          'Tools',
    'campaign':      'Campaigns',
    'x-mitre-tactic':'Tactics',
    'attack-pattern':'Techniques',
    'course-of-action':'Mitigations',
    'x-mitre-data-source':'Data Sources',
    'x-mitre-data-component':'Data Sources',
}

entities   = {}      
catalog    = {}        
name_index = {}        

def clean_text(text):
    if not text:
        return ''
    text = re.sub(r'\[([^\]]+)\]\((.*?)\)', r'\1', text)
    text = re.sub(r'\(Citation:.*?\)', '', text)
    for k, v in {'\u2018':"'",'\u2019':"'",'\u201c':'"','\u201d':'"','\u2013':'-','\u2014':'-','\u2026':'...'}.items():
        text = text.replace(k, v)
    return text.strip()

def get_mitre_id(obj):
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id', ''), ref.get('url', '')
    return '', ''

def load_mitre():
    global entities, catalog, name_index
    print('[+] Loading MITRE ATT&CK data...')
    with open(MITRE_FILE, 'r', encoding='utf-8') as f:
        raw = json.load(f)

    objects = raw.get('objects', [])

  
    for obj in objects:
        t = obj.get('type', '')
        cat = TYPE_MAP.get(t)
        if not cat:
            continue
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue

        eid = obj['id']
        mitre_id, url = get_mitre_id(obj)
        name = obj.get('name', 'Unknown')
        desc = clean_text(obj.get('description', ''))
        aliases = obj.get('aliases', []) or obj.get('x_mitre_aliases', [])
        aliases = [a for a in aliases if a != name]
        platforms = obj.get('x_mitre_platforms', [])

       
        phases = []
        for kc in obj.get('kill_chain_phases', []):
            if kc.get('kill_chain_name') == 'mitre-attack':
                phases.append(kc.get('phase_name', ''))

        entities[eid] = {
            'id': eid,
            'mitre_id': mitre_id,
            'url': url,
            'category': cat,
            'name': name,
            'description': desc,
            'aliases': aliases,
            'platforms': platforms,
            'phases': phases,
            'related': {},   
        }

    
        if cat not in catalog:
            catalog[cat] = []
        catalog[cat].append(name)

     
        name_index[name.lower()] = eid
        for alias in aliases:
            name_index[alias.lower()] = eid

 
    for cat in catalog:
        catalog[cat] = sorted(set(catalog[cat]))

  
    for obj in objects:
        if obj.get('type') != 'relationship':
            continue
        src = obj.get('source_ref', '')
        tgt = obj.get('target_ref', '')
        rel = obj.get('relationship_type', '')

        if src not in entities or tgt not in entities:
            continue

        src_cat = entities[src]['category']
        tgt_cat = entities[tgt]['category']

  
        if tgt_cat not in entities[src]['related']:
            entities[src]['related'][tgt_cat] = []
        entities[src]['related'][tgt_cat].append(tgt)

       
        if src_cat not in entities[tgt]['related']:
            entities[tgt]['related'][src_cat] = []
        entities[tgt]['related'][src_cat].append(src)

   
    for eid in entities:
        for cat in entities[eid]['related']:
            entities[eid]['related'][cat] = list(set(entities[eid]['related'][cat]))

    total = sum(len(v) for v in catalog.values())
    print(f'[+] MITRE data loaded: {len(entities)} entities, {total} catalog entries')

load_mitre()




CATEGORY_ORDER = ['Actors','Malwares','Tools','Campaigns','Tactics','Techniques','Mitigations','Data Sources']

def search_entities(query, category='Auto'):
    q = query.lower().strip()
    results = []

    
    if q in name_index:
        eid = name_index[q]
        e = entities[eid]
        if category == 'Auto' or e['category'] == category:
            return [eid]

 
    cats_to_search = CATEGORY_ORDER if category == 'Auto' else [category]
    for cat in cats_to_search:
        for eid, e in entities.items():
            if e['category'] != cat:
                continue
            if q in e['name'].lower() or any(q in a.lower() for a in e['aliases']):
                results.append(eid)

    return results



glossary_defs = {
    'APT': 'Advanced Persistent Threat',
    'C2': 'Command and Control server',
    'Exfiltration': 'Stealing data from a network',
    'Lateral Movement': 'Moving through a network',
    'MITRE ATT&CK': 'Knowledge base of adversary techniques',
    'Phishing': 'Tricking users to open malicious files',
    'Ransomware': 'Malware encrypting files for ransom',
    'STIX': 'Structured Threat Information Expression',
    'TTPs': 'Tactics Techniques Procedures',
    'Zero-Day': 'Unknown vulnerability exploited',
}



@app.route('/', methods=['GET', 'POST'])
def index():
    results    = None
    error      = None
    search_term = ''
    ip_result  = None
    vt_result  = None
    file_hash  = None

    if request.method == 'POST':
        search_term     = request.form.get('search_query', '').strip()
        search_category = request.form.get('category', 'Auto')
        ip   = request.form.get('ip')
        file = request.files.get('file')

        if ip:
            ip_data = check_ip(ip)
            if ip_data:
                ip_result = ip_data['data']

        if file and file.filename != '':
            vt_data, file_hash = check_file(file)
            if vt_data:
                vt_result = vt_data['data']['attributes']['last_analysis_stats']

        if search_term:
            matches = search_entities(search_term, search_category)

            if not matches:
                error = f"No results found for '{search_term}'."
            else:
                eid = matches[0]
                e   = entities[eid]

               
                related_data = {}
                for cat in CATEGORY_ORDER:
                    if cat not in e['related']:
                        continue
                    items = []
                    for rid in e['related'][cat][:50]:   # cap at 50 per category
                        r = entities.get(rid)
                        if r:
                            items.append({
                                'name': r['name'],
                                'description': r['description'][:300] + '...' if len(r['description']) > 300 else r['description'],
                                'id': r['mitre_id'],
                                'url': r['url'],
                            })
                    items.sort(key=lambda x: x['name'])
                    if items:
                        related_data[cat] = items

               
                tech_ids = e['related'].get('Techniques', [])
                clean_techs = []
                phase_counts = {}
                platforms_set = set()

                for tid in tech_ids:
                    t = entities.get(tid)
                    if not t:
                        continue
                    phase = t['phases'][0] if t['phases'] else 'other'
                    phase_counts[phase] = phase_counts.get(phase, 0) + 1
                    for p in t['platforms']:
                        platforms_set.add(p)
                    clean_techs.append({
                        'id': t['mitre_id'],
                        'name': t['name'],
                        'description': t['description'][:300] + '...' if len(t['description']) > 300 else t['description'],
                        'full_desc': t['description'],
                        'phase': phase,
                        'platforms': ', '.join(t['platforms']) or 'Unknown',
                    })
                clean_techs.sort(key=lambda x: x['phase'])

                
                if e['category'] == 'Techniques' and not clean_techs:
                    phase = e['phases'][0] if e['phases'] else 'other'
                    phase_counts[phase] = 1
                    clean_techs.append({
                        'id': e['mitre_id'],
                        'name': e['name'],
                        'description': e['description'],
                        'full_desc': e['description'],
                        'phase': phase,
                        'platforms': ', '.join(e['platforms']) or 'Unknown',
                    })

                count = len(clean_techs)
                if count <= 5:   risk_level, risk_score = 'LOW', 25
                elif count <= 10: risk_level, risk_score = 'MEDIUM', 50
                elif count <= 20: risk_level, risk_score = 'HIGH', 75
                else:             risk_level, risk_score = 'CRITICAL', 100

             
                mit_ids = e['related'].get('Mitigations', [])
                defenses_list = []
                for mid in mit_ids[:20]:
                    m = entities.get(mid)
                    if m:
                        defenses_list.append(f"{m['name']}: {m['description'][:200]}...")

                results = {
                    'type': e['category'],
                    'name': e['name'],
                    'description': e['description'],
                    'url': e['url'],
                    'aliases': ', '.join(e['aliases']) if e['aliases'] else 'None known',
                    'platforms': list(platforms_set),
                    'id': e['mitre_id'],
                    'count': count,
                    'risk': risk_level,
                    'risk_score': risk_score,
                    'techniques': clean_techs,
                    'chart_data': phase_counts,
                    'defenses': defenses_list,
                    'related': related_data,
                }

                generate_pdf_report(e['name'], clean_techs, defenses_list)

    return render_template(
        'index.html',
        results=results,
        error=error,
        search_term=search_term,
        catalog=catalog,
        glossary=glossary_defs,
        ip_result=ip_result,
        vt_result=vt_result,
        file_hash=file_hash,
        category_order=CATEGORY_ORDER,
    )




@app.route('/download_playbook/<name>')
def download_playbook(name):
    filename = os.path.join('reports', f'{name}_Playbook.pdf')
    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)
    return 'Error: File not found', 404


def generate_pdf_report(name, techniques, defenses):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 20)
    pdf.cell(0, 10, f'Threat Report: {clean_text(name)}', ln=True)
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Adversary Playbook', ln=True)
    for i, t in enumerate(techniques, 1):
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, f"{i}. {clean_text(t['name'])} ({t['id']})", ln=True)
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 6, clean_text(t['description']))
        pdf.ln(2)
    pdf.add_page()
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Defense Blueprint', ln=True)
    for d in defenses[:20]:
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 6, clean_text(d))
        pdf.ln(1)
    folder = 'reports'
    os.makedirs(folder, exist_ok=True)
    pdf.output(os.path.join(folder, f'{clean_text(name)}_Playbook.pdf'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
