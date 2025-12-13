from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Input, Button, Static, DataTable, Log, Label
from textual.validation import Length
from textual import on
import os
import threading
import subprocess
import sys
from datetime import datetime
from mitreattack.stix20 import MitreAttackData

# css styles
CSS = """
Screen {
    layout: grid;
    grid-size: 2;
    grid-columns: 35fr 65fr;
    grid-rows: 1fr;
    background: #0f1219;
}

#sidebar {
    dock: left;
    width: 100%;
    height: 100%;
    background: #1a1b26;
    border-right: vkey $accent;
    padding: 1 2;
}

#main_content {
    width: 100%;
    height: 100%;
    padding: 1 2;
    background: #0f1219;
}

Label {
    color: $text-muted;
    margin-bottom: 1;
}

.title {
    color: #7aa2f7;
    text-style: bold;
    margin-bottom: 2;
}

.section-title {
    color: #bb9af7;
    text-style: bold;
    border-bottom: solid #bb9af7;
    margin-bottom: 1;
    margin-top: 2;
}

Input {
    border: tall #7aa2f7;
    background: #16161e;
    color: #c0caf5;
}

Input:focus {
    border: tall #bb9af7;
}

Button {
    width: 100%;
    margin-top: 1;
    background: #7aa2f7;
    color: #0f1219;
    text-style: bold;
}

Button.success {
    background: #9ece6a;
    color: #0f1219;
}

DataTable {
    height: 1fr;
    border: solid #565f89;
    margin-top: 1;
    background: #16161e;
}

Log {
    height: 15;
    border: solid #565f89;
    background: #0f1219;
    color: #9ece6a;
    margin-top: 1;
}
"""

class ThreatIntelApp(App):
    CSS = CSS
    TITLE = "MITRE ATT&CK MAPPING SYSTEM v3.0"
    SUB_TITLE = "Enterprise Adversary Emulation Engine"

    def compose(self) -> ComposeResult:
        # left panel
        with Container(id="sidebar"):
            yield Static("THREAT ENGINE", classes="title")
            yield Label("TARGET ARTIFACT:")
            yield Input(placeholder="e.g. WannaCry", id="malware_input")
            
            yield Label("OPERATIONS:", classes="section-title")
            yield Button("INITIALIZE EXTRACTION", id="scan_btn", variant="primary")
            yield Button("OPEN PLAYBOOK REPORT", id="open_btn", disabled=True, classes="success")
            
            yield Label("SYSTEM LOGS:", classes="section-title")
            yield Log(id="console_log", highlight=True)

        # right panel
        with Container(id="main_content"):
            yield Static("DETECTED BEHAVIORS (TTPs)", classes="section-title")
            yield DataTable(id="results_table", zebra_stripes=True)

        yield Footer()

    def on_mount(self) -> None:
        # app start
        self.query_one(Log).write("[*] System Initialized.")
        self.query_one(Log).write("[*] Waiting for user input...")
        
        # table setup
        table = self.query_one(DataTable)
        table.add_columns("ID", "Technique Name", "Phase")
        table.cursor_type = "row"

        # load db in bg
        threading.Thread(target=self.load_data, daemon=True).start()

    def load_data(self):
        log = self.query_one(Log)
        log.write("[*] Loading Knowledge Base...")
        
        json_file = "enterprise-attack.json"
        if not os.path.exists(json_file):
            log.write("[!] CRITICAL: DB NOT FOUND")
            return

        try:
            self.mitre_data = MitreAttackData(json_file)
            log.write("[+] Database Loaded Successfully.")
            self.notify("System Ready", title="Status", severity="information")
        except Exception as e:
            log.write(f"[!] Error: {e}")

    @on(Button.Pressed, "#scan_btn")
    def start_scan(self):
        malware = self.query_one("#malware_input").value
        if not malware:
            self.notify("Please enter a malware name", title="Error", severity="error")
            return
            
        self.query_one(Log).write(f"[*] Scanning: {malware}...")
        threading.Thread(target=self.run_analysis, args=(malware,), daemon=True).start()

    def run_analysis(self, malware):
        log = self.query_one(Log)
        table = self.query_one(DataTable)
        
        if not hasattr(self, 'mitre_data'):
            log.write("[!] DB still loading...")
            return

        # clear table (main thread)
        self.call_from_thread(table.clear)

        software_list = self.mitre_data.get_software_by_alias(malware)

        if software_list:
            target = software_list[0]
            log.write(f"[+] Match: {target['name']}")
            
            techniques = self.mitre_data.get_techniques_used_by_software(target['id'])
            log.write(f"[+] Extracted {len(techniques)} TTPs")
            
            # build rows
            rows = []
            for t in techniques:
                tech_name = t['object']['name']
                mitre_id = "Unknown"
                phases = ", ".join([p['phase_name'] for p in t['object'].get('kill_chain_phases', [])])
                
                for ref in t['object'].get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        mitre_id = ref.get('external_id')
                        break
                rows.append((mitre_id, tech_name, phases))

            # update table (main thread)
            self.call_from_thread(self.update_table, rows)
            
            # create report
            self.generate_playbook(malware, techniques)
            
            # enable btn
            self.call_from_thread(self.enable_button)
            
        else:
            log.write(f"[-] No matches for '{malware}'")
            self.notify("No matches found", severity="warning")

    def update_table(self, rows):
        table = self.query_one(DataTable)
        table.add_rows(rows)

    def enable_button(self):
        self.query_one("#open_btn").disabled = False

    def generate_playbook(self, malware_name, techniques):
        filename = f"{malware_name}_Playbook.md"
        self.current_playbook = filename
        
        with open(filename, "w") as f:
            f.write(f"# 🛡️ MITRE Threat Map: {malware_name}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for i, t in enumerate(techniques, 1):
                f.write(f"### {i}. {t['object']['name']}\n")
                f.write("Objective: Mimic adversary behavior.\n\n")
        
        self.query_one(Log).write(f"[+] Report Saved: {filename}")

    @on(Button.Pressed, "#open_btn")
    def open_report(self):
        if hasattr(self, 'current_playbook'):
            if sys.platform.startswith('linux'):
                subprocess.call(['xdg-open', self.current_playbook])
            elif sys.platform == 'win32':
                os.startfile(self.current_playbook)

if __name__ == "__main__":
    app = ThreatIntelApp()
    app.run()