# MITRE Threat Intelligence Platform

## Setup & Run (Step-by-Step)

### Step 1: Clone Project

```bash
git clone https://github.com/harish795r/Cyber-Threat-Intelligence-Platform-Based-on-MITRE-ATTACK.git
cd Cyber-Threat-Intelligence-Platform-Based-on-MITRE-ATTACK
```

or download and extract the zip file

---

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3: Install Requirements

```bash
pip install -r requirements.txt
```

---

### Step 4: Start AttackMatrix Engine

```bash
python3 attackmatrix/attackmatrix.py -d
```

---

### Step 5: Run Flask App

```bash
python3 app.py
```

---

### Step 6: Open in Browser

```bash
http://127.0.0.1:5000
```

---

## Usage

1. Enter any threat-related input:
   - Malware  
   - Technique (Txxxx)  
   - Threat Actor  
   - Tool  

2. Click **SCAN**

3. View:
   - Techniques  
   - Actors  
   - Tools  
   - Attack phases  
   - Charts & timeline  

4. Click any item for detailed popup  

5. Export dashboard or download report if needed  

