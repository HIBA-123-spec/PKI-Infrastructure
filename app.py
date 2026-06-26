from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import os
import json
from datetime import datetime
import tempfile
import platform

app = Flask(__name__)

# ─── Configuration des chemins ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = r"C:\PKI"

PATHS = {
    "root": {
        "dir": os.path.join(PKI_DIR, "root-ca"),
        "key": os.path.join(PKI_DIR, "root-ca", "private", "root-ca.key.pem"),
        "cert": os.path.join(PKI_DIR, "root-ca", "certs", "root-ca.cert.pem"),
        "crl": os.path.join(PKI_DIR, "root-ca", "crl", "root-ca.crl.pem"),
        "config": os.path.join(PKI_DIR, "root-ca", "openssl-root.cnf"),
        "index": os.path.join(PKI_DIR, "root-ca", "index.txt"),
        "serial": os.path.join(PKI_DIR, "root-ca", "serial"),
    },
    "intermediate": {
        "dir": os.path.join(PKI_DIR, "intermediate-ca"),
        "key": os.path.join(PKI_DIR, "intermediate-ca", "private", "intermediate-ca.key.pem"),
        "cert": os.path.join(PKI_DIR, "intermediate-ca", "certs", "intermediate-ca.cert.pem"),
        "chain": os.path.join(PKI_DIR, "intermediate-ca", "certs", "ca-chain.cert.pem"),
        "crl": os.path.join(PKI_DIR, "intermediate-ca", "crl", "intermediate-ca.crl.pem"),
        "config": os.path.join(PKI_DIR, "intermediate-ca", "openssl-intermediate.cnf"),
        "csr": os.path.join(PKI_DIR, "intermediate-ca", "csr", "intermediate-ca.csr.pem"),
        "index": os.path.join(PKI_DIR, "intermediate-ca", "index.txt"),
        "serial": os.path.join(PKI_DIR, "intermediate-ca", "serial"),
    },
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def run_openssl(cmd, input_data=None):
    """Exécute une commande OpenSSL et retourne (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, input=input_data, capture_output=True,
            text=True, timeout=30
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout: la commande a pris trop de temps."
    except FileNotFoundError:
        return False, "", "OpenSSL introuvable. Vérifie ton installation."

def cert_exists(path):
    return os.path.isfile(path)

def get_cert_info(cert_path):
    """Retourne les infos d'un certificat en dict."""
    if not cert_exists(cert_path):
        return None
    ok, out, _ = run_openssl([
        "openssl", "x509", "-noout", "-subject", "-issuer",
        "-dates", "-serial", "-in", cert_path
    ])
    if not ok:
        return None
    info = {}
    for line in out.strip().splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            info[key.strip()] = val.strip()
    return info

def pki_status():
    """Retourne l'état de chaque niveau de la PKI."""
    return {
        "root": cert_exists(PATHS["root"]["cert"]),
        "intermediate": cert_exists(PATHS["intermediate"]["cert"]),
        "chain": cert_exists(PATHS["intermediate"]["chain"]),
        "leaf_count": len([
            f for f in os.listdir(os.path.join(PKI_DIR, "leaf", "certs"))
            if f.endswith(".cert.pem")
        ]) if os.path.isdir(os.path.join(PKI_DIR, "leaf", "certs")) else 0,
    }

def write_root_config(cn, org, country, state):
    """Génère le fichier openssl-root.cnf dynamiquement."""
    pki_path = PKI_DIR.replace("\\", "/")
    root_dir = PATHS["root"]["dir"].replace("\\", "/")
    config = f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {root_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/root-ca.key.pem
certificate       = $dir/certs/root-ca.cert.pem
crl               = $dir/crl/root-ca.crl.pem
crlnumber         = $dir/crlnumber
default_days      = 3650
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
C  = {country}
ST = {state}
O  = {org}
CN = {cn}

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ usr_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ crl_ext ]
authorityKeyIdentifier = keyid:always,issuer
"""
    with open(PATHS["root"]["config"], "w") as f:
        f.write(config)

def write_intermediate_config(cn, org, country, state):
    """Génère le fichier openssl-intermediate.cnf dynamiquement."""
    inter_dir = PATHS["intermediate"]["dir"].replace("\\", "/")
    config = f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {inter_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/intermediate-ca.key.pem
certificate       = $dir/certs/intermediate-ca.cert.pem
crl               = $dir/crl/intermediate-ca.crl.pem
crlnumber         = $dir/crlnumber
default_days      = 365
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
prompt              = no

[ req_distinguished_name ]
C  = {country}
ST = {state}
O  = {org}
CN = {cn}

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ usr_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ crl_ext ]
authorityKeyIdentifier = keyid:always,issuer
"""
    with open(PATHS["intermediate"]["config"], "w") as f:
        f.write(config)

def init_pki_dirs():
    """Crée tous les répertoires et fichiers nécessaires."""
    dirs = [
        "root-ca/private", "root-ca/certs", "root-ca/crl", "root-ca/newcerts",
        "intermediate-ca/private", "intermediate-ca/certs",
        "intermediate-ca/crl", "intermediate-ca/newcerts", "intermediate-ca/csr",
        "leaf/private", "leaf/certs", "leaf/csr",
    ]
    for d in dirs:
        os.makedirs(os.path.join(PKI_DIR, d), exist_ok=True)

    for f, content in [
        (PATHS["root"]["index"], ""),
        (PATHS["root"]["serial"], "1000\n"),
        (os.path.join(PATHS["root"]["dir"], "crlnumber"), "1000\n"),
        (PATHS["intermediate"]["index"], ""),
        (PATHS["intermediate"]["serial"], "2000\n"),
        (os.path.join(PATHS["intermediate"]["dir"], "crlnumber"), "2000\n"),
    ]:
        if not os.path.exists(f):
            with open(f, "w") as fp:
                fp.write(content)

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    init_pki_dirs()
    status = pki_status()
    return render_template("index.html", status=status)

# ── Root CA ───────────────────────────────────────────────────────────────────

@app.route("/api/root-ca/create", methods=["POST"])
def create_root_ca():
    data = request.json
    cn = data.get("cn", "Root CA")
    org = data.get("org", "MonOrg PKI")
    country = data.get("country", "MA")
    state = data.get("state", "Tanger-Tetouan")
    password = data.get("password", "")

    init_pki_dirs()
    write_root_config(cn, org, country, state)

    # Générer clé RSA 4096
    key_cmd = ["openssl", "genrsa", "-out", PATHS["root"]["key"], "4096"]
    if password:
        key_cmd = ["openssl", "genrsa", "-aes256", "-passout", f"pass:{password}",
                   "-out", PATHS["root"]["key"], "4096"]

    ok, out, err = run_openssl(key_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    # Générer certificat auto-signé
    cert_cmd = [
        "openssl", "req", "-config", PATHS["root"]["config"],
        "-key", PATHS["root"]["key"],
        "-new", "-x509", "-days", "3650", "-sha256",
        "-extensions", "v3_ca",
        "-out", PATHS["root"]["cert"],
    ]
    if password:
        cert_cmd += ["-passin", f"pass:{password}"]

    ok, out, err = run_openssl(cert_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    info = get_cert_info(PATHS["root"]["cert"])
    return jsonify({"success": True, "info": info})

@app.route("/api/root-ca/info")
def root_ca_info():
    info = get_cert_info(PATHS["root"]["cert"])
    if info:
        ok, pem, _ = run_openssl(["openssl", "x509", "-text", "-noout", "-in", PATHS["root"]["cert"]])
        return jsonify({"success": True, "info": info, "pem": pem})
    return jsonify({"success": False, "error": "Root CA introuvable."})

@app.route("/api/root-ca/crl", methods=["POST"])
def generate_root_crl():
    data = request.json or {}
    password = data.get("password", "")
    cmd = ["openssl", "ca", "-config", PATHS["root"]["config"],
           "-gencrl", "-out", PATHS["root"]["crl"]]
    if password:
        cmd += ["-passin", f"pass:{password}"]
    ok, out, err = run_openssl(cmd)
    if not ok:
        return jsonify({"success": False, "error": err})
    ok2, crl_text, _ = run_openssl(["openssl", "crl", "-noout", "-text", "-in", PATHS["root"]["crl"]])
    return jsonify({"success": True, "crl": crl_text})

# ── Intermediate CA ───────────────────────────────────────────────────────────

@app.route("/api/intermediate-ca/create", methods=["POST"])
def create_intermediate_ca():
    data = request.json
    cn = data.get("cn", "Intermediate CA")
    org = data.get("org", "MonOrg PKI")
    country = data.get("country", "MA")
    state = data.get("state", "Tanger-Tetouan")
    password = data.get("password", "")
    root_password = data.get("root_password", "")

    write_intermediate_config(cn, org, country, state)

    # Clé 2048
    key_cmd = ["openssl", "genrsa", "-out", PATHS["intermediate"]["key"], "2048"]
    if password:
        key_cmd = ["openssl", "genrsa", "-aes256", "-passout", f"pass:{password}",
                   "-out", PATHS["intermediate"]["key"], "2048"]
    ok, out, err = run_openssl(key_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    # CSR
    csr_cmd = [
        "openssl", "req", "-config", PATHS["intermediate"]["config"],
        "-new", "-sha256",
        "-key", PATHS["intermediate"]["key"],
        "-out", PATHS["intermediate"]["csr"],
    ]
    if password:
        csr_cmd += ["-passin", f"pass:{password}"]
    ok, out, err = run_openssl(csr_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    # Signer par Root CA
    sign_cmd = [
        "openssl", "ca", "-config", PATHS["root"]["config"],
        "-extensions", "v3_intermediate_ca",
        "-days", "1825", "-notext", "-md", "sha256", "-batch",
        "-in", PATHS["intermediate"]["csr"],
        "-out", PATHS["intermediate"]["cert"],
    ]
    if root_password:
        sign_cmd += ["-passin", f"pass:{root_password}"]
    ok, out, err = run_openssl(sign_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    # Créer la chaîne
    with open(PATHS["intermediate"]["cert"]) as f:
        inter_pem = f.read()
    with open(PATHS["root"]["cert"]) as f:
        root_pem = f.read()
    with open(PATHS["intermediate"]["chain"], "w") as f:
        f.write(inter_pem + root_pem)

    info = get_cert_info(PATHS["intermediate"]["cert"])
    return jsonify({"success": True, "info": info})

@app.route("/api/intermediate-ca/info")
def intermediate_ca_info():
    info = get_cert_info(PATHS["intermediate"]["cert"])
    if info:
        ok, pem, _ = run_openssl(["openssl", "x509", "-text", "-noout", "-in", PATHS["intermediate"]["cert"]])
        return jsonify({"success": True, "info": info, "pem": pem})
    return jsonify({"success": False, "error": "Intermediate CA introuvable."})

@app.route("/api/intermediate-ca/crl", methods=["POST"])
def generate_inter_crl():
    data = request.json or {}
    password = data.get("password", "")
    cmd = ["openssl", "ca", "-config", PATHS["intermediate"]["config"],
           "-gencrl", "-out", PATHS["intermediate"]["crl"]]
    if password:
        cmd += ["-passin", f"pass:{password}"]
    ok, out, err = run_openssl(cmd)
    if not ok:
        return jsonify({"success": False, "error": err})
    ok2, crl_text, _ = run_openssl(["openssl", "crl", "-noout", "-text", "-in", PATHS["intermediate"]["crl"]])
    return jsonify({"success": True, "crl": crl_text})

# ── Leaf Certificate ──────────────────────────────────────────────────────────

@app.route("/api/leaf/create", methods=["POST"])
def create_leaf():
    data = request.json
    name = data.get("name", "server").replace(" ", "_")
    cn = data.get("cn", "www.example.com")
    cert_type = data.get("type", "server")  # server ou client
    inter_password = data.get("inter_password", "")

    leaf_key = os.path.join(PKI_DIR, "leaf", "private", f"{name}.key.pem")
    leaf_csr = os.path.join(PKI_DIR, "leaf", "csr", f"{name}.csr.pem")
    leaf_cert = os.path.join(PKI_DIR, "leaf", "certs", f"{name}.cert.pem")

    # Clé 2048
    ok, _, err = run_openssl(["openssl", "genrsa", "-out", leaf_key, "2048"])
    if not ok:
        return jsonify({"success": False, "error": err})

    # CSR avec subject
    subj = f"/CN={cn}"
    ok, _, err = run_openssl([
        "openssl", "req", "-new", "-sha256",
        "-key", leaf_key, "-subj", subj, "-out", leaf_csr
    ])
    if not ok:
        return jsonify({"success": False, "error": err})

    # Signer par Intermediate CA
    ext = "server_cert" if cert_type == "server" else "usr_cert"
    sign_cmd = [
        "openssl", "ca", "-config", PATHS["intermediate"]["config"],
        "-extensions", ext,
        "-days", "365", "-notext", "-md", "sha256", "-batch",
        "-in", leaf_csr, "-out", leaf_cert,
    ]
    if inter_password:
        sign_cmd += ["-passin", f"pass:{inter_password}"]
    ok, out, err = run_openssl(sign_cmd)
    if not ok:
        return jsonify({"success": False, "error": err})

    info = get_cert_info(leaf_cert)
    return jsonify({"success": True, "info": info, "name": name})

@app.route("/api/leaf/list")
def list_leaves():
    leaf_dir = os.path.join(PKI_DIR, "leaf", "certs")
    certs = []
    if os.path.isdir(leaf_dir):
        for f in os.listdir(leaf_dir):
            if f.endswith(".cert.pem"):
                info = get_cert_info(os.path.join(leaf_dir, f))
                certs.append({"filename": f, "info": info})
    return jsonify({"success": True, "certs": certs})

@app.route("/api/leaf/revoke", methods=["POST"])
def revoke_leaf():
    data = request.json
    filename = data.get("filename")
    inter_password = data.get("inter_password", "")
    cert_path = os.path.join(PKI_DIR, "leaf", "certs", filename)

    if not os.path.exists(cert_path):
        return jsonify({"success": False, "error": "Certificat introuvable."})

    revoke_cmd = [
        "openssl", "ca", "-config", PATHS["intermediate"]["config"],
        "-revoke", cert_path,
    ]
    if inter_password:
        revoke_cmd += ["-passin", f"pass:{inter_password}"]
    ok, out, err = run_openssl(revoke_cmd)
    if not ok and "Already revoked" not in err:
        return jsonify({"success": False, "error": err})

    # Régénérer la CRL
    crl_cmd = ["openssl", "ca", "-config", PATHS["intermediate"]["config"],
               "-gencrl", "-out", PATHS["intermediate"]["crl"]]
    if inter_password:
        crl_cmd += ["-passin", f"pass:{inter_password}"]
    run_openssl(crl_cmd)

    return jsonify({"success": True, "message": f"{filename} révoqué avec succès."})

# ── Vérification ──────────────────────────────────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def verify_cert():
    data = request.json
    filename = data.get("filename")

    if filename:
        cert_path = os.path.join(PKI_DIR, "leaf", "certs", filename)
    else:
        return jsonify({"success": False, "error": "Nom de fichier requis."})

    if not os.path.exists(cert_path):
        return jsonify({"success": False, "error": "Certificat introuvable."})

    chain = PATHS["intermediate"]["chain"]
    if not os.path.exists(chain):
        return jsonify({"success": False, "error": "Chaîne de confiance introuvable."})

    ok, out, err = run_openssl([
        "openssl", "verify", "-CAfile", chain, cert_path
    ])

    details_ok, details, _ = run_openssl([
        "openssl", "x509", "-noout", "-text", "-in", cert_path
    ])

    return jsonify({
        "success": ok,
        "result": out if ok else err,
        "details": details,
        "valid": ok,
    })

@app.route("/api/status")
def get_status():
    return jsonify(pki_status())

if __name__ == "__main__":
    init_pki_dirs()
    app.run(debug=True, port=5001)
