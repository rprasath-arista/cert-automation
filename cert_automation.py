#!/usr/bin/env python3
"""Replace self-signed certs on Arista EOS switches with CA-signed certs via CVP workspaces."""

import csv, getpass, ipaddress, math, shutil, socket, ssl, sys, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests, urllib3, yaml
from cvprac.cvp_client import CvpClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).parent.resolve()
CERTS_DIR, CA_DIR = BASE_DIR / "certs", BASE_DIR / "ca"
INVENTORY_FILE = BASE_DIR / "inventory" / "hosts.yml"

G, R, Y, C, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"

SSL_KEYWORDS = ["security pki certificate", "security pki key", "ssl profile", "protocol https ssl profile"]


# --- Console helpers ---

def banner(t):
    w = max(len(t) + 4, 50)
    print(f"\n{C}{'='*w}\n  {t}\n{'='*w}{X}\n")

def ok(m):    print(f"  {G}OK{X} {m}")
def err(m):   print(f"  {R}ERROR{X} {m}")
def warn(m):  print(f"  {Y}WARN{X} {m}")
def info(m):  print(f"  {C}>{X} {m}")

def prompt(label, default="", required=True, hidden=False, validator=None):
    suffix = f" [{default}]" if default else ""
    while True:
        v = getpass.getpass(f"  {label}{suffix}: ") if hidden else input(f"  {label}{suffix}: ").strip()
        if not v and default: v = default
        if required and not v: err("Required."); continue
        if validator and (e := validator(v)): err(e); continue
        return v

def confirm(label, default=True):
    v = input(f"  {label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not v else v in ("y", "yes")

def choose(label, options):
    print(f"\n  {label}")
    for i, (_, d) in enumerate(options, 1): print(f"    {B}{i}{X}. {d}")
    while True:
        v = input(f"  Choice [1-{len(options)}]: ").strip()
        if v.isdigit() and 1 <= int(v) <= len(options): return options[int(v)-1][0]
        err(f"Enter 1-{len(options)}.")

def val_ip(v):
    try: ipaddress.ip_address(v); return None
    except ValueError: return f"'{v}' is not a valid IP."

def val_country(v):
    return "Must be 2 letters." if len(v) != 2 or not v.isalpha() else None

def val_path(v):
    return f"Not found: {v}" if not Path(v).exists() else None


# --- Inventory ---

def load_inventory():
    if not INVENTORY_FILE.exists(): return {}
    inv = yaml.safe_load(INVENTORY_FILE.read_text()) or {}
    hosts = {}
    for grp in inv.get("all", inv).get("children", inv).values():
        if isinstance(grp, dict) and grp.get("hosts"): hosts.update(grp["hosts"])
    return hosts

def save_inventory(hosts):
    INVENTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    yaml.dump({"all": {"children": {"eos_switches": {"hosts": hosts}}}},
              INVENTORY_FILE.open("w"), default_flow_style=False, sort_keys=False)

def show_table(hosts):
    if not hosts: warn("No switches."); return
    print(f"\n  {'Hostname':<25} {'IP':<18} {'Extra SANs'}")
    print(f"  {'-'*25} {'-'*18} {'-'*30}")
    for n, v in hosts.items():
        v = v or {}
        print(f"  {n:<25} {v.get('ansible_host','N/A'):<18} {', '.join(v.get('cert_sans',[])) or '-'}")
    print()

def import_csv(path, hosts):
    imported = skipped = 0
    for i, row in enumerate(csv.reader(open(path, newline="")), 1):
        if not row or row[0].strip().lower() in ("hostname","host","name",""): continue
        h = row[0].strip()
        if len(row) < 2 or not row[1].strip(): warn(f"Row {i}: no IP"); skipped += 1; continue
        ip = row[1].strip()
        if val_ip(ip): warn(f"Row {i}: bad IP"); skipped += 1; continue
        hv = {"ansible_host": ip}
        if len(row) >= 3 and row[2].strip():
            hv["cert_sans"] = [s.strip() for s in row[2].split(";") if s.strip()]
        hosts[h] = hv; imported += 1
    return imported, skipped

def menu_switches():
    banner("Manage Switches")
    hosts = load_inventory()
    if hosts: info(f"{len(hosts)} switch(es)"); show_table(hosts)
    else: info("No switches yet")

    act = choose("", [("view","View inventory"),("add","Add switches"),("delete","Delete switches")])
    if act == "view": return

    if act == "delete":
        if not hosts: warn("Nothing to delete."); return
        names = list(hosts)
        for i, n in enumerate(names, 1):
            v = hosts[n] or {}
            print(f"  {i}. {n} ({v.get('ansible_host','N/A')})")
        sel = prompt("Delete which? (numbers or 'all')")
        td = names if sel.lower() == "all" else [names[int(x)-1] for x in sel.split(",") if x.strip().isdigit() and 0 < int(x) <= len(names)]
        if not td or not confirm(f"Delete {len(td)} switch(es)?", False): return
        for n in td: del hosts[n]; ok(f"Deleted {n}")
        save_inventory(hosts); return

    method = choose("", [("csv","Import CSV"),("manual","Enter manually")])
    if method == "csv":
        p = prompt("CSV path", validator=val_path)
        imp, skip = import_csv(p, hosts)
        if imp: ok(f"Imported {imp}")
        if skip: warn(f"Skipped {skip}")
        if not imp: err("No valid entries."); return
    else:
        while True:
            h = prompt("Hostname")
            ip = prompt("Management IP", validator=val_ip)
            sans = prompt("Extra SANs (comma-sep, or blank)", required=False)
            hv = {"ansible_host": ip}
            if sans: hv["cert_sans"] = [s.strip() for s in sans.split(",") if s.strip()]
            hosts[h] = hv; ok(f"Added {h}")
            if not confirm("Add another?"): break
    save_inventory(hosts); show_table(hosts)


# --- PKI ---

def gen_key(bits=2048):
    return rsa.generate_private_key(65537, bits)

def build_sans(hv, hostname):
    sans = []
    if ah := hv.get("ansible_host",""):
        try: sans.append(x509.IPAddress(ipaddress.ip_address(ah)))
        except ValueError: sans.append(x509.DNSName(ah))
    sans.append(x509.DNSName(hostname))
    for e in hv.get("cert_sans",[]):
        try: sans.append(x509.IPAddress(ipaddress.ip_address(e)))
        except ValueError: sans.append(x509.DNSName(e))
    return sans

def make_csr(key, cn, sans, org="", country=""):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org: attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if country: attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    if sans: b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(key, hashes.SHA256())

def validate_cert(hostname, host_dir):
    try:
        cert = x509.load_pem_x509_certificate((host_dir / "switch.crt").read_bytes())
        now = datetime.now(timezone.utc)
        issues = []
        if now < cert.not_valid_before_utc: issues.append("not yet valid")
        if now > cert.not_valid_after_utc: issues.append("expired")
        if (cert.not_valid_after_utc - now).days < 30: issues.append(f"expires in {(cert.not_valid_after_utc - now).days}d")
        key = serialization.load_pem_private_key((host_dir / "switch.key").read_bytes(), None)
        if cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) != \
           key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo):
            issues.append("key mismatch")
        exp = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if issues: err(f"{hostname}: {', '.join(issues)}"); return "FAIL", exp
        ok(f"{hostname}: valid (CN={cn[0].value if cn else 'N/A'}, expires {exp})")
        return "PASS", exp
    except Exception as e:
        err(f"{hostname}: {e}"); return "INVALID", ""

def menu_csrs():
    banner("Generate Keys & CSRs")
    hosts = load_inventory()
    if not hosts: err("No switches. Add first."); return
    show_table(hosts)
    org = prompt("Organization", default="Arista Networks", required=False)
    country = prompt("Country (2 letters)", default="US", validator=val_country)
    bits = int(choose("Key size:", [("2048","2048-bit"),("4096","4096-bit")]))
    CERTS_DIR.mkdir(exist_ok=True)
    for h, hv in hosts.items():
        hv = hv or {}
        d = CERTS_DIR / h; d.mkdir(exist_ok=True)
        k = gen_key(bits)
        kf = d / "switch.key"
        kf.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        kf.chmod(0o600)
        csr = make_csr(k, h, build_sans(hv, h), org, country)
        (d / "switch.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        ok(f"{h}: key + CSR")
    print(f"\n  Saved to: {CERTS_DIR}")
    print(f"  Send CSR files (certs/<hostname>/switch.csr) to your CA provider.")

def menu_import():
    banner("Import Signed Certificates")
    hosts = load_inventory()
    if not hosts: err("No switches."); return
    missing = [h for h in hosts if not (CERTS_DIR/h/"switch.key").exists()]
    if missing: err(f"Keys missing: {', '.join(missing)}. Run option 2 first."); return

    method = choose("", [
        ("dir","From directory (<hostname>.crt)"),
        ("each","Specify each file"),
        ("test","Generate test certs (NOT for production)"),
    ])

    if method == "test":
        warn("Generating TEST certificates — not for production.")
        CA_DIR.mkdir(parents=True, exist_ok=True)
        ca_key = gen_key(4096)
        now = datetime.now(timezone.utc)
        ca_cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA (NOT FOR PRODUCTION)")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA (NOT FOR PRODUCTION)")]))
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
        (CA_DIR/"ca.key").write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        (CA_DIR/"ca.key").chmod(0o600)
        (CA_DIR/"ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        ok("Test CA created")
        results = []
        for h in hosts:
            csr_path = CERTS_DIR/h/"switch.csr"
            if not csr_path.exists(): err(f"{h}: no CSR"); results.append((h,"FAIL","")); continue
            csr = x509.load_pem_x509_csr(csr_path.read_bytes())
            b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
            try:
                b = b.add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
            except x509.ExtensionNotFound: pass
            cert = b.sign(ca_key, hashes.SHA256())
            (CERTS_DIR/h/"switch.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            exp = cert.not_valid_after_utc.strftime("%Y-%m-%d")
            ok(f"{h}: test cert (expires {exp})"); results.append((h,"PASS",exp))
        _show_cert_results(results)
        warn("These are TEST certs. Replace before production.")
        return

    ca_path = CA_DIR / "ca.crt"
    need_ca = not ca_path.exists() or confirm("Replace existing CA cert?")
    if need_ca:
        src = prompt("CA certificate chain (.crt/.pem)", validator=val_path)
        CA_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, ca_path); ok("CA cert saved")

    results = []
    if method == "dir":
        d = Path(prompt("Directory with .crt files", validator=val_path))
        for h in hosts:
            found = next((d/p for p in [f"{h}.crt",f"{h}.pem",f"{h.lower()}.crt",f"{h.lower()}.pem"] if (d/p).exists()), None)
            if not found: err(f"{h}: no .crt found"); results.append((h,"MISSING","")); continue
            shutil.copy2(found, CERTS_DIR/h/"switch.crt")
            results.append(validate_cert(h, CERTS_DIR/h))
    else:
        for h in hosts:
            p = prompt(f"Cert for {h}", validator=val_path)
            shutil.copy2(p, CERTS_DIR/h/"switch.crt")
            results.append(validate_cert(h, CERTS_DIR/h))
    _show_cert_results(results)

def _show_cert_results(results):
    print(f"\n  {'Hostname':<25} {'Status':<10} {'Expires'}")
    print(f"  {'-'*25} {'-'*10} {'-'*12}")
    for h, s, e in results:
        print(f"  {h:<25} {(G if s=='PASS' else R)}{s:<10}{X} {e}")
    p = sum(1 for _,s,_ in results if s=="PASS")
    print(f"\n  OK: {G}{p}{X}  Failed: {R}{len(results)-p}{X}")


# --- CVP pre-flight ---

_cvp_cache = {}

def get_cvp_token():
    info("Paste token directly or enter path to a file containing it.")
    raw = input("  Service account token: ").strip()
    if Path(raw).is_file():
        token = Path(raw).read_text().strip()
        ok(f"Token loaded from {raw}")
    else:
        token = raw
    return token

def connect_cvp(force=False):
    """Returns (cvprac_client, raw_session, cvp_url). Caches connection."""
    if not force and _cvp_cache.get("client"):
        return _cvp_cache["client"], _cvp_cache["session"], _cvp_cache["url"]

    cvp_host = prompt("CVP server (IP or hostname, e.g. 10.10.10.1)")
    token = get_cvp_token()
    cvp_url = f"https://{cvp_host}"

    client = CvpClient()
    info("Connecting to CVP...")
    try:
        client.connect([cvp_host], username="", password="", api_token=token)
        ok("Connected to CVP")
    except Exception as e:
        err(f"Failed to connect: {e}"); return None, None, None

    # Raw session for Resource API v3 (workspace/configlet endpoints)
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {token}"})

    _cvp_cache.update({"client": client, "session": session, "url": cvp_url})
    return client, session, cvp_url

def run_preflight(hosts):
    client, _, _ = connect_cvp()
    if not client: return None

    try: devices = client.api.get_inventory()
    except Exception as e: err(f"Fetch failed: {e}"); return None

    # Identify Undefined container
    try:
        containers = client.api.get_containers()["data"]
        undefined_keys = {c["key"] for c in containers if c.get("name","").lower() in ("undefined", "undefined_container")}
    except Exception:
        undefined_keys = set()

    by_host = {d.get("hostname",""): d for d in devices}
    by_ip = {d.get("ipAddress",""): d for d in devices}
    results = {}
    blocked, needs_action = [], []

    for h, hv in hosts.items():
        ip = (hv or {}).get("ansible_host","")
        dev = by_host.get(h) or by_ip.get(ip)
        if not dev:
            warn(f"{h}: not found in CVP inventory")
            results[h] = "NOT_IN_CVP"; needs_action.append(h)
            continue

        issues = []

        # Check if device is in Undefined container
        container_name = dev.get("parentContainerName", dev.get("containerName", ""))
        container_key = dev.get("parentContainerKey", dev.get("parentContainerId", ""))
        if container_key in undefined_keys or container_name.lower() in ("undefined", "undefined_container"):
            issues.append("in Undefined container")

        # Check provisioning status
        status = dev.get("status", "")
        if status and status.lower() not in ("registered", "provisioned"):
            issues.append(f"status: {status}")

        # Check compliance
        comp = dev.get("complianceCode", "")
        if comp != "0000":
            labels = {"0001": "config", "0002": "image", "0003": "both"}
            issues.append(f"out of compliance ({labels.get(comp, comp)})")

        # Check configlets for SSL conflicts
        try:
            cfgs = client.api.get_configlets_by_device_id(dev.get("systemMacAddress", ""))
            for c in cfgs:
                hits = [l.strip() for l in c.get("config", "").splitlines()
                        if any(k in l.strip().lower() for k in SSL_KEYWORDS)]
                if hits:
                    tag = f"{R}RECONCILED{X}" if c.get("reconciled", False) else "designed"
                    issues.append(f"SSL config in {tag} configlet '{c['name']}'")
                    for l in hits[:3]: print(f"      {l}")
                    results[h] = "SSL_CONFLICT"; blocked.append(h)
        except Exception: pass

        if "in Undefined container" in issues or any("status:" in i for i in issues):
            if h not in blocked:
                results[h] = "NOT_READY"; needs_action.append(h)
            for i in issues: warn(f"{h}: {i}")
        elif h in blocked:
            for i in issues:
                if "SSL config" not in i: warn(f"{h}: {i}")
        elif issues:
            for i in issues: warn(f"{h}: {i}")
            results[h] = "OK_WARN"
        else:
            results[h] = "OK"
            ok(f"{h}: ready")

    # Summary
    ready = sum(1 for v in results.values() if v in ("OK", "OK_WARN"))
    print(f"\n  {B}Pre-flight Summary{X}")
    print(f"  Ready:       {G}{ready}{X}")
    print(f"  Conflicts:   {R}{len(blocked)}{X}")
    print(f"  Not ready:   {Y}{len(needs_action)}{X}")

    if needs_action:
        print(f"\n  {Y}Devices needing attention before deploy:{X}")
        for h in needs_action:
            if results[h] == "NOT_IN_CVP":
                print(f"    {h}: not in CVP — add to inventory and assign to a container")
            else:
                print(f"    {h}: move out of Undefined container and approve in topology")

    if blocked:
        print(f"\n  {R}Devices with SSL config conflicts (will be skipped):{X}")
        for h in blocked: print(f"    {h}")
        warn("Remove SSL config from the CVP configlet, then re-run.")

    return results


# --- CVP configlet + workspace deployment ---

def build_configlet(hostname, cert_pem, key_pem, ca_pem, profile):
    """Build EOS config that installs certs and binds SSL profile to eAPI.
    Make-before-break: new certs installed before switchover."""
    lines = [
        "!", "management security",
        f"   ssl profile {profile}",
        f"      certificate {hostname}.crt key {hostname}.key",
        "      trust certificate ca.crt",
        "!", f"security pki certificate {hostname}.crt",
    ]
    for l in cert_pem.strip().splitlines(): lines.append(f"   {l}")
    lines += ["!", f"security pki key {hostname}.key"]
    for l in key_pem.strip().splitlines(): lines.append(f"   {l}")
    lines += ["!", "security pki certificate ca.crt"]
    for l in ca_pem.strip().splitlines(): lines.append(f"   {l}")
    lines += [
        "!", "management api http-commands",
        f"   protocol https ssl profile {profile}",
        "!",
    ]
    return "\n".join(lines)

def deploy_to_device(client, hostname, device, configlet_config, configlet_name):
    """Create/update configlet and apply to device via cvprac.
    Returns ("OK", task_ids) or ("ERROR", error_message)."""
    try:
        # Create or update the configlet
        info("Creating configlet...")
        try:
            existing = client.api.get_configlet_by_name(configlet_name)
            client.api.update_configlet(configlet_config, existing["key"], configlet_name)
            configlet = client.api.get_configlet_by_name(configlet_name)
            ok(f"Updated: {configlet_name}")
        except Exception:
            client.api.add_configlet(configlet_name, configlet_config)
            configlet = client.api.get_configlet_by_name(configlet_name)
            ok(f"Created: {configlet_name}")

        # Apply configlet to device (creates a task)
        info("Applying configlet to device...")
        result = client.api.apply_configlets_to_device(
            "cert-automation", device, [configlet])
        task_ids = result.get("data", {}).get("taskIds", [])

        if task_ids:
            ok(f"Task(s) created: {', '.join(task_ids)}")
            return "OK", task_ids
        else:
            warn("No tasks created (config may already match)")
            return "OK", []

    except Exception as e:
        err(f"Failed: {e}")
        return "ERROR", str(e)

def menu_deploy():
    banner("Deploy Certificates via CVP Workspace")
    hosts = load_inventory()
    if not hosts: err("No switches."); return
    for check, msg in [
        (any(not (CERTS_DIR/h/"switch.crt").exists() for h in hosts), "Missing certs. Run options 2+3 first."),
        (any(not (CERTS_DIR/h/"switch.key").exists() for h in hosts), "Missing keys. Run option 2 first."),
        (not (CA_DIR/"ca.crt").exists(), "Missing CA cert. Run option 3 first."),
    ]:
        if check: err(msg); return
    show_table(hosts)

    # CVP pre-flight check + connect
    pf = run_preflight(hosts)
    if not pf: err("CVP connection required for deployment."); return
    skip = [h for h, v in pf.items() if v in ("SSL_CONFLICT", "NOT_READY", "NOT_IN_CVP")]
    if skip:
        warn(f"Skipping {len(skip)} device(s) not ready for deploy.")
        hosts = {h: v for h, v in hosts.items() if h not in skip}
        if not hosts: err("No devices ready. Fix issues above and re-run."); return
        info(f"Proceeding with {len(hosts)} device(s)")
        show_table(hosts)

    # Re-use cached CVP connection
    client, _, _ = connect_cvp()
    if not client: return

    try: devices = client.api.get_inventory()
    except Exception: err("Failed to fetch inventory."); return
    by_host = {d.get("hostname",""): d for d in devices}
    by_ip = {d.get("ipAddress",""): d for d in devices}

    profile = prompt("SSL profile name", default="CA_SIGNED_PROFILE")
    batch = int(prompt("Batch size", default="50"))

    matched = []
    for h, hv in hosts.items():
        ip = (hv or {}).get("ansible_host","")
        dev = by_host.get(h) or by_ip.get(ip)
        if dev: matched.append((h, dev))
        else: warn(f"{h}: not found in CVP, skipping")

    if not matched: err("No devices matched."); return
    sections = math.ceil(len(matched) / batch)

    print(f"\n  Devices: {len(matched)}  Batch: {batch}  Sections: {sections}")
    warn("Configlets will be created and assigned. Tasks will be generated for you to execute in CVP.")
    if not confirm("Proceed?"): return

    ca_pem = (CA_DIR/"ca.crt").read_text()
    all_res, all_tasks = [], []

    for sec in range(sections):
        s, e = sec*batch, min((sec+1)*batch, len(matched))
        chunk = matched[s:e]
        banner(f"Section {sec+1}/{sections} (devices {s+1}-{e})")

        results = []
        for i, (h, dev) in enumerate(chunk):
            print(f"\n  {B}[{s+i+1}/{len(matched)}] {h}{X}")
            cert_pem = (CERTS_DIR/h/"switch.crt").read_text()
            key_pem = (CERTS_DIR/h/"switch.key").read_text()
            config = build_configlet(h, cert_pem, key_pem, ca_pem, profile)
            st, detail = deploy_to_device(client, h, dev, config, f"SSL_CERT_{h}")
            if st == "OK":
                task_ids = detail if isinstance(detail, list) else []
                all_tasks.extend(task_ids)
                results.append((h, "OK", ", ".join(task_ids) if task_ids else "no tasks"))
            else:
                results.append((h, "ERROR", detail))

        all_res.extend(results)
        o = sum(1 for _,s,_ in results if s=="OK")
        print(f"\n  {B}Section {sec+1}:{X} {G}{o} OK{X}, {R}{len(results)-o} failed{X}")
        print(f"  {'Hostname':<25} {'Status':<10} {'Detail'}")
        print(f"  {'-'*25} {'-'*10} {'-'*40}")
        for h, st, det in results:
            c = G if st=="OK" else R
            print(f"  {h:<25} {c}{st:<10}{X} {det}")

        if sec < sections-1:
            print(f"\n  {Y}>>> Execute tasks above in CVP before continuing.{X}")
            if not confirm(f"Proceed to section {sec+2}?"): break

    banner("Summary")
    t_ok = sum(1 for _,s,_ in all_res if s=="OK")
    print(f"  Processed: {len(all_res)}/{len(matched)}  OK: {G}{t_ok}{X}  Failed: {R}{len(all_res)-t_ok}{X}")
    if all_tasks:
        print(f"\n  {B}Tasks created ({len(all_tasks)}):{X}")
        for t in all_tasks: print(f"    - {t}")
        print(f"\n  {Y}>>> Go to CVP > Tasks{X}")
        print(f"  {Y}>>> Execute tasks to push config to devices.{X}")


# --- Verify ---

def menu_verify():
    banner("Verify Certificates")
    hosts = load_inventory()
    if not hosts: err("No switches."); return
    results = []
    for h, hv in hosts.items():
        ip = (hv or {}).get("ansible_host","")
        if not ip: results.append((h,"","NO_IP","","")); continue
        info(f"{h} ({ip}:443)...")
        try:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=h) as ss:
                    cert = x509.load_der_x509_certificate(ss.getpeercert(binary_form=True))
                    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    exp = cert.not_valid_after_utc.strftime("%Y-%m-%d")
                    st = "SELF-SIGNED" if cert.subject == cert.issuer else "CA-SIGNED"
                    results.append((h, ip, st, cn[0].value if cn else "N/A", exp))
        except Exception as e: err(f"{h}: {e}"); results.append((h,ip,"UNREACHABLE","",""))

    print(f"\n  {'Hostname':<25} {'IP':<18} {'CN':<20} {'Expires':<12} {'Status'}")
    print(f"  {'-'*25} {'-'*18} {'-'*20} {'-'*12} {'-'*12}")
    for h, ip, st, cn, exp in results:
        c = G if st=="CA-SIGNED" else (R if st=="SELF-SIGNED" else Y)
        print(f"  {h:<25} {ip:<18} {cn:<20} {exp:<12} {c}{st}{X}")


# --- Rollback ---

def menu_rollback():
    banner("Rollback (Remove SSL Configlets from CVP)")
    client, _, _ = connect_cvp()
    if not client: return

    info("Searching for SSL certificate configlets...")
    try:
        all_cfgs = client.api.get_configlets()["data"]
    except Exception as e:
        err(f"Failed to fetch configlets: {e}"); return

    ssl_cfgs = [c for c in all_cfgs if c.get("name","").startswith("SSL_CERT_")]
    if not ssl_cfgs:
        info("No SSL_CERT_* configlets found."); return

    print(f"\n  {B}SSL Certificate Configlets:{X}")
    for i, c in enumerate(ssl_cfgs, 1):
        print(f"    {i}. {c['name']}")

    sel = prompt("Delete which? (numbers or 'all')")
    if sel.lower() == "all":
        to_del = ssl_cfgs
    else:
        idx = [int(x)-1 for x in sel.split(",") if x.strip().isdigit()]
        to_del = [ssl_cfgs[i] for i in idx if 0 <= i < len(ssl_cfgs)]

    if not to_del: info("None selected."); return
    if not confirm(f"Delete {len(to_del)} configlet(s)?", False): return

    for c in to_del:
        try:
            client.api.delete_configlet(c["name"], c["key"])
            ok(f"Deleted: {c['name']}")
        except Exception as e: err(f"{c['name']}: {e}")

    warn("Configlets removed from CVP. If config was already pushed,")
    warn("eAPI will revert to self-signed on the next compliance push.")


# --- Main ---

def main():
    banner("Arista EOS Certificate Automation")
    print(f"  Dir: {BASE_DIR}")
    hosts = load_inventory()
    if hosts: info(f"{len(hosts)} switch(es)")
    csrs = sum(1 for d in CERTS_DIR.iterdir() if d.is_dir() and (d/"switch.csr").exists()) if CERTS_DIR.exists() else 0
    certs = sum(1 for d in CERTS_DIR.iterdir() if d.is_dir() and (d/"switch.crt").exists()) if CERTS_DIR.exists() else 0
    if csrs: info(f"CSRs: {csrs}")
    if certs: info(f"Certs: {certs}")

    while True:
        choice = choose("", [
            ("sw","Manage switches"), ("csr","Generate keys & CSRs"),
            ("imp","Import / generate certs"), ("dep","Deploy via CVP configlet"),
            ("ver","Verify certs"), ("rb","Rollback (remove CVP configlets)"), ("q","Exit"),
        ])
        {"sw":menu_switches, "csr":menu_csrs, "imp":menu_import,
         "dep":menu_deploy, "ver":menu_verify, "rb":menu_rollback,
         "q": lambda: (print(f"\n  {C}Goodbye!{X}\n"), sys.exit(0))
        }[choice]()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n  {Y}Interrupted.{X}"); sys.exit(130)
