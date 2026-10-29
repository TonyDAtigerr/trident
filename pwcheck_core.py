#!/usr/bin/env python3
"""
pwdlast-check -- verify remediation of cross-domain privileged password reuse.

Checks whether flagged accounts actually had their passwords reset, by reading
pwdLastSet across the domains each account appears in. For a password-REUSE
finding, remediation means the passwords no longer match -- so an account is
marked REMEDIATED if it was reset within the assessment window in at least one
domain (which breaks the match), or if it is no longer present in two or more
domains (so there is no cross-domain pair left to reuse).

Reads work with a single low-privilege account across domain trusts: the tool
authenticates over SMB using your home domain (the trust path) and reads
pwdLastSet via SAMR (--users), falling back to LDAP. It auto-detects which DC
and auth realm work per domain, so one account can verify every domain it can
reach without hard-coding DCs or realms.

LIMITATION (state this in your report):
    pwdLastSet proves a password was *changed*, not that it was changed to a
    *different, non-reused* value. If both sides were reset to the same new
    password, the hashes could still match. Cryptographic proof of non-reuse
    requires a hash comparison (NTDS / DCSync) under privilege. This tool gives
    the strongest low-privilege evidence: a necessary, not sufficient, condition.

Requirements
------------
    - netexec (nxc) on PATH
    - Python 3.8+
    - openpyxl                 (optional, for --xlsx)
    - dnspython, ldap3         (optional, only for --forest auto-discovery)

Inputs
------
    users file   : one sAMAccountName per line.
    domains file : one domain per line, optionally 'domain,dc' (a bare domain is
                   resolved to a DC via SRV). Include the account's home domain so
                   the tool can learn the trust realm.

Usage
-----
    pwdlast-check.py -u users.txt -d domains.txt -U user -P 'pass' \
        --testing-start 05/12/2026 -o Results

    # stored netexec credential instead of -U/-P:
    pwdlast-check.py -u users.txt -d domains.txt --id 1 --testing-start 05/12/2026 -o Results

-o writes Results.txt, Results.csv and Results.xlsx (green = REMEDIATED,
red = NOT REMEDIATED, orange = UNVERIFIED). See --help for all options.

For authorized security assessments only. Use only against systems you have
explicit written permission to test.
"""

import argparse
import csv
import datetime
import re
import shutil
import subprocess
import sys

# Optional deps, only needed for --forest auto-discovery. Guarded so the
# live/offline modes work without them.
try:
    import dns.resolver as _dnsresolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False
try:
    import ldap3 as _ldap3
    HAVE_LDAP3 = True
except ImportError:
    HAVE_LDAP3 = False

# --- Windows FILETIME epoch offset (100ns intervals since 1601-01-01) -------
EPOCH_DIFF = 116444736000000000

# --- userAccountControl bit flags -------------------------------------------
UAC_FLAGS = {
    0x0001: "LOGON_SCRIPT",
    0x0002: "ACCOUNT_DISABLED",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}
ACCOUNT_DISABLED = 0x0002

# netexec ldap --query output lines look like:
#   LDAP  10.0.0.1  389  DC01  sAMAccountName  jsmith
#   LDAP  10.0.0.1  389  DC01  pwdLastSet      133445...
# i.e. LDAP, host, port, dc-name, attribute, value
LDAP_LINE = re.compile(r"LDAP\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.*)")


def decode_uac(val):
    flags = [name for bit, name in UAC_FLAGS.items() if val & bit]
    return ", ".join(flags) if flags else "UNKNOWN"


def convert_timestamp(val):
    """Convert a pwdLastSet FILETIME integer to a timezone-aware UTC datetime.

    Returns (datetime|None, display_string).
    """
    if val == 0:
        return None, "Never Set (0)"
    unix_ts = (val - EPOCH_DIFF) / 10_000_000
    try:
        dt = datetime.datetime.fromtimestamp(unix_ts, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None, f"INVALID ({val})"
    return dt, dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_pwdlastset(raw):
    """netexec usually returns pwdLastSet as the raw FILETIME int, but some
    versions pre-format it. Handle both. Returns (datetime|None, display)."""
    raw = raw.strip()
    if raw == "":
        return None, "(empty)"
    # raw FILETIME integer (the common case)
    try:
        return convert_timestamp(int(raw))
    except ValueError:
        pass
    # already a date string from a newer netexec -- try a couple of formats
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt, dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            continue
    return None, raw  # unknown shape -- keep as-is


def _nxc_creds_args(creds, realm):
    """Build the netexec auth args. `realm` is the -d value, or None to OMIT -d
    (so netexec discovers the DC's real domain -- handles domains.txt names that
    don't match the DC's actual domain). A stored credential id (-id) short-
    circuits everything, exactly like `nxc smb ... -id N`."""
    if creds.get("cred_id"):
        return ["-id", str(creds["cred_id"])]
    args = []
    if realm:
        args += ["-d", realm]
    if creds.get("kerberos"):
        args += ["-k"]
    if creds.get("nthash"):
        args += ["-u", creds["username"], "-H", creds["nthash"]]
    else:
        args += ["-u", creds["username"], "-p", creds["password"]]
    return args


def run_query(target, realm, user, creds, nxc_bin, timeout):
    """Run netexec ldap --query for one user against one DC. realm is the -d value
    or None (omit -d). Returns raw stdout."""
    cmd = [nxc_bin, "ldap", target] + _nxc_creds_args(creds, realm) + \
          ["--query", f"(sAMAccountName={user})",
           "sAMAccountName pwdLastSet userAccountControl"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "__ERROR__ query timed out"
    except FileNotFoundError:
        return f"__ERROR__ '{nxc_bin}' not found (install netexec, or set --nxc-bin)"


def run_query_smb(target, realm, user, creds, nxc_bin, timeout):
    """Run netexec smb --users for one user against a DC (SAMR path). Works when
    LDAP is blocked by signing. realm is the -d value or None. Returns raw stdout."""
    cmd = [nxc_bin, "smb", target] + _nxc_creds_args(creds, realm) + ["--users", user]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "__ERROR__ query timed out"
    except FileNotFoundError:
        return f"__ERROR__ '{nxc_bin}' not found (install netexec, or set --nxc-bin)"


# A data row from `nxc smb --users`:
#   SMB  host  445  DC01  <user>  <YYYY-MM-DD HH:MM:SS | <never>>  <badpw>  <desc>
# The username may be bare or DOMAIN\user. Header/status lines won't match
# because they lack a date / <never> token in that position.
SMB_USER_LINE = re.compile(
    r"^SMB\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+"
    r"(?P<pwd><never>|\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?)\s+"
    r"\d+\b(?P<desc>.*)$",
    re.IGNORECASE)


def parse_smb_users(text):
    """Parse `nxc smb --users` output -> {username_lower: pwdlastset_string}."""
    out = {}
    for line in text.splitlines():
        m = SMB_USER_LINE.match(line)
        if m:
            u = m.group("user").split("\\")[-1]
            out[u.lower()] = m.group("pwd").strip()
    return out


def parse_smb_pwdlastset(s):
    """A netexec smb 'Last PW Set' string -> (datetime|None, display)."""
    s = (s or "").strip()
    if s == "" or s.lower() == "<never>":
        return None, "Never Set"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
            return dt, dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            continue
    return None, s


def build_record_smb(out, user):
    """Build a result record from `nxc smb --users` output for one user."""
    rows = parse_smb_users(out)
    key = user.lower()
    datestr = None
    if key in rows:
        datestr = rows[key]
    elif len(rows) == 1:            # single row returned by the filter
        datestr = next(iter(rows.values()))
    if datestr is None:
        return None                 # not found in output
    dt, disp = parse_smb_pwdlastset(datestr)
    # SMB --users does not expose userAccountControl, so 'disabled' is unknown here.
    return {"present": True, "pwd_dt": dt, "pwd_disp": disp,
            "uac": None, "disabled": None, "error": None}


def parse_query_output(text):
    """Pull attribute/value pairs out of netexec ldap output.
    Returns dict of {attr: value} (last value wins)."""
    attrs = {}
    for line in text.splitlines():
        m = LDAP_LINE.match(line)
        if m:
            attrs[m.group(1)] = m.group(2).strip()
    return attrs


# Signatures in netexec output that mean the DC was unreachable vs the bind
# was rejected. Checked case-insensitively.
_UNREACHABLE_SIGS = (
    "error connecting", "connection refused", "connection error",
    "unable to connect", "can't contact", "cannot contact",
    "no route to host", "timed out", "timeout", "network is unreachable",
    "name or service not known", "could not resolve", "socket",
)
_AUTHFAIL_SIGS = (
    "status_logon_failure", "status_wrong_password", "status_account_locked_out",
    "status_account_disabled", "status_account_restriction",
    "status_password_expired", "status_password_must_change",
    "status_access_denied", "status_logon_type_not_granted",
    "status_not_supported", "invalid credentials", "authentication failed",
    "strongerauthrequired", "status_trusted_relationship_failure",
)


def detect_auth_status(text):
    """Classify a netexec LDAP run: 'ok', 'auth_failed', 'unreachable', 'unknown'.

    Lets the caller tell "the account isn't there" (auth OK, no object) apart
    from "I couldn't authenticate to this DC" (bind rejected) and "I couldn't
    reach this DC at all" (network/DNS)."""
    # Success first: a [+] bind line means auth worked, regardless of any other
    # substrings in the output. Only if there's no success marker do we look at
    # failure signatures (and only on [-] lines, to avoid matching returned data).
    if "[+]" in text:
        return "ok"
    fail_text = "\n".join(ln for ln in text.splitlines() if "[-]" in ln).lower()
    if not fail_text:
        return "unknown"
    for sig in _UNREACHABLE_SIGS:
        if sig in fail_text:
            return "unreachable"
    for sig in _AUTHFAIL_SIGS:
        if sig in fail_text:
            return "auth_failed"
    return "auth_failed"  # a [-] line with no recognised code is still a failure


def build_record(attrs):
    """Turn an {attr: value} dict into a result record (present / pwd_dt /
    pwd_disp / uac / disabled / error). Shared by live and offline paths."""
    rec = {"present": False, "pwd_dt": None, "pwd_disp": "NOT PRESENT",
           "uac": None, "disabled": None, "error": None}
    # A returned sAMAccountName OR a pwdLastSet attribute both prove the object exists.
    if attrs.get("sAMAccountName") or "pwdLastSet" in attrs:
        rec["present"] = True
    if "pwdLastSet" in attrs:
        rec["pwd_dt"], rec["pwd_disp"] = parse_pwdlastset(attrs["pwdLastSet"])
    if "userAccountControl" in attrs:
        try:
            uac = int(str(attrs["userAccountControl"]).split()[0])
            rec["uac"] = uac
            rec["disabled"] = bool(uac & ACCOUNT_DISABLED)
        except (ValueError, IndexError):
            pass
    return rec


# Matches already-converted lines from the original convert script, e.g.
#   pwdLastSet: 133145... (2024-01-01 00:00:00 UTC)
#   userAccountControl: 512 (NORMAL_ACCOUNT)
#   sAMAccountName: jsmith
CONVERTED_LINE = re.compile(r"^([A-Za-z]\w+):\s*(.*)$")
HEADER_LINE = re.compile(r"^===\s*(.*?)\s*===\s*$")


def parse_results_file(path):
    """Parse a pre-collected ldap_results file grouped into '=== user ==='
    blocks. Handles BOTH the raw netexec format (LDAP ... attr value) and the
    already-converted format (attr: value (...)). Returns {user: {attr: val}}."""
    out = {}
    current = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            h = HEADER_LINE.match(line)
            if h:
                current = h.group(1).strip()
                out.setdefault(current, {})
                continue
            if current is None or line.strip() == "":
                continue

            # raw netexec line?
            m = LDAP_LINE.match(line)
            if m:
                attr, val = m.group(1), m.group(2).strip()
            else:
                # already-converted "attr: value" line
                c = CONVERTED_LINE.match(line)
                if not c:
                    continue
                attr, val = c.group(1), c.group(2).strip()

            # For the numeric attrs, keep only the raw number (strip any
            # trailing "(decoded...)" that the converter appended).
            if attr in ("pwdLastSet", "userAccountControl"):
                val = val.split()[0] if val.split() else val
            out[current][attr] = val
    return out


def load_offline(parse_specs, users_filter):
    """Build results[user][domain] = record from pre-collected files.
    parse_specs: list of (domain, filepath). users_filter: ordered list or None.
    Returns (results, domain_names, users)."""
    per_domain = {}        # domain -> {user: attrs}
    seen_users = []        # preserve first-seen order across files
    domain_names = []
    for domain, filepath in parse_specs:
        print(f"[*] Loading {domain} from {filepath} ...", file=sys.stderr)
        parsed = parse_results_file(filepath)
        per_domain[domain] = parsed
        domain_names.append(domain)
        for u in parsed:
            if u not in seen_users:
                seen_users.append(u)

    users = users_filter if users_filter else seen_users
    results = {u: {} for u in users}
    for domain in domain_names:
        parsed = per_domain[domain]
        for u in users:
            attrs = parsed.get(u)
            if attrs is None:
                # user header absent from this domain's file -> not present
                results[u][domain] = {"present": False, "pwd_dt": None,
                                      "pwd_disp": "NOT PRESENT", "uac": None,
                                      "disabled": None, "error": None}
            else:
                results[u][domain] = build_record(attrs)
    return results, domain_names, users


def read_one_user(via, target, realm, u, creds, nxc_bin, timeout):
    """Read one user over one protocol. realm is the -d value or None. Returns
    (raw_output, record_or_None); record is present if the object/row came back."""
    if via == "smb":
        out = run_query_smb(target, realm, u, creds, nxc_bin, timeout)
    else:
        out = run_query(target, realm, u, creds, nxc_bin, timeout)
    if out.startswith("__ERROR__"):
        return out, None
    if via == "smb":
        return out, build_record_smb(out, u)
    attrs = parse_query_output(out)
    if attrs.get("sAMAccountName") or "pwdLastSet" in attrs:
        return out, build_record(attrs)
    return out, None


def run_query_smb_all(target, realm, creds, nxc_bin, timeout):
    """Enumerate ALL domain users once (SAMR) -> raw stdout. One call reads every
    user's Last PW Set, instead of one call per user."""
    cmd = [nxc_bin, "smb", target] + _nxc_creds_args(creds, realm) + ["--users"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout, 120))
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "__ERROR__ enumeration timed out"
    except FileNotFoundError:
        return f"__ERROR__ '{nxc_bin}' not found (install netexec, or set --nxc-bin)"


def run_query_ldap_bulk(target, realm, users, creds, nxc_bin, timeout):
    """One LDAP query for ALL requested users via an OR filter -> raw stdout."""
    ors = "".join(f"(sAMAccountName={u})" for u in users)
    filt = f"(&(objectClass=user)(|{ors}))"
    cmd = [nxc_bin, "ldap", target] + _nxc_creds_args(creds, realm) + \
          ["--query", filt, "sAMAccountName pwdLastSet userAccountControl"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout, 120))
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "__ERROR__ query timed out"
    except FileNotFoundError:
        return f"__ERROR__ '{nxc_bin}' not found (install netexec, or set --nxc-bin)"


def parse_ldap_bulk(out):
    """Group a multi-object LDAP --query result into {username_lower: {attr: val}}
    by starting a new object at each sAMAccountName line."""
    objs, current = {}, None
    for line in out.splitlines():
        m = LDAP_LINE.match(line)
        if not m:
            continue
        attr, val = m.group(1), m.group(2).strip()
        if attr == "sAMAccountName":
            current = val.lower()
            objs[current] = {"sAMAccountName": val}
        elif current is not None:
            objs[current][attr] = val
    return objs


def _rec_err(disp, err):
    return {"present": False, "pwd_dt": None, "pwd_disp": disp,
            "uac": None, "disabled": None, "error": err}


def _rec_not_present():
    return {"present": False, "pwd_dt": None, "pwd_disp": "NOT PRESENT",
            "uac": None, "disabled": None, "error": None}


def read_domain_bulk(domain_fqdn, target, via, realm, users, creds, nxc_bin,
                     timeout, fallback, raw_fh, raw_lock):
    """Read every requested user in ONE domain using bulk netexec calls.
    Returns {user: record}. SMB enumerates all users once; LDAP uses one OR query."""
    def log_raw(tag, text):
        if raw_fh:
            with raw_lock:
                raw_fh.write(f"=== {tag} @ {domain_fqdn} (-d "
                             f"{realm if realm else 'auto'}) ===\n{text}\n\n")

    def smb_pass():
        out = run_query_smb_all(target, realm, creds, nxc_bin, timeout)
        log_raw("ALL users (smb)", out)
        if out.startswith("__ERROR__"):
            return None, "error", out
        rows = parse_smb_users(out)           # {username_lower: pwdlastset_string}
        status = detect_auth_status(out)
        if not rows and status in ("auth_failed", "unreachable"):
            return None, status, out
        recs = {}
        for u in users:
            if u.lower() in rows:
                dt, disp = parse_smb_pwdlastset(rows[u.lower()])
                recs[u] = {"present": True, "pwd_dt": dt, "pwd_disp": disp,
                           "uac": None, "disabled": None, "error": None}
            else:
                recs[u] = _rec_not_present()
        return recs, "ok", out

    def ldap_pass():
        out = run_query_ldap_bulk(target, realm, users, creds, nxc_bin, timeout)
        log_raw("bulk (ldap)", out)
        if out.startswith("__ERROR__"):
            return None, "error", out
        objs = parse_ldap_bulk(out)
        status = detect_auth_status(out)
        if not objs and status in ("auth_failed", "unreachable"):
            return None, status, out
        recs = {}
        for u in users:
            attrs = objs.get(u.lower())
            recs[u] = build_record(attrs) if attrs else _rec_not_present()
        return recs, "ok", out

    primary, secondary = (smb_pass, ldap_pass) if via == "smb" else (ldap_pass, smb_pass)
    recs, status, out = primary()
    if recs is None and fallback:
        recs2, status2, out2 = secondary()
        if recs2 is not None:
            other = "ldap" if via == "smb" else "smb"
            for u in recs2:                    # tag values obtained via fallback
                if recs2[u].get("present"):
                    recs2[u] = dict(recs2[u])
                    recs2[u]["pwd_disp"] = f"{recs2[u]['pwd_disp']} (via {other})"
            return recs2
    if recs is not None:
        return recs
    # Couldn't read the domain at all -- classify why, for every user.
    if status == "auth_failed":
        return {u: _rec_err("CANNOT AUTH TO DC (current user)", "auth_failed") for u in users}
    if status == "unreachable":
        return {u: _rec_err("DC UNREACHABLE", "dc_unreachable") for u in users}
    msg = out.replace("__ERROR__", "").strip() if out else "error"
    return {u: _rec_err("QUERY ERROR", msg) for u in users}


def collect(users, domains, creds, nxc_bin, timeout, raw_fh, domain_status=None,
            via="ldap", fallback=False, domain_auth=None, home_domain=None,
            max_workers=8, domain_users=None):
    """Query every user in every domain and return results[user][domain] = record.
    FAST path: one bulk netexec call per domain (SMB enumerates all users; LDAP
    uses one OR query), and domains are processed in parallel threads.
    domain_users[domain] optionally restricts which users to report per domain
    (used by the per-account 'username@domain' weak-password mode)."""
    results = {u: {} for u in users}
    has_auth_map = domain_auth is not None
    using_id = bool(creds.get("cred_id"))
    raw_lock = __import__("threading").Lock()

    def users_for(domain_fqdn):
        if domain_users is not None:
            return domain_users.get(domain_fqdn, [])
        return users

    def process_domain(dom):
        domain_fqdn, target = dom
        dom_users = users_for(domain_fqdn)
        auth_realm = domain_auth.get(domain_fqdn) if has_auth_map else domain_fqdn
        st = (domain_status or {}).get(domain_fqdn)
        if st in ("unreachable", "error"):
            print(f"[*] {domain_fqdn}: DC unreachable (pre-flight) -- skipping", file=sys.stderr)
            return domain_fqdn, {u: _rec_err("DC UNREACHABLE", "dc_unreachable") for u in dom_users}

        # SMB TRUST PATH IS THE PRIORITY. For every domain, authenticate over SMB
        # trying the HOME (trust) realm first, then the pre-flight realm, then
        # DC-discovered -- and use the first that binds. The home realm is how a
        # single account reaches a trusted domain's DC, so trying it first means a
        # foreign domain authenticates over the trust rather than being rejected.
        # Skipped only with --id (netexec resolves the domain itself) and when the
        # pre-flight already settled on the home realm for an already-ok domain.
        if not using_id and not (st == "ok" and auth_realm == home_domain):
            realms = []
            if home_domain:
                realms.append(home_domain)                 # trust path first
            if auth_realm is not None and auth_realm not in realms:
                realms.append(auth_realm)                   # pre-flight realm
            if None not in realms:
                realms.append(None)                         # DC-discovered, last
            for rl in realms:
                if smoke_check_domain(target, rl, creds, nxc_bin,
                                      min(timeout, 20), "smb") == "ok":
                    if rl != auth_realm:
                        print(f"[*] {domain_fqdn}: SMB auth via realm "
                              f"'{rl if rl else 'auto/DC-discovered'}' (trust path)",
                              file=sys.stderr)
                    auth_realm = rl
                    break

        realm_disp = auth_realm if auth_realm else "auto/DC-discovered"
        fb_note = f" + {'ldap' if via == 'smb' else 'smb'} fallback" if fallback else ""
        print(f"[*] {domain_fqdn}: reading {len(dom_users)} account(s) via "
              f"{via.upper()}{fb_note} [auth: {realm_disp}] ...", file=sys.stderr)
        recs = read_domain_bulk(domain_fqdn, target, via, auth_realm, dom_users, creds,
                                nxc_bin, timeout, fallback, raw_fh, raw_lock)
        return domain_fqdn, recs

    workers = max(1, min(max_workers, len(domains)))
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(process_domain, dom) for dom in domains]
        for fut in as_completed(futures):
            domain_fqdn, recs = fut.result()
            for u, rec in recs.items():
                results[u][domain_fqdn] = rec
    return results


def _in_window(dt, te, now):
    return dt is not None and te is not None and te <= dt <= now


def domain_reset_in_window(rec, te, now):
    """Per-domain indicator for display: 'Yes' / 'No' / 'Unverified' / ''."""
    if te is None or rec is None:
        return ""
    if rec.get("error") in ("auth_failed", "dc_unreachable") \
            or rec.get("pwd_disp", "").startswith("QUERY ERROR"):
        return "Unverified"
    if not rec.get("present") or rec.get("pwd_dt") is None:
        return ""
    return "Yes" if _in_window(rec["pwd_dt"], te, now) else "No"


def user_remediation(recs, te, now):
    """Per-USER remediation verdict across all the domains the account appears in.

    Credential-REUSE finding: the accounts shared a password across domains, so
    remediation means they can no longer match. That happens if EITHER:
      (a) the password was reset within the window in at least one domain
          (the values no longer match), OR
      (b) the account is no longer present in 2+ domains (removed from one, so
          there is no cross-domain pair left to reuse).
    Only CONFIRMED absence counts for (b) -- a domain we couldn't authenticate to
    is 'unverified', not 'absent'.

    Returns REMEDIATED / NOT REMEDIATED / UNVERIFIED / N/A (or "" if off)."""
    if te is None:
        return ""
    present_count, unverified_count = 0, 0
    present_dts = []
    for _d, r in (recs or {}).items():
        if r is None:
            unverified_count += 1
            continue
        if r.get("error") in ("auth_failed", "dc_unreachable") \
                or r.get("pwd_disp", "").startswith("QUERY ERROR"):
            unverified_count += 1
            continue
        if not r.get("present"):          # auth worked, object absent -> confirmed gone
            continue
        present_count += 1
        if r.get("pwd_dt") is not None:
            present_dts.append(r["pwd_dt"])

    # (a) a reset within the window in any present domain breaks the match.
    if any(_in_window(dt, te, now) for dt in present_dts):
        return "REMEDIATED"
    # Still present (and unchanged) in 2+ domains -> the reuse persists.
    if present_count >= 2:
        return "NOT REMEDIATED"
    # (b) present in fewer than two domains, and we're sure (no unverified) ->
    # no cross-domain pair remains, so the reuse can't exist.
    if unverified_count == 0:
        return "REMEDIATED"
    # present in <2 but some domains unreadable -> can't confirm it isn't in one.
    return "UNVERIFIED"


def _rem_explanation(verdict):
    return {
        "REMEDIATED": "reset in-window, or no longer in 2+ domains -- reuse broken",
        "NOT REMEDIATED": "still present & unchanged in 2+ domains -- may still match",
        "UNVERIFIED": "could not fully verify (some domains unreadable)",
        "N/A": "account not present / no pwdLastSet to assess",
    }.get(verdict, "")


_ILLEGAL_XLSX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _safe(v):
    """Strip control chars Excel rejects from a cell value."""
    return _ILLEGAL_XLSX.sub("", v) if isinstance(v, str) else v


# ======================= per-account (weak-password) mode =======================
# Each input line is 'username@domain' -- a specific account in a specific domain
# (e.g. accounts found with weak/crackable passwords). The verdict is simple: was
# THIS account's password reset within the window? No cross-domain reuse logic.

def account_remediation(rec, te, now):
    """Per-account verdict for the weak-password check: REMEDIATED if this
    account's password was reset within [te, now], else NOT REMEDIATED."""
    if te is None:
        return ""
    if rec is None:
        return "UNVERIFIED"
    if rec.get("error") in ("auth_failed", "dc_unreachable") \
            or rec.get("pwd_disp", "").startswith("QUERY ERROR"):
        return "UNVERIFIED"
    if not rec.get("present"):
        return "NOT PRESENT"              # account gone -- flag for review
    dt = rec.get("pwd_dt")
    if dt is None:
        return "UNKNOWN"
    return "REMEDIATED" if _in_window(dt, te, now) else "NOT REMEDIATED"


def read_accounts(path):
    """Parse a 'username@domain' list. Returns (accounts, domain_users) where
    accounts is an ordered list of (username, domain) and domain_users maps
    domain -> [usernames]. Lines without '@' are skipped with a warning."""
    accounts, domain_users = [], {}
    for ln in read_lines(path):
        if "@" not in ln:
            print(f"[!] skipping '{ln}' -- expected username@domain", file=sys.stderr)
            continue
        user, domain = ln.rsplit("@", 1)
        user, domain = user.strip(), domain.strip()
        if not user or not domain:
            continue
        accounts.append((user, domain))
        domain_users.setdefault(domain, [])
        if user not in domain_users[domain]:
            domain_users[domain].append(user)
    return accounts, domain_users


def write_report_accounts(fh, accounts, results, run_dt, testing_start_dt):
    sep = "=" * 78
    fh.write(sep + "\n")
    fh.write("WEAK-PASSWORD RESET VERIFICATION\n")
    now = run_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    fh.write(f"Generated: {now}\n")
    if testing_start_dt:
        fh.write(f"Reset window: {testing_start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                 f"(assessment start)  ->  {now} (now)\n")
        fh.write("  (an account is remediated only if its password was reset within this window)\n")
    fh.write(sep + "\n\n")
    for user, domain in accounts:
        rec = results.get(user, {}).get(domain)
        disp = rec.get("pwd_disp", "NOT QUERIED") if rec else "NOT QUERIED"
        v = account_remediation(rec, testing_start_dt, run_dt) if testing_start_dt else ""
        tag = f"   => {v}" if v else ""
        fh.write(f"  {user}@{domain}\n")
        fh.write(f"      pwdLastSet: {disp}{tag}\n")
    fh.write("\n" + sep + "\n")
    fh.write("Note: pwdLastSet proves a password was CHANGED, not that the new one is\n")
    fh.write("strong. For weak-password findings, confirm the reset AND that the new\n")
    fh.write("password meets policy (or the account was disabled/removed).\n")
    fh.write(sep + "\n")


def write_csv_accounts(path, accounts, results, run_dt, testing_start_dt):
    show = testing_start_dt is not None
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        header = ["Account", "Username", "Domain", "pwdLastSet"]
        if show:
            header.append("Remediation")
        w.writerow(header)
        for user, domain in accounts:
            rec = results.get(user, {}).get(domain)
            disp = _pwd_cell(rec)
            row = [f"{user}@{domain}", user, domain, disp]
            if show:
                row.append(account_remediation(rec, testing_start_dt, run_dt))
            w.writerow(row)


def write_xlsx_accounts(path, accounts, results, run_dt, testing_start_dt):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    show = testing_start_dt is not None
    COLORS = {"REMEDIATED": ("C6EFCE", "006100"),
              "NOT REMEDIATED": ("FFC7CE", "9C0006"),
              "UNVERIFIED": ("FFCC99", "974706")}
    GRAY = ("D9D9D9", "808080")
    arial = "Arial"
    wb = Workbook(); ws = wb.active; ws.title = "Weak-Password Resets"
    ws["A1"] = "WEAK-PASSWORD RESET VERIFICATION"
    ws["A1"].font = Font(name=arial, bold=True, size=13)
    if show:
        ws["A2"] = (f"Reset window: {testing_start_dt.strftime('%Y-%m-%d')} (assessment "
                    f"start) to {run_dt.strftime('%Y-%m-%d %H:%M UTC')} (now) -- a reset "
                    f"in this window counts as remediated")
        ws["A2"].font = Font(name=arial, italic=True, size=10)
    hr = 4
    headers = ["Account", "Username", "Domain", "pwdLastSet"]
    if show:
        headers.append("Remediation")
    hdr_fill = PatternFill("solid", fgColor="305496")
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c, name in enumerate(headers, start=1):
        cell = ws.cell(row=hr, column=c, value=name)
        cell.font = Font(name=arial, bold=True, color="FFFFFF")
        cell.fill = hdr_fill
        cell.alignment = Alignment(horizontal="left", vertical="center")
        cell.border = border
    r = hr + 1
    for user, domain in accounts:
        rec = results.get(user, {}).get(domain)
        vals = [f"{user}@{domain}", user, domain, _pwd_cell(rec)]
        v = account_remediation(rec, testing_start_dt, run_dt) if show else None
        if show:
            vals.append(v)
        for c, val in enumerate(vals, start=1):
            cell = ws.cell(row=r, column=c, value=_safe(val))
            cell.font = Font(name=arial)
            cell.border = border
        if show:
            rem = ws.cell(row=r, column=len(headers))
            fill, fc = COLORS.get(v, GRAY)
            rem.fill = PatternFill("solid", fgColor=fill)
            rem.font = Font(name=arial, bold=True, color=fc)
        r += 1
    for col, wdt in zip("ABCDE", [34, 22, 24, 30, 16]):
        ws.column_dimensions[col].width = wdt
    ws.freeze_panes = ws.cell(row=hr + 1, column=1)
    ws.auto_filter.ref = f"A{hr}:{chr(64+len(headers))}{max(r-1, hr)}"
    wb.save(path)


def write_report(fh, domain_names, users, results, report_dt,
                 testing_start_dt=None, run_dt=None):
    sep = "=" * 78
    fh.write(sep + "\n")
    fh.write("PRIVILEGED PASSWORD REUSE -- REMEDIATION VERIFICATION\n")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    fh.write(f"Generated: {now}\n")
    if report_dt:
        fh.write(f"Report/finding date (baseline): {report_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    if testing_start_dt and run_dt:
        fh.write(f"Remediation window: {testing_start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                 f"(assessment start)  ->  {run_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} (now)\n")
        fh.write("  (a password is remediated if it was reset at any point during or after the assessment)\n")
    fh.write(f"Domains compared: {', '.join(domain_names)}\n")
    fh.write(sep + "\n\n")

    for u in users:
        recs = results.get(u, {})
        fh.write(f"=== {u} ===\n")
        for d in domain_names:
            r = recs.get(d)
            if r is None:
                fh.write(f"  {d:<30} (not queried)\n")
                continue
            if r.get("error") == "auth_failed":
                fh.write(f"  {d:<30} CANNOT AUTH TO DC (current user has no access)\n")
                continue
            if r.get("error") == "dc_unreachable":
                fh.write(f"  {d:<30} DC UNREACHABLE (network/DNS)\n")
                continue
            if r.get("error"):
                fh.write(f"  {d:<30} QUERY ERROR: {r['error']}\n")
                continue
            dis = ""
            if r.get("disabled") is True:
                dis = "  [DISABLED]"
            elif r.get("disabled") is False:
                dis = "  [enabled]"
            win = domain_reset_in_window(r, testing_start_dt, run_dt)
            win = {"Yes": "  (reset in window)", "No": "  (before window)"}.get(win, "")
            fh.write(f"  {d:<30} pwdLastSet: {r['pwd_disp']}{dis}{win}\n")
        if testing_start_dt is not None:
            v = user_remediation(recs, testing_start_dt, run_dt)
            fh.write(f"  => {v}  ({_rem_explanation(v)})\n")
        fh.write("\n")

    fh.write(sep + "\n")
    fh.write("NOTE: pwdLastSet proves a password was CHANGED, not that it was\n")
    fh.write("changed to a different (non-reused) value. Cryptographic proof of\n")
    fh.write("non-reuse requires hash comparison (NTDS/DCSync) under privilege.\n")
    fh.write(sep + "\n")


def _pwd_cell(r):
    """The pwdLastSet cell, matching what the screen shows (date, Never Set, or
    the failure reason)."""
    if r is None:
        return "(not queried)"
    if r.get("error") == "auth_failed":
        return "CANNOT AUTH TO DC"
    if r.get("error") == "dc_unreachable":
        return "DC UNREACHABLE"
    if r.get("error"):
        return f"QUERY ERROR: {r['error']}"
    return r.get("pwd_disp", "")


def _disabled_cell(r):
    v = (r or {}).get("disabled")
    return "Yes" if v is True else "No" if v is False else "Unknown"


def write_csv(path, domain_names, users, results, report_dt,
              testing_start_dt=None, run_dt=None):
    """CSV grouped by ACCOUNT, mirroring the on-screen layout: each account's
    domain rows together, separated by a blank line, account name first."""
    show_rem = testing_start_dt is not None

    header = ["sAMAccountName", "Domain", "pwdLastSet", "AccountDisabled"]
    if show_rem:
        header += ["ResetInWindow", "Remediation"]   # per-domain, then per-account verdict

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for i, u in enumerate(users):
            if i > 0:
                w.writerow([])                       # blank line between accounts
            recs = results.get(u, {})
            verdict = user_remediation(recs, testing_start_dt, run_dt) if show_rem else None
            for d in domain_names:
                r = recs.get(d)
                row = [u, d, _pwd_cell(r), _disabled_cell(r)]
                if show_rem:
                    riw = domain_reset_in_window(r, testing_start_dt, run_dt) if r else "Unverified"
                    row += [riw, verdict]
                w.writerow(row)


def write_xlsx(path, domain_names, users, results, testing_start_dt, run_dt):
    """Colored Excel report: one row per account-per-domain, grouped by domain,
    with the Remediation cell filled green/red/orange so it pops for the client."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    show_rem = testing_start_dt is not None

    # Excel-style status colors (fill, font)
    COLORS = {
        "REMEDIATED":     ("C6EFCE", "006100"),   # green
        "NOT REMEDIATED": ("FFC7CE", "9C0006"),   # red
        "UNVERIFIED":     ("FFCC99", "974706"),   # orange
    }
    GRAY = ("D9D9D9", "808080")                    # N/A, unknown

    wb = Workbook()
    ws = wb.active
    ws.title = "Remediation"
    arial = "Arial"

    ws["A1"] = "PRIVILEGED PASSWORD REUSE -- REMEDIATION VERIFICATION"
    ws["A1"].font = Font(name=arial, bold=True, size=13)
    if show_rem:
        ws["A2"] = (f"Remediation window: {testing_start_dt.strftime('%Y-%m-%d')} "
                    f"(assessment start) to {run_dt.strftime('%Y-%m-%d %H:%M UTC')} "
                    f"(now) -- a reset anytime in this window counts as remediated")
        ws["A2"].font = Font(name=arial, italic=True, size=10)

    header_row = 4
    # Grouped by account, mirroring the screen: account name first.
    headers = ["sAMAccountName", "Domain", "pwdLastSet", "AccountDisabled"]
    if show_rem:
        headers += ["ResetInWindow", "Remediation"]
    hdr_fill = PatternFill("solid", fgColor="305496")
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c, name in enumerate(headers, start=1):
        cell = ws.cell(row=header_row, column=c, value=name)
        cell.font = Font(name=arial, bold=True, color="FFFFFF")
        cell.fill = hdr_fill
        cell.alignment = Alignment(horizontal="left", vertical="center")
        cell.border = border

    r_i = header_row + 1
    for ui, u in enumerate(users):
        if ui > 0:
            r_i += 1                                   # blank separator row
        recs = results.get(u, {})
        verdict = user_remediation(recs, testing_start_dt, run_dt) if show_rem else None
        first = True
        for d in domain_names:
            r = recs.get(d)
            vals = [u if first else "", d, _pwd_cell(r), _disabled_cell(r)]
            if show_rem:
                riw = domain_reset_in_window(r, testing_start_dt, run_dt) if r else "Unverified"
                vals += [riw, verdict]
            for c, v in enumerate(vals, start=1):
                cell = ws.cell(row=r_i, column=c, value=v)
                cell.font = Font(name=arial, bold=(c == 1))   # bold the account name
                cell.border = border
            if show_rem:
                rem_cell = ws.cell(row=r_i, column=len(headers))
                fill, fontcolor = COLORS.get(verdict, GRAY)
                rem_cell.fill = PatternFill("solid", fgColor=fill)
                rem_cell.font = Font(name=arial, bold=True, color=fontcolor)
            first = False
            r_i += 1

    widths = [24, 26, 34, 15, 14, 16]
    for i, w in enumerate(widths[:len(headers)], start=1):
        ws.column_dimensions[chr(64 + i)].width = w
    ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    wb.save(path)


def parse_mdy(s):
    """Parse a month/day/year date string -> timezone-aware UTC datetime.
    Accepts MM/DD/YYYY (and 2-digit year). Raises ValueError otherwise."""
    s = (s or "").strip()
    for fmt in ("%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    raise ValueError("expected MM/DD/YYYY")


def read_lines(path):
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def parse_domains(lines):
    """Each line: domain[,dc]. Returns list of (domain_fqdn, target)."""
    out = []
    for ln in lines:
        if "," in ln:
            dom, target = (p.strip() for p in ln.split(",", 1))
        else:
            dom, target = ln, ln  # use the FQDN as the netexec target
        out.append((dom, target))
    return out


# ------------------------- forest auto-discovery ---------------------------

def pick_srv_target(records):
    """Given SRV records (objects with .priority/.weight/.target), return the
    best target hostname (lowest priority, then highest weight). Pure helper
    so it can be unit-tested without DNS."""
    if not records:
        return None
    best = sorted(records, key=lambda r: (r.priority, -r.weight))[0]
    return str(best.target).rstrip(".")


def resolve_dc(domain, dns_server=None, timeout=5):
    """Find a DC for a domain via DNS SRV records. Returns a hostname or None."""
    res = _dnsresolver.Resolver(configure=(dns_server is None))
    if dns_server:
        res.nameservers = [dns_server]
    res.lifetime = res.timeout = timeout
    for q in (f"_ldap._tcp.dc._msdcs.{domain}", f"_ldap._tcp.{domain}"):
        try:
            ans = res.resolve(q, "SRV")
            target = pick_srv_target(list(ans))
            if target:
                return target
        except Exception:
            continue
    return None


def resolve_ip(host, dns_server=None, timeout=5):
    """Best-effort resolve a hostname to an IP for display. Returns host
    unchanged if it is already an IP, or None if unresolved / no dnspython."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return host  # already an IP
    except ValueError:
        pass
    if HAVE_DNS:
        res = _dnsresolver.Resolver(configure=(dns_server is None))
        if dns_server:
            res.nameservers = [dns_server]
        res.lifetime = res.timeout = timeout
        for rtype in ("A", "AAAA"):
            try:
                ans = res.resolve(host, rtype)
                return str(list(ans)[0])
            except Exception:
                continue
    return resolve_ip_nslookup(host, dns_server, timeout)


# --- nslookup fallbacks (no python deps; uses the system resolver tool) -----

def _run_nslookup(args, timeout):
    try:
        p = subprocess.run(["nslookup"] + args, capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def resolve_dc_nslookup(domain, dns_server=None, timeout=5):
    """Find a DC hostname via `nslookup -type=SRV`. Returns hostname or None."""
    for srv in (f"_ldap._tcp.dc._msdcs.{domain}", f"_ldap._tcp.{domain}"):
        args = ["-type=SRV", srv] + ([dns_server] if dns_server else [])
        out = _run_nslookup(args, timeout)
        hosts = []
        for line in out.splitlines():
            # Linux: "... service = 0 100 389 dc01.domain.local."
            # Windows: "... SRV service location:" then "svr hostname = dc01..."
            if "service =" in line or "hostname" in line.lower():
                tok = line.strip().split()[-1].rstrip(".")
                if tok and not tok.replace(".", "").isdigit():
                    hosts.append(tok)
        if hosts:
            return hosts[0]
    return None


def resolve_ip_nslookup(host, dns_server=None, timeout=5):
    """Resolve a hostname to an IP via nslookup. Returns IP or None."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    args = [host] + ([dns_server] if dns_server else [])
    out = _run_nslookup(args, timeout)
    addrs = []
    seen_name = False
    for line in out.splitlines():
        if line.strip().startswith("Name:"):
            seen_name = True
            continue
        if "Address:" in line and "#" not in line:
            ip = line.split("Address:")[-1].strip()
            if seen_name and ip:
                addrs.append(ip)
    return addrs[0] if addrs else None


def find_dc(domain, dns_server=None):
    """Resolve a DC for a domain via SRV (dnspython if present, else nslookup),
    then return its IP if resolvable, otherwise the hostname. None on failure."""
    host = resolve_dc(domain, dns_server) if HAVE_DNS else None
    if not host:
        host = resolve_dc_nslookup(domain, dns_server)
    if not host:
        return None
    return resolve_ip(host, dns_server) or host


def resolve_all_dcs_dnspython(domain, dns_server=None, timeout=5):
    """All DC hostnames for a domain from SRV, best-first (dnspython)."""
    res = _dnsresolver.Resolver(configure=(dns_server is None))
    if dns_server:
        res.nameservers = [dns_server]
    res.lifetime = res.timeout = timeout
    out = []
    # Query BOTH service records and merge -- some environments register a
    # different set of DCs under each, so stopping at the first undercounts.
    for q in (f"_ldap._tcp.dc._msdcs.{domain}", f"_ldap._tcp.{domain}"):
        try:
            ans = res.resolve(q, "SRV")
            for r in sorted(ans, key=lambda r: (r.priority, -r.weight)):
                t = str(r.target).rstrip(".")
                if t and t not in out:
                    out.append(t)
        except Exception:
            continue
    return out


def resolve_all_dcs_nslookup(domain, dns_server=None, timeout=5):
    """All DC hostnames for a domain from SRV via nslookup (no python deps)."""
    out = []
    for srv in (f"_ldap._tcp.dc._msdcs.{domain}", f"_ldap._tcp.{domain}"):
        args = ["-type=SRV", srv] + ([dns_server] if dns_server else [])
        text = _run_nslookup(args, timeout)
        for line in text.splitlines():
            if "service =" in line or "hostname" in line.lower():
                tok = line.strip().split()[-1].rstrip(".")
                if tok and not tok.replace(".", "").isdigit() and tok not in out:
                    out.append(tok)
    return out


def find_all_dc_ips(domain, dns_server=None):
    """Every DC for a domain, as IPs (resolving each SRV target's A record),
    best-first and de-duplicated. Falls back to the hostname if A-resolution
    fails. Returns [] if SRV found nothing."""
    hosts = resolve_all_dcs_dnspython(domain, dns_server) if HAVE_DNS else []
    if not hosts:
        hosts = resolve_all_dcs_nslookup(domain, dns_server)
    ips = []
    for h in hosts:
        ip = resolve_ip(h, dns_server) or h
        if ip not in ips:
            ips.append(ip)
    return ips


def build_candidates(domains, dns_server):
    """Turn [(domain, target)] into [(domain, [candidate DCs])].
    Bare domain lines expand to EVERY DC IP found via SRV; explicit ',<dc>'
    lines keep just that one."""
    out = []
    for dom, target in domains:
        if target == dom:   # bare domain -> enumerate all its DCs via SRV
            cands = find_all_dc_ips(dom, dns_server) or [dom]
            print(f"[*] {dom}: {len(cands)} candidate DC(s) via SRV -> "
                  f"{', '.join(cands)}", file=sys.stderr)
        else:               # explicit DC(s): 'domain,dc1,dc2,dc3' -> all of them
            cands = [t.strip() for t in target.split(",") if t.strip()]
        out.append((dom, cands))
    return out


def smoke_and_select(domain_candidates, creds, nxc_bin, timeout, proto="smb",
                     home_domain=None):
    """Pre-flight that figures out HOW to authenticate to each domain's DC, the
    way a working credential does, instead of blindly forcing the domains.txt
    name as the auth realm.

    For each DC it tries several auth 'realms' in order and keeps the first that
    binds:
      1. the domain name from the file (-d <name>)
      2. the home domain, if known (-d <home>)  -- the trust path for a foreign DC
      3. NO -d at all  -- netexec discovers the DC's real domain (fixes the case
         where the file's name doesn't match the DC's actual domain, e.g.
         short.example.com in the file but fullname.example.net on the DC)
    A stored credential id (creds['cred_id']) makes auth a single attempt that
    netexec resolves itself -- exactly like `nxc smb ... -id N`.

    Returns ([(domain, chosen_dc)], status, auth_map). auth_map[domain] = the realm
    that worked (a domain string, or None to omit -d)."""
    smoke_timeout = min(timeout, 20)
    using_id = bool(creds.get("cred_id"))
    ORDER = {"unreachable": 0, "auth_failed": 1, "unknown": 2}

    def test(dc, realm):
        return smoke_check_domain(dc, realm, creds, nxc_bin, smoke_timeout, proto)

    # ---- Stored credential (--id): netexec resolves the domain itself; one try ----
    if using_id:
        print("[*] Pre-flight: testing each domain's DC with the stored credential "
              "(--id) ...", file=sys.stderr)
        domains_out, status, auth_map = [], {}, {}
        for dom, cands in domain_candidates:
            chosen, result = (cands[0] if cands else dom), "unreachable"
            for dc in cands:
                st = test(dc, None)
                if st == "ok":
                    chosen, result = dc, "ok"
                    break
                if ORDER.get(st, 0) > ORDER.get(result, 0):
                    chosen, result = dc, st
            print(f"      {dom:<28} {chosen:<16} {_STATUS_LABEL.get(result, result)}",
                  file=sys.stderr)
            domains_out.append((dom, chosen))
            status[dom] = result
            auth_map[dom] = None
        return domains_out, status, auth_map, home_domain

    # ---- Password / hash ----
    # Phase 1: test each domain in ITS OWN context (-d <name>, then no -d). A domain
    # that authenticates this way is one the account is NATIVE to -> a home candidate.
    print("[*] Pre-flight phase 1: testing each domain in its own context ...",
          file=sys.stderr)
    prelim = {}
    for dom, cands in domain_candidates:
        chosen = cands[0] if cands else dom
        best = ("unreachable", None)          # (status, winning_realm)
        for dc in cands:
            reached = saw_unknown = False
            won = ("miss", None)
            for realm in (dom, None):         # own name, then DC-discovered
                st = test(dc, realm)
                if st == "ok":
                    won = ("ok", realm)
                    break
                if st in ("auth_failed", "unknown"):
                    reached = True
                if st == "unknown":
                    saw_unknown = True
            if won[0] == "ok":
                chosen, best = dc, won
                break
            s = "unknown" if saw_unknown else ("auth_failed" if reached else "unreachable")
            if ORDER[s] > ORDER[best[0]]:
                chosen, best = dc, (s, None)
        prelim[dom] = (chosen, best[0], best[1])
        note = ("  (realm: " + (best[1] if best[1] else "auto/DC-discovered") + ")"
                if best[0] == "ok" else "")
        print(f"      {dom:<28} {chosen:<16} {_STATUS_LABEL.get(best[0], best[0])}{note}",
              file=sys.stderr)

    # Home domain: explicit override, else the first domain the account authed to in
    # its own context (that is where the account lives).
    if not home_domain:
        for dom, _ in domain_candidates:
            if prelim[dom][1] == "ok":
                home_domain = dom
                break
        if home_domain:
            print(f"[*] Home domain: {home_domain} (account authenticates here; using "
                  f"it to reach the other domains over their trust)", file=sys.stderr)
        else:
            print("[*] Could not auto-detect a home domain (no listed domain "
                  "authenticated). Use --id, or --auth-domain if your account's domain "
                  "isn't in the list.", file=sys.stderr)

    # Phase 2: for domains that were reached but rejected in their own context, retry
    # with the HOME domain as -d -- the trust path a foreign account uses.
    domains_out, status, auth_map = [], {}, {}
    for dom, _ in domain_candidates:
        chosen, st, realm = prelim[dom]
        if st in ("auth_failed", "unknown") and home_domain and home_domain != dom:
            st2 = test(chosen, home_domain)
            if st2 == "ok":
                st, realm = "ok", home_domain
                print(f"[*] {dom}: authenticated via home domain '{home_domain}' "
                      f"(trust path)", file=sys.stderr)
            else:
                print(f"[*] {dom}: still cannot auth, even via '{home_domain}' "
                      f"({_STATUS_LABEL.get(st2, st2)})", file=sys.stderr)
        domains_out.append((dom, chosen))
        status[dom] = st
        auth_map[dom] = realm
    return domains_out, status, auth_map, home_domain


def resolve_missing_dcs(domains, dns_server):
    """For each (domain, target) where no explicit DC was given (target==domain),
    SRV-resolve a DC. Returns an updated [(domain, dc)] list."""
    out = []
    for dom, target in domains:
        if target == dom:  # bare domain line -> resolve its DC
            dc = find_dc(dom, dns_server)
            if dc:
                print(f"[*] Resolved DC for {dom}: {dc}", file=sys.stderr)
                out.append((dom, dc))
            else:
                print(f"[!] {dom}: no DC found via SRV; using domain name as target "
                      f"(set --dns-server to a DC IP, or add ',<dc>' in the file)",
                      file=sys.stderr)
                out.append((dom, dom))
        else:
            out.append((dom, target))
    return out


def print_precheck(domains, n_users, dns_server, domain_status=None):
    """Print the domain -> DC list (and, if available, the pre-flight auth status)
    to stderr, so the final report on stdout stays clean."""
    print("\n[*] Pre-check -- domains, resolved DC, and auth status:\n",
          file=sys.stderr)
    for dom, target in domains:
        ip = resolve_ip(target, dns_server)
        disp = f"{target} ({ip})" if ip and ip != target else target
        st = ""
        if domain_status is not None:
            st = "  " + _STATUS_LABEL.get(domain_status.get(dom), "")
        print(f"      {dom:<30} {disp:<26}{st}", file=sys.stderr)
    # count only the domains we will actually query
    if domain_status is not None:
        queryable = [d for d, _ in domains
                     if domain_status.get(d) not in ("auth_failed", "unreachable", "error")]
        nq = n_users * len(queryable)
        print(f"\n[*] Users: {n_users}   Queryable domains: {len(queryable)}/"
              f"{len(domains)}   Queries: {nq}\n", file=sys.stderr)
    else:
        print(f"\n[*] Users: {n_users}   Domains: {len(domains)}   "
              f"Queries: {n_users * len(domains)}\n", file=sys.stderr)


def smoke_check_domain(target, realm, creds, nxc_bin, timeout, proto="smb"):
    """One lightweight auth check against a DC. `realm` is the -d value, or None
    to omit -d so netexec discovers the DC's real domain. Defaults to SMB (the
    reliable credential test; an LDAP bind can false-fail on signing). Returns
    'ok' | 'auth_failed' | 'unreachable' | 'unknown' | 'error'."""
    cmd = [nxc_bin, proto, target] + _nxc_creds_args(creds, realm)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "unreachable"
    except FileNotFoundError:
        return "error"
    return detect_auth_status(out)


def run_smoke_checks(domains, creds, nxc_bin, timeout):
    """Bind-test every domain's DC once. Returns {domain: status}. Uses a short
    timeout so an unreachable DC fails fast instead of per-user."""
    smoke_timeout = min(timeout, 20)
    print("[*] Pre-flight: testing auth/reachability of each DC ...", file=sys.stderr)
    status = {}
    for dom, target in domains:
        status[dom] = smoke_check_domain(target, dom, creds, nxc_bin, smoke_timeout)
    return status


_STATUS_LABEL = {
    "ok": "[AUTH OK]",
    "auth_failed": "[CANNOT AUTH]",
    "unreachable": "[DC UNREACHABLE]",
    "unknown": "[reachable, bind unconfirmed]",
    "error": "[ERROR]",
}


def confirm_or_exit(assume_yes):
    """Ask the operator to confirm before querying. Auto-proceeds when -y is
    given or stdin is not a TTY (scripted runs)."""
    if assume_yes:
        print("[*] --yes given; proceeding without prompt.", file=sys.stderr)
        return
    if not sys.stdin.isatty():
        print("[*] Non-interactive stdin; proceeding.", file=sys.stderr)
        return
    ans = input("Proceed with queries? [y/N] ").strip().lower()
    if ans not in ("y", "yes"):
        print("[!] Aborted by operator.", file=sys.stderr)
        sys.exit(0)


def parse_crossrefs(entries):
    """From ldap3 crossRef entries, return the list of domain dnsRoot values.
    Pure helper (entries are dicts {attr: value}) for unit-testing."""
    domains = []
    for e in entries:
        dr = e.get("dnsRoot")
        nb = e.get("nETBIOSName")
        # real AD domains have a NetBIOS name; app partitions don't
        if dr and nb:
            domains.append(dr)
    return domains


def discover_via_ldap(dc, bind_domain, creds, timeout=10, debug=False):
    """Bind once to a DC and return (forest_domains, trusts).

    forest_domains: every domain in THIS forest (from the Partitions container).
    trusts:         trustPartner names from trustedDomain objects -- these may be
                    other forests, reachable only with their own credentials.
    """
    user = creds["username"]
    if user and "\\" not in user and "@" not in user and bind_domain:
        user = f"{bind_domain}\\{user}"
    password = creds["nthash"] if creds["nthash"] else creds["password"]

    server = _ldap3.Server(dc, get_info=_ldap3.ALL, connect_timeout=timeout)
    conn = _ldap3.Connection(server, user=user, password=password,
                             authentication=_ldap3.NTLM, auto_bind=True)
    if debug:
        print(f"[debug] bound to {dc} as {user}", file=sys.stderr)
        print(f"[debug] bind result: {conn.result}", file=sys.stderr)

    config_nc = default_nc = None
    if server.info:
        config_nc = (server.info.other.get("configurationNamingContext") or [None])[0]
        default_nc = (server.info.other.get("defaultNamingContext") or [None])[0]
    if not config_nc:
        conn.search("", "(objectClass=*)", search_scope=_ldap3.BASE,
                    attributes=["configurationNamingContext", "defaultNamingContext"])
        config_nc = conn.entries[0]["configurationNamingContext"].value
        default_nc = conn.entries[0]["defaultNamingContext"].value
    if debug:
        print(f"[debug] configurationNamingContext = {config_nc}", file=sys.stderr)
        print(f"[debug] defaultNamingContext       = {default_nc}", file=sys.stderr)

    # --- forest domains, from Partitions ---
    conn.search(f"CN=Partitions,{config_nc}",
                "(&(objectClass=crossRef)(nETBIOSName=*))",
                attributes=["dnsRoot", "nETBIOSName"])
    cross = [{"dnsRoot": e["dnsRoot"].value, "nETBIOSName": e["nETBIOSName"].value}
             for e in conn.entries]
    if debug:
        print(f"[debug] Partitions returned {len(cross)} crossRef(s):", file=sys.stderr)
        for c in cross:
            print(f"[debug]    {c['nETBIOSName']!r:16} {c['dnsRoot']!r}", file=sys.stderr)
    forest_domains = parse_crossrefs(cross)

    # --- trusts, from trustedDomain objects (may be separate forests) ---
    trusts = []
    if default_nc:
        try:
            conn.search(default_nc, "(objectClass=trustedDomain)",
                        attributes=["trustPartner", "trustDirection", "trustAttributes"])
            for e in conn.entries:
                tp = e["trustPartner"].value
                if tp:
                    trusts.append(tp)
            if debug:
                print(f"[debug] trustedDomain objects: {trusts or 'none'}", file=sys.stderr)
        except Exception as e:
            if debug:
                print(f"[debug] trust enumeration failed: {e}", file=sys.stderr)

    conn.unbind()
    return forest_domains, trusts


def discover_forest(start_domain, creds, dns_server=None, debug=False,
                    include_trusts=False):
    """One domain + creds -> ([(domain, dc), ...], trusts)."""
    if not (HAVE_DNS and HAVE_LDAP3):
        raise RuntimeError("forest discovery needs dnspython and ldap3: "
                           "pip install dnspython ldap3")
    print(f"[*] Resolving a DC for {start_domain} via DNS SRV ...", file=sys.stderr)
    dc = resolve_dc(start_domain, dns_server)
    if not dc:
        raise RuntimeError(f"could not resolve a DC for {start_domain} "
                           "(try --dns-server <DC-IP>)")
    print(f"[*] Using {dc}; reading forest Partitions + trusts ...", file=sys.stderr)
    forest_domains, trusts = discover_via_ldap(dc, start_domain, creds, debug=debug)
    if not forest_domains:
        raise RuntimeError("bound OK but found no domains in the Partitions container")

    names = list(dict.fromkeys(forest_domains))  # de-dupe, keep order
    if include_trusts:
        for t in trusts:
            if t not in names:
                names.append(t)

    out = []
    for d in sorted(set(names)):
        ddc = resolve_dc(d, dns_server) or d
        out.append((d, ddc))
        print(f"[*]   {d} -> {ddc}", file=sys.stderr)

    # Surface trusts we did NOT include, so the operator knows they exist.
    if trusts and not include_trusts:
        extra = [t for t in trusts if t not in set(forest_domains)]
        if extra:
            print(f"[*] Note: {len(extra)} trusted domain(s) found but NOT included "
                  f"(likely separate forests needing their own creds): "
                  f"{', '.join(extra)}", file=sys.stderr)
            print("[*]   Re-run with --include-trusts to add them.", file=sys.stderr)
    return out, trusts


def main(mode="reuse"):
    """Shared entry point. mode='reuse' is the cross-domain password-reuse checker;
    mode='weak' is the per-account (username@domain) weak-password checker. Each
    tool is a thin wrapper that calls this with its mode."""
    weak = (mode == "weak")
    if weak:
        prog, default_out = "weak_password_checker.py", "weak_password_report"
        desc = ("Verify that specific accounts (e.g. ones found with weak passwords) "
                "were reset.\nTypical run:\n"
                "  weak_password_checker.py --accounts accounts.txt -U user -P pass "
                "--testing-start 05/12/2026 -o Results")
    else:
        prog, default_out = "password_reuse_checker.py", "password_reuse_report"
        desc = ("Verify remediation of cross-domain privileged password reuse.\n"
                "Typical run:\n"
                "  password_reuse_checker.py -u users.txt -d domains.txt -U user -P pass "
                "--testing-start 05/12/2026 -o Results")
    ap = argparse.ArgumentParser(prog=prog, description=desc,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

    # ---- inputs (mode-specific) ----
    if weak:
        ap.add_argument("--accounts", required=True, metavar="FILE",
                        help="file of 'username@domain', one per line -- the accounts to "
                             "check (each in its own domain)")
        ap.add_argument("-d", "--domains", metavar="FILE",
                        help="optional: pin a DC per domain ('domain,dc' lines); domains "
                             "otherwise come from the accounts list")
    else:
        ap.add_argument("-u", "--users", help="file of sAMAccountNames, one per line")
        ap.add_argument("-d", "--domains",
                        help="file of domains, one per line ('domain' or 'domain,dc')")
    ap.add_argument("-U", "--username", default="", help="account username")
    ap.add_argument("-P", "--password", default="", help="account password")
    ap.add_argument("--testing-start", metavar="MM/DD/YYYY",
                    help="date the client's assessment STARTED. Marks each account "
                         "REMEDIATED if its password was reset at any point from then to "
                         "now (catches mid-assessment resets); otherwise NOT REMEDIATED. "
                         "Prompts if omitted (blank = skip).")
    ap.add_argument("-o", "--out", default=default_out, metavar="NAME",
                    help="output base name; writes NAME.txt, NAME.csv and NAME.xlsx")

    # ---- auth & reading (smart defaults; touch only if needed) ----
    g = ap.add_argument_group("auth & reading (optional)")
    g.add_argument("--id", dest="cred_id", default="",
                   help="use a stored netexec credential id instead of -U/-P (exactly "
                        "like 'nxc smb ... --id N'; netexec resolves the domain itself)")
    g.add_argument("-H", "--hashes", dest="nthash", default="",
                   help="NT hash (LM:NT or NT) for pass-the-hash instead of -P")
    g.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos")
    g.add_argument("--auth-domain", metavar="DOMAIN",
                   help="your account's home domain (auto-detected by default; set this "
                        "only if your domain isn't among the targets)")
    g.add_argument("--via", choices=["smb", "ldap"], default="smb",
                   help="how to read pwdLastSet (default smb: works when LDAP signing "
                        "blocks LDAP; ldap gives exact UTC + disabled status)")
    g.add_argument("--no-fallback", dest="fallback", action="store_false",
                   help="don't retry the other protocol when one returns nothing")
    ap.set_defaults(fallback=True)

    # ---- advanced (rarely needed) ----
    a = ap.add_argument_group("advanced (optional)")
    if not weak:
        a.add_argument("--forest", metavar="DOMAIN",
                       help="auto-discover every domain in a forest from one domain name "
                            "(needs: pip install dnspython ldap3); replaces -d")
        a.add_argument("--include-trusts", action="store_true",
                       help="with --forest, also include trusted (other-forest) domains")
        a.add_argument("--parse", action="append", metavar="DOMAIN=FILE",
                       help="OFFLINE: analyze an already-collected ldap_results file per "
                            "domain instead of querying (repeat per domain). No creds needed.")
        a.add_argument("--report-date", metavar="YYYY-MM-DD",
                       help="baseline date printed in the report header")
    a.add_argument("--dns-server", metavar="IP",
                   help="DNS server for SRV lookups (a DC IP on the client network)")
    a.add_argument("--smoke-proto", choices=["smb", "ldap"], default="smb",
                   help="protocol for the pre-flight auth check")
    a.add_argument("--skip-smoke", action="store_true",
                   help="skip the pre-flight auth check (query every domain regardless)")
    a.add_argument("-y", "--yes", action="store_true",
                   help="skip the confirmation prompt (for scripted runs)")
    a.add_argument("--csv", help="override the CSV output path")
    a.add_argument("--xlsx", help="override the Excel output path")
    a.add_argument("--raw", help="save raw netexec output for auditing")
    a.add_argument("--nxc-bin", default="netexec", help="netexec binary name")
    a.add_argument("--timeout", type=int, default=60, help="per-query timeout (seconds)")
    a.add_argument("--threads", type=int, default=8,
                   help="how many domains to query in parallel (default 8)")
    a.add_argument("--debug", action="store_true", help="verbose discovery output")
    args = ap.parse_args()

    # Flags that exist only in one mode -- default them so the shared code below works.
    if weak:
        args.users = None
        args.forest = None
        args.include_trusts = False
        args.parse = None
        args.report_date = None
    else:
        args.accounts = None

    # Derive the three output paths from the single -o base name.
    import os
    base_root, base_ext = os.path.splitext(args.out)
    root = base_root if base_ext.lower() in (".txt", ".csv", ".xlsx") else args.out
    report_path = root + ".txt"
    csv_path = args.csv or (root + ".csv")
    xlsx_path = args.xlsx or (root + ".xlsx")

    # --- shared: parse the optional baseline date ---
    report_dt = None
    if args.report_date:
        try:
            report_dt = datetime.datetime.strptime(args.report_date, "%Y-%m-%d") \
                .replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            print("[!] --report-date must be YYYY-MM-DD", file=sys.stderr)
            sys.exit(1)

    # --- remediation window: [testing-start, now] ---
    run_dt = datetime.datetime.now(datetime.timezone.utc)
    testing_start_dt = None
    if args.testing_start:                       # from flag
        try:
            testing_start_dt = parse_mdy(args.testing_start)
        except ValueError:
            print("[!] --testing-start must be MM/DD/YYYY (e.g. 05/12/2026)", file=sys.stderr)
            sys.exit(1)
    elif sys.stdin.isatty():                   # otherwise prompt (interactive only)
        while True:
            ans = input("Date the client's assessment STARTED "
                        "(MM/DD/YYYY), blank to skip: ").strip()
            if not ans:
                break
            try:
                testing_start_dt = parse_mdy(ans)
                break
            except ValueError:
                print("    please use MM/DD/YYYY, e.g. 09/01/2026", file=sys.stderr)
    # (non-interactive with no flag -> remediation marking stays off)

    if testing_start_dt and testing_start_dt > run_dt:
        print("[!] testing-start is in the future; the remediation window would be empty.",
              file=sys.stderr)
        sys.exit(1)

    # weak-password mode is set in the live branch; default off for other modes.
    weak_mode = False
    accounts = None

    # optional user filter/ordering (used by both modes)
    users_filter = None
    if args.users:
        try:
            users_filter = read_lines(args.users)
        except OSError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    # =================== OFFLINE MODE (--parse) ===================
    if args.parse:
        parse_specs = []
        for spec in args.parse:
            if "=" not in spec:
                print(f"[!] --parse expects DOMAIN=FILE, got: {spec}", file=sys.stderr)
                sys.exit(1)
            dom, path = spec.split("=", 1)
            parse_specs.append((dom.strip(), path.strip()))
        try:
            results, domain_names, users = load_offline(parse_specs, users_filter)
        except OSError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
        if not users:
            print("[!] no users found in the parsed files (and no -u given).", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Offline: {len(users)} users across {len(domain_names)} domains "
              f"(no queries run)\n", file=sys.stderr)

    # =================== LIVE MODE (netexec) ===================
    else:
        creds = {"username": args.username, "password": args.password,
                 "nthash": args.nthash, "kerberos": args.kerberos,
                 "cred_id": args.cred_id}

        weak_mode = weak
        domain_users = None
        accounts = None

        # domains: weak-password 'username@domain' list, --forest, or read from -d
        if weak_mode:
            try:
                accounts, domain_users = read_accounts(args.accounts)
            except OSError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)
            if not accounts:
                print("[!] no valid username@domain entries in the accounts file.",
                      file=sys.stderr)
                sys.exit(1)
            users = sorted({u for u, _d in accounts})
            # DC pins from -d (optional); domains come from the account list
            dc_pins = {}
            if args.domains:
                for dom, dc in parse_domains(read_lines(args.domains)):
                    dc_pins[dom] = dc
            upn_domains, seen = [], set()
            for _u, d in accounts:
                if d not in seen:
                    seen.add(d)
                    upn_domains.append(d)
            domains = [(d, dc_pins.get(d, d)) for d in upn_domains]
            print(f"[*] Weak-password mode: {len(accounts)} account(s) across "
                  f"{len(domains)} domain(s)", file=sys.stderr)
        elif args.forest:
            try:
                domains, _trusts = discover_forest(
                    args.forest, creds, args.dns_server,
                    debug=args.debug, include_trusts=args.include_trusts)
            except Exception as e:
                print(f"[!] forest discovery failed: {e}", file=sys.stderr)
                sys.exit(1)
            users_path = args.users or input("Path to shared-password users file: ").strip()
            try:
                users = users_filter if users_filter else read_lines(users_path)
            except OSError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)
        else:
            users_path = args.users or input("Path to shared-password users file: ").strip()
            domains_path = args.domains or input("Path to domains list file: ").strip()
            try:
                users = users_filter if users_filter else read_lines(users_path)
                domains = parse_domains(read_lines(domains_path))
            except OSError as e:
                print(f"[!] {e}", file=sys.stderr)
                sys.exit(1)
        if not users or not domains:
            print("[!] no accounts/domains to query.", file=sys.stderr)
            sys.exit(1)

        nxc_bin = args.nxc_bin
        if shutil.which(nxc_bin) is None:
            alt = "nxc" if nxc_bin == "netexec" else "netexec"
            if shutil.which(alt):
                nxc_bin = alt
                print(f"[*] '{args.nxc_bin}' not found; using '{alt}'.", file=sys.stderr)

        # Home/auth domain: explicit flag, else derive from the username form.
        home_domain = args.auth_domain
        if not home_domain and args.username:
            if "\\" in args.username:
                home_domain = args.username.split("\\", 1)[0]
            elif "@" in args.username:
                home_domain = args.username.split("@", 1)[1]
        if home_domain:
            print(f"[*] Home/auth domain for trust fallback: {home_domain}", file=sys.stderr)

        # Enumerate candidate DCs per domain (bare domains expand to EVERY SRV DC),
        # then pre-flight: pick the first DC per domain we can actually auth to.
        domain_status = None
        domain_auth = None
        if not args.skip_smoke:
            candidates = build_candidates(domains, args.dns_server)
            domains, domain_status, domain_auth, home_domain = smoke_and_select(
                candidates, creds, nxc_bin, args.timeout, args.smoke_proto, home_domain)
        else:
            # no smoke: still resolve a single DC for bare domains (old behaviour)
            if any(dom == target for dom, target in domains):
                domains = resolve_missing_dcs(domains, args.dns_server)

        domain_names = [d[0] for d in domains]

        # Pre-check: show domains, chosen DC, and auth status, then confirm.
        print_precheck(domains, len(users), args.dns_server, domain_status)

        if domain_status is not None:
            unreachable = {d for d, s in domain_status.items()
                           if s in ("unreachable", "error")}
            if len(unreachable) == len(domains):
                print("[!] Every domain's DC(s) are unreachable. Nothing to query "
                      "-- aborting. (Check --dns-server / routing.)", file=sys.stderr)
                sys.exit(1)
            if unreachable:
                print(f"[*] {len(unreachable)} domain(s) unreachable, will be skipped: "
                      f"{', '.join(unreachable)}", file=sys.stderr)
            authfail = {d for d, s in domain_status.items() if s == "auth_failed"}
            if authfail:
                print(f"[*] {len(authfail)} domain(s) failed the auth pre-check but "
                      f"will still be queried (result decides): {', '.join(authfail)}",
                      file=sys.stderr)

        confirm_or_exit(args.yes)

        raw_fh = open(args.raw, "w") if args.raw else None
        try:
            results = collect(users, domains, creds, nxc_bin, args.timeout, raw_fh,
                              domain_status, args.via, args.fallback, domain_auth,
                              home_domain, args.threads, domain_users)
        finally:
            if raw_fh:
                raw_fh.close()

    # =================== shared: write outputs ===================
    if weak_mode:
        with open(report_path, "w") as fh:
            write_report_accounts(fh, accounts, results, run_dt, testing_start_dt)
        with open(report_path) as fh:
            sys.stdout.write(fh.read())
        write_csv_accounts(csv_path, accounts, results, run_dt, testing_start_dt)
        xlsx_written = False
        try:
            write_xlsx_accounts(xlsx_path, accounts, results, run_dt, testing_start_dt)
            xlsx_written = True
        except ImportError:
            print("[!] Excel output needs openpyxl (pip install openpyxl); skipped.",
                  file=sys.stderr)
        print(f"\n[*] Wrote: {report_path}, {csv_path}"
              + (f", {xlsx_path}" if xlsx_written else ""), file=sys.stderr)
        return

    with open(report_path, "w") as fh:
        write_report(fh, domain_names, users, results, report_dt,
                     testing_start_dt, run_dt)
    with open(report_path) as fh:
        sys.stdout.write(fh.read())

    write_csv(csv_path, domain_names, users, results, report_dt,
              testing_start_dt, run_dt)

    xlsx_written = False
    try:
        write_xlsx(xlsx_path, domain_names, users, results, testing_start_dt, run_dt)
        xlsx_written = True
    except ImportError:
        print("[!] Excel output needs openpyxl (pip install openpyxl); skipped.",
              file=sys.stderr)

    print(f"\n[*] Wrote: {report_path}, {csv_path}"
          + (f", {xlsx_path}" if xlsx_written else ""), file=sys.stderr)


if __name__ == "__main__":
    main("reuse")
