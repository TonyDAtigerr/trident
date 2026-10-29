# Trident

*A three-barreled Active Directory remediation-verification suite -- three focused tools, one trust-aware engine.*

Three focused tools for verifying remediation of common Active Directory findings
across domains and trusts, using a single low-privilege account.

| Tool | Finding it verifies |
|------|---------------------|
| `password_reuse_checker.py` | Cross-domain privileged **password reuse** |
| `weak_password_checker.py`  | **Weak-password** accounts were reset |
| `foreign_principal_checker.py`              | **Foreign Security Principals** in privileged groups |

The two password tools share one engine (`pwcheck_core.py`); the FSP tool is
standalone. All three authenticate over SMB using your home domain (the trust
path), auto-detect the DC and auth realm per domain, run domains/queries in
parallel, and read with a single low-privilege account across trusts.

## Workflow

Trident is the remediation-verification half of a domain password audit. The input
lists come from a domain password audit run with
[max.py](https://github.com/knavesec/max) -- its domain password audit / NTLM-hash
import against the NTDS database and cracked passwords, which surfaces the accounts
with **reused passwords across domains** and **weak/crackable passwords**.

You export those findings as Trident's input lists and point the tools at them:

```
max.py (domain password audit)          Trident (remediation verification)
  reused-password accounts   ──────────▶  password_reuse_checker.py  (users.txt)
  weak-password accounts     ──────────▶  weak_password_checker.py   (accounts.txt)
  foreign principals (BloodHound) ─────▶  foreign_principal_checker.py
```

Trident then confirms whether the client actually reset those accounts, turning the
raw audit output directly into per-account remediation guidance
(REMEDIATED / NOT REMEDIATED).

## Requirements

- [netexec](https://github.com/Pennyw0rth/NetExec) (`nxc`) on `PATH`
- Python 3.8+
- `openpyxl` - optional, for the `--xlsx` reports
- `dnspython`, `ldap3` - optional, only for `--forest` auto-discovery (reuse tool)

```bash
pip install -r requirements.txt
```

## Install

```bash
git clone https://github.com/TonyDAtigerr/trident.git
cd trident
chmod +x *.py
```

Each tool is a standalone script. `password_reuse_checker.py` and
`weak_password_checker.py` import `pwcheck_core.py`, so keep those three files in
the same directory. Sample input files are in `examples/`.

---

## password_reuse_checker.py

Checks a list of accounts across the domains they appear in. An account is
**REMEDIATED** if its password was reset within the assessment window in at
least one domain (breaking the match), or if it is no longer present in two or
more domains. Otherwise **NOT REMEDIATED** (or UNVERIFIED / N/A).

```bash
./password_reuse_checker.py -u users.txt -d domains.txt -U user -P 'pass' \
    --testing-start 05/12/2026 -o Reuse
```

- `users.txt` - one `sAMAccountName` per line.
- `domains.txt` - one domain per line, optionally `domain,dc`.
- Supports `--forest`, `--parse` (offline), and a stored credential via `--id`.

## weak_password_checker.py

Checks specific accounts in specific domains (e.g. ones found with weak
passwords). Feed `username@domain`, one per line. Each is **REMEDIATED** only if
its password was reset within the window, else **NOT REMEDIATED**.

```bash
./weak_password_checker.py --accounts accounts.txt -U user -P 'pass' \
    --testing-start 05/12/2026 -o Weak
```

- `accounts.txt` - one `username@domain` per line.
- Domains come from the list; use `-d` only to pin a DC per domain.

## foreign_principal_checker.py

Lists the foreign users and groups in privileged groups, per domain - a
cross-domain compromise path. Give it domains and (optionally) a group list.

```bash
./foreign_principal_checker.py -d domains.txt --groups-file groups.txt -U user -P 'pass' \
    -o fsp_report.txt --csv fsp.csv --xlsx fsp.xlsx
```

See **[docs/finding-fsps-in-bloodhound.md](docs/finding-fsps-in-bloodhound.md)** for the Cypher queries to pull the FSP findings (and the domains/groups to scan) out of BloodHound.

---

## Shared behaviour

- `--testing-start MM/DD/YYYY` (password tools): the assessment start date. A
  reset any time from then to now counts, which credits mid-assessment rotations.
  Omit it and you're prompted (blank skips remediation marking).
- `-o NAME` writes `NAME.txt`, `NAME.csv`, and `NAME.xlsx` (green = REMEDIATED,
  red = NOT REMEDIATED, orange = UNVERIFIED).
- `--id N` uses a stored netexec credential; `--auth-domain` pins your home
  domain if it isn't among the targets; `--threads` controls parallelism.

> Limitation: pwdLastSet proves a password was *changed*, not that the new one is
> *different/non-reused* or *strong*. Cryptographic proof needs a hash comparison
> (NTDS/DCSync) under privilege. These tools give the strongest low-privilege
> evidence - a necessary, not sufficient, condition.

## License

MIT -- see [LICENSE](LICENSE).

## Disclaimer

For authorized security assessments only. Use solely against systems you have
explicit written permission to test.
