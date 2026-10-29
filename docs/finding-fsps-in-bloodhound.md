# Finding Foreign Security Principals in BloodHound

A **Foreign Security Principal (FSP)** in a privileged group is a user or group
from a *different* domain/forest that is a member of a highly privileged group.
In BloodHound this shows up as a **cross-domain `MemberOf` edge** into a tier-0
group — the member's `domain` differs from the group's `domain`. These are the
findings you feed into `foreign_principal_checker.py` to verify remediation.

> Collect **every** trusted domain with SharpHound first. A foreign principal
> whose home domain wasn't collected appears only as an unresolved SID
> (`S-1-5-21-...`), so you can't see its name or expand group members.

---

## Quickest: Cypher queries

Paste these into the raw query box (BloodHound CE: the **Cypher** tab;
Legacy: the bar at the bottom).

### Direct foreign members of tier-0 groups

```cypher
MATCH (n)-[:MemberOf]->(g:Group)
WHERE (
    g.name STARTS WITH "ADMINISTRATORS@"      OR
    g.name STARTS WITH "DOMAIN ADMINS@"       OR
    g.name STARTS WITH "ENTERPRISE ADMINS@"   OR
    g.name STARTS WITH "SCHEMA ADMINS@"       OR
    g.name STARTS WITH "BACKUP OPERATORS@"
  )
  AND n.domain <> g.domain
RETURN g.name        AS PrivilegedGroup,
       labels(n)     AS Type,
       n.name        AS ForeignPrincipal,
       n.domain      AS ForeignDomain
ORDER BY g.name
```

`Type` tells you whether each foreign member is a `User` or a `Group`. A foreign
**Group** is higher risk — everyone inside it inherits the privileged access.

### Effective (recursive) members — catches nesting

A foreign principal can be nested inside a local group that is itself a member of
the privileged group. This walks the full chain:

```cypher
MATCH (n)-[:MemberOf*1..]->(g:Group)
WHERE (
    g.name STARTS WITH "ADMINISTRATORS@"    OR
    g.name STARTS WITH "DOMAIN ADMINS@"     OR
    g.name STARTS WITH "ENTERPRISE ADMINS@"
  )
  AND n.domain <> g.domain
RETURN DISTINCT g.name   AS PrivilegedGroup,
       labels(n)         AS Type,
       n.name            AS ForeignPrincipal,
       n.domain          AS ForeignDomain
ORDER BY g.name
```

(The variable-length `*1..` can be slow on large graphs — run it per domain if it
times out.)

### Which domains to scan

This lists the group's domain vs the foreign member's domain, so you know which
domains to put in the tool:

```cypher
MATCH (n)-[:MemberOf]->(g:Group)
WHERE (g.name STARTS WITH "ADMINISTRATORS@" OR
       g.name STARTS WITH "DOMAIN ADMINS@"  OR
       g.name STARTS WITH "ENTERPRISE ADMINS@")
  AND n.domain <> g.domain
RETURN DISTINCT g.domain AS GroupDomain, n.domain AS ForeignDomain
```

### Custom privileged groups

If the environment has custom tier-0 groups (e.g. a vendor's admin group), add
them to the `WHERE` clause by name:

```cypher
    ... OR g.name STARTS WITH "KYNDRYL_TIER0_ADMINS@" ...
```

---

## In the GUI

1. Search for a privileged group (e.g. `DOMAIN ADMINS@CORP.LOCAL`) and open it.
2. In **Node Info**, expand **Members** (CE) / **Direct Members** and
   **Unrolled Members** (Legacy).
3. Any member whose name ends in a **different** `@DOMAIN` than the group is a
   foreign security principal. Unrolled/effective members reveal nested ones.
4. Repeat for `ADMINISTRATORS@`, `ENTERPRISE ADMINS@`, etc. in each domain.

---

## Feeding the results into Trident

From the query output you get, per finding: the **privileged group**, the
**foreign principal**, and its **home domain**. Use those as the tool's inputs:

```bash
# groups.txt  <- the PrivilegedGroup names (sAMAccountName part, e.g. "Domain Admins")
# domains.txt <- the owning domains AND the foreign domains (so SIDs resolve + group
#                members can be enumerated)

./foreign_principal_checker.py -d domains.txt --groups-file groups.txt \
    -U user -P 'pass' -o fsp_report.txt --csv fsp.csv --xlsx fsp.xlsx
```

Include the **foreign** domains in `domains.txt` too — the tool resolves each
foreign SID to a name/type and (for a foreign group) can only enumerate the users
inside it if that group's home domain is in scope and reachable.
