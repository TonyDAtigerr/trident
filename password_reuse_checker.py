#!/usr/bin/env python3
"""
password_reuse_checker -- verify remediation of cross-domain privileged password reuse.

Reads pwdLastSet for a list of accounts across the domains they appear in and
decides, per account, whether the reuse finding was remediated: a reset within
the assessment window in at least one domain breaks the match, or the account is
no longer present in two or more domains.

See --help for options. For authorized security assessments only.
"""
import pwcheck_core

if __name__ == "__main__":
    pwcheck_core.main("reuse")
