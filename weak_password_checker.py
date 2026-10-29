#!/usr/bin/env python3
"""
weak_password_checker -- verify that specific accounts were reset.

Takes a list of 'username@domain' (e.g. accounts found with weak/crackable
passwords) and checks each in its own domain: REMEDIATED if its password was
reset within the assessment window, otherwise NOT REMEDIATED.

See --help for options. For authorized security assessments only.
"""
import pwcheck_core

if __name__ == "__main__":
    pwcheck_core.main("weak")
