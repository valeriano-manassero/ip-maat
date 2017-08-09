#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
__reference__ = "abuse.ch"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line.split(',')[0]] = ("%s (malware)" % line.split(',')[2].lower().split()[0], __reference__)

    return retval
