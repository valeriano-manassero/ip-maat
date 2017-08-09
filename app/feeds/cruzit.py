#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cruzit_web_attacks.ipset"
__reference__ = "cruzit.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
