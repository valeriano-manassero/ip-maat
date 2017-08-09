#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
__reference__ = "emergingthreats.net"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
