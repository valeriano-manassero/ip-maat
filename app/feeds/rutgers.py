#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://report.rutgers.edu/DROP/attackers"
__reference__ = "rutgers.edu"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
