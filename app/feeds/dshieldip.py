#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://feeds.dshield.org/top10-2.txt"
__reference__ = "dshield.org"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line.split()[0]] = __reference__

    return retval
