#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://lists.blocklist.de/lists/all.txt"
__reference__ = "blocklist.de"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
