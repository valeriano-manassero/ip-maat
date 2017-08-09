#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://sblam.com/blacklist.txt"
__reference__ = "sblam.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
