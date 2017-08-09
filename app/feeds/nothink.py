#!/usr/bin/env python

from urllib import urlopen
__url__ = "http://www.nothink.org/blacklist/blacklist_malware_irc.txt"
__reference__ = "nothink.org"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
