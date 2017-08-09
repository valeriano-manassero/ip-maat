#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://www.packetmail.net/iprep_ramnode.txt"
__reference__ = "packetmail.net"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line.split(';')[0].strip()] = __reference__

    return retval
