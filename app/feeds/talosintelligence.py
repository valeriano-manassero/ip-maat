#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://www.talosintelligence.com/feeds/ip-filter.blf"
__reference__ = "talosintelligence.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
