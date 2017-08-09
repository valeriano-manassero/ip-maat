#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://www.badips.com/get/list/any/2?age=7d"
__reference__ = "badips.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = __reference__

    return retval
