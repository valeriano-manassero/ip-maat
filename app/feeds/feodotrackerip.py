#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"
__reference__ = "abuse.ch"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        retval[line] = __reference__

    return retval
