#!/usr/bin/env python

from urllib import urlopen

__url__ = "https://reputation.alienvault.com/reputation.generic"
__reference__ = "alienvault.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        if " # " in line:
            reason = line.split(" # ")[1].split()[0].lower()
            if reason == "scanning":  # too many false positives
                continue
            retval[line.split(" # ")[0]] = __reference__

    return retval
