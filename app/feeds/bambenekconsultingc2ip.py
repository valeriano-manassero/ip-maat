#!/usr/bin/env python

from urllib import urlopen
import re

__url__ = "http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt"
__reference__ = "bambenekconsulting.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for match in re.finditer(r"(?m)^([\d.]+),IP used by ([^,/]+) C&C", content):
        retval[match.group(1)] = ("%s (malware)" % match.group(2).lower().strip(), __reference__)

    return retval
