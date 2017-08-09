#!/usr/bin/env python

from urllib import urlopen
import re

__url__ = "https://www.maxmind.com/en/high-risk-ip-sample-list"
__reference__ = "maxmind.com"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for match in re.finditer(r"high-risk-ip-sample/([\d.]+)", content):
        retval[match.group(1)] = __reference__

    return retval
