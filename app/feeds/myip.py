#!/usr/bin/env python

from urllib import urlopen
import re

__url__ = "https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt"
__reference__ = "myip.ms"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for match in re.finditer(r"deny from (\d+\.\d+\.\d+\.\d+)", content):
        retval[match.group(1)] = __reference__

    return retval
