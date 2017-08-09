#!/usr/bin/env python

from urllib import urlopen
import re

__url__ = "http://cybercrime-tracker.net/ccam.php"
__reference__ = "cybercrime-tracker.net"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for match in re.finditer(r">([^<]+\.[a-zA-Z]+)</td>\s*<td style=\"background-color: rgb\(11, 11, 11\);\"><a href=\"ccamdetail\.php\?hash=", content):
            retval[match.group(1)] = __reference__

    return retval
