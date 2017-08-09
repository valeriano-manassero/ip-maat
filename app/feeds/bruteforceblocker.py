#!/usr/bin/env python

from urllib import urlopen

__url__ = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
__reference__ = "rulez.sk"


def fetch():
    retval = {}
    content = urlopen(__url__).read()

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line.split('\t')[0]] = __reference__

    return retval
