#!/usr/bin/env python

import glob
import inspect
import os
import imp
import time
import socket
import json

LOGSTASH_HOST = os.environ['LOGSTASH_HOST']
LOGSTASH_PORT = int(os.environ['LOGSTASH_PORT'])
CRON_SECONDS = int(os.environ['CRON_SECONDS'])

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def main():
    while True:
        modules = {}
        for path in glob.glob('feeds/[!_]*.py'):
            name, ext = os.path.splitext(os.path.basename(path))
            try:
                modules[name] = imp.load_source(name, path)
            except (ImportError, SyntaxError), ex:
                print "[ERROR] Import of feed file '%s' ('%s')" % (name, ex)
                continue

        ips = {}
        for module_name, module_instance in modules.items():
            for function_name, module_function in inspect.getmembers(module_instance, inspect.isfunction):
                if function_name == "fetch":
                    try:
                        print "[INFO] Importing data feed '%s'" % module_name
                        results = module_function()
                        for item in results.items():
                            if validate_ip(item[0]):
                                if item[0] in ips:
                                    ips[item[0]].append(item[1])
                                else:
                                    ips[item[0]] = [item[1]]
                    except IOError, ex:
                        print "[ERROR] Retrieving data '%s' ('%s')" % (module_name, ex)
                        continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
            print "[INFO] Exporting to Logstash"
            for key, value in ips.items():
                message = {"ip": key, "lists": value, "lists_count": len(value)}
                sock.send(json.dumps(message) + "\n")
            print "[INFO] Closing Logstash connection"
            sock.close()
        except socket.error, ex:
            print "[ERROR] Connecting to LogStash %s\n" % ex
        time.sleep(CRON_SECONDS)

if __name__ == "__main__":
    main()
