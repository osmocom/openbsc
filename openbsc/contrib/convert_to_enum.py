#!/usr/bin/env python

#
# Convert ETSI documents to an enum
#

import re, sys

def convert(string):
    string = string.strip().replace(" ", "").rjust(8, "0")
    var = 0
    offset = 7
    for char in string:
        assert offset >= 0
        var = var | (int(char) << offset)
        offset = offset - 1

    return var

def string(name):
    name = name.replace(" ", "_")
    name = name.replace('"', "")
    name = name.replace('/', '_')
    name = name.replace('(', '_')
    name = name.replace(')', '_')
    return "%s_%s" % (sys.argv[2], name.upper())

file = open(sys.argv[1])


for line in file:
    m = re.match(r"[ \t]*(?P<value>[01 ]+)[ ]+(?P<name>[a-zA-Z /0-9()]+)", line[:-1])

    if m:
        print "\t%s\t\t= %d," % (string(m.groupdict()["name"]), convert(m.groupdict()["value"]))
    else:
        print line[:-1]
