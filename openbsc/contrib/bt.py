#!/usr/bin/env python

import os

f = open("unbalanced")
lines = []
for line in f:
    lines.append(line)

filenames = {}

output = []
for line in lines:
    if "[0x" in line:
        start = line.find("[")
        end = line.find("]")
        addr = line[start+1:end]
        try:
            file = filenames[addr]
        except KeyError:
            r = os.popen("addr2line -fs -e ./bsc_hack %s" % addr)
            all = r.read().replace("\n", ",")
            file = all
            filenames[addr] = file

        line = line.replace(addr, file)
    output.append(line)

g = open("unbalanced.2", "w")
g.write("".join(output))



