#!/usr/bin/env python3

import os

file_name = "ip_list.txt"
local_path = ""
remote_path = ""

ips = []
with open(file_name) as fp:
    line = fp.readline()
    while line:
        ips.append(line.strip().strip(","))
        line = fp.readline()

for ip in ips:
    cmd = "ssh-copy-id -f -o StrictHostKeyChecking=no -i pubkey.pub ubuntu@{}".format(
        ip
    )
    print(cmd)
    os.system(cmd)
