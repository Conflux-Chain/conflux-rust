#!/usr/bin/env python3

fw = open("large-chain.in", "w")
for i in range(0, 1000000):
    print(i, file = fw)
fw.close()
