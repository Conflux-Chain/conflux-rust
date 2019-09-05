#!/usr/bin/env python3

fw = open("large-chain.in", "w")
print("2 3 1000 1000", file = fw)
for i in range(0, 1000000):
    print(-1, -1, -1, 1, i, file = fw)
fw.close()
