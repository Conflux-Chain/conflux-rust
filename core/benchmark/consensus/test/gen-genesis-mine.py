#!/usr/bin/env python3

fw = open("genesis-mine.in", "w")
for i in range(0, 200000):
    print(i, file = fw)
cnt = 200000
last_cnt = cnt
for j in range(0, 200000):
    cnt += 1
    if j % 2 == 1:
        # print(last_cnt, file = fw, end = " ")
        # print(cnt - 1, file = fw)
        print(last_cnt, file = fw)
        last_cnt = cnt
    else:
        print(0, file = fw)
fw.close()
