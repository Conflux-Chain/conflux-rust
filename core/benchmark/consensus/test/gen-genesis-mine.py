#!/usr/bin/env python3

fw = open("genesis-mine.in", "w")
print("2 3 1000 1000", file = fw)
N = 200000
for i in range(0, N):
    print(-1, -1, -1, 1, i, file = fw)
cnt = N
last_cnt = cnt
for j in range(0, N):
    cnt += 1
    if j % 2 == 1:
        # print(last_cnt, file = fw, end = " ")
        # print(cnt - 1, file = fw)
        print(-1, -1, -1, 1, last_cnt, file = fw)
        last_cnt = cnt
    else:
        print(-1, -1, -1, 1, 0, file = fw)
fw.close()
