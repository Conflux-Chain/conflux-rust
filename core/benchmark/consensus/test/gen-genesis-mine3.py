#!/usr/bin/env python3

fw = open("genesis-mine3.in", "w")
print("2 3 1000 1000", file = fw)
N = 480000
for i in range(0, N):
    print(-1, -1, -1, 1, i, file = fw)
cnt = N
M = 40000
last_cnt = cnt
for j in range(0, M):
    cnt += 1
    if j % 2 == 1:
        print(-1, -1, -1, 1, last_cnt, file = fw, end = " ")
        print(cnt - 1, file = fw)
        last_cnt = cnt
    else:
        print(-1, -1, -1, 1, 0, file = fw)
for j in range(cnt, cnt + N):
    print(-1, -1, -1, 1, j, file = fw)
fw.close()
