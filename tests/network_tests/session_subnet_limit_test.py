#!/usr/bin/env python3

from session_ip_limit_test import SessionIpLimitTests

if __name__ == "__main__":
    # 2 nodes for a single subnet/C
    SessionIpLimitTests("9,8,4,2", 3).main()