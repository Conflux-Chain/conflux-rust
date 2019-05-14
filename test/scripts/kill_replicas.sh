#!/bin/bash

parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 "killall -9 conflux || echo already killed"