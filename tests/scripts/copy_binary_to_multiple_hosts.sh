#!/usr/bin/env bash

parallel-scp -O "StrictHostKeyChecking no" -h ip_list.txt -l ubuntu -p 1000 ../../target/release/conflux ~ | grep FAILURE |wc -l
