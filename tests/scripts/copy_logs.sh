#!/bin/bash

. $(dirname "$0")/copy_logs_lib.sh

set -e

log_dir=logs

init_log_dir "$log_dir"

#parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 -t 600 'find /tmp/conflux_test_* -name "conflux.log" | xargs tar cvfz log.tgz'
parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 -t 600 "./remote_collect_log.sh"

copy_file_from_slaves log.tgz ips "$log_dir" ".tgz"
wait_for_copy "tgz"
expand_logs "$log_dir" ".tgz"
