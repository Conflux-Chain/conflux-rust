#!/bin/bash
rm -rf blockchain_data
rm -rf log
rm stderr.txt

rm -rf pos_db
rm pos.log
rm -rf pos_config/private_keys

cd pos_config && ls | grep -v pos_config.yaml | grep -v pos_key | grep -v genesis_file | grep -v initial_nodes.json | xargs rm -rf
