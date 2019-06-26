#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
rsync -mravz $DIR/../../ conflux:~/conflux-rust --prune-empty-dirs --include "*/" --include="*.rs" --include="*.py" --include="*.sh" --include="*.toml" --exclude="*"
#ssh conflux /home/ec2-user/conflux-rust/test/scripts/sync_replicas.sh
