function copy_file_from_slaves() {
  file_name=$1
  slave_ips=$2
  log_dir=$3
  dest_file_name=$4
  while IFS= read -r i; do
    scp -o "StrictHostKeyChecking no" "ubuntu@$i:~/$file_name" "$log_dir/logs_tmp/$i$dest_file_name" &
  done < "$slave_ips"
}

function init_log_dir() {
  log_dir=$1

  rm -rf "$log_dir"
  mkdir -p "$log_dir/logs_tmp"
}

function wait_for_copy() {
  $dest_file_name=$1
  while true
  do
      n=`ps -ef|grep [s]cp|grep "$dest_file_name"|grep -v grep|wc -l`
      if [ $n -eq 0 ]
      then
          break
      fi
      echo $n remaining to download log
      sleep 1
  done
}

function expand_logs() {
  log_dir=$1
  dest_file_name=$2

  for file in "$log_dir/logs_tmp/*$dest_file_name"
  do
      tar_dir=${file%$dest_file_name}
      mkdir "$tar_dir"
      tar xzf "$file" -C "$tar_dir"
      rm "$file"
  done
}
