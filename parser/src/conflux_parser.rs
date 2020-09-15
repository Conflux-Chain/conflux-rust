use std::sync::Arc;
use cfx_types::{ H256 };
use primitives::{ block_header::BlockHeader, transaction::SignedTransaction, block::Block };
use rlp::Rlp;

pub fn block_header_to_json(bh : &BlockHeader) -> String {
  let mut res = String::new();
  res.push_str(&format!("block_header: {}\n", '{'));
  res.push_str(&format!("hash: {:#x},\n", bh.hash()));
  res.push_str(&format!("pow_hash: {:#x},\n", bh.pow_hash.unwrap()));
  res.push_str(&format!("approximated_rlp_size: {},\n", bh.approximated_rlp_size()));
  res.push_str(&format!("rlp_part: {}\n", '{'));
  res.push_str(&format!("parent_hash: {:#x},\n", bh.parent_hash()));
  res.push_str(&format!("height: {},\n", bh.height()));
  res.push_str(&format!("timestamp: {},\n", bh.timestamp()));
  res.push_str(&format!("author: {:#x},\n", bh.author()));
  res.push_str(&format!("transactions_root: {:#x},\n", bh.transactions_root()));
  res.push_str(&format!("deferred_state_root: {:#x},\n", bh.deferred_state_root()));
  res.push_str(&format!("deferred_receipts_root: {:#x},\n", bh.deferred_receipts_root()));
  res.push_str(&format!("deferred_logs_bloom_hash: {:#x},\n", bh.deferred_logs_bloom_hash()));
  res.push_str(&format!("blame: {},\n", bh.blame()));
  res.push_str(&format!("difficulty: {:#x},\n", bh.difficulty()));
  res.push_str(&format!("adaptive: {},\n", bh.adaptive()));
  res.push_str(&format!("gas_limit: {:#x},\n", bh.gas_limit()));
  res.push_str(&format!("referee_hashes: {}\n", '['));
  let referee_iter = bh.referee_hashes().iter();
  for val in referee_iter {
    res.push_str(&format!("{:#x},\n", val));
  }
  res.push_str(&format!("{},\n", ']'));
  res.push_str(&format!("custom: {}\n", '['));
  let custom_iter = bh.custom().iter();
  for val in custom_iter {
    res.push_str(&format!("\"{:?}\"", val));
  }
  res.push_str(&format!("{},\n", ']'));
  res.push_str(&format!("nonce: {:#x},\n", bh.nonce()));
  res.push_str(&format!("{}\n", '}'));
  res.push_str(&format!("{}\n", '}'));

  res
}

pub fn transaction_to_json(tx : &SignedTransaction) -> String {
  let mut res = String::new();
  res.push_str(&format!("transaction: {}\n", "{"));
  res.push_str(&format!("sender: {:#x}\n", tx.sender()));
  res.push_str(&format!("is_unsigned: {}\n", tx.is_unsigned()));
  res.push_str(&format!("nonce: {:#x}\n", tx.nonce()));
  res.push_str(&format!("hash: {:#x}\n", tx.hash()));
  res.push_str(&format!("gas: {:#x}\n", tx.gas()));
  res.push_str(&format!("gas_limit: {:#x}\n", tx.gas_limit()));
  res.push_str(&format!("gas_price: {:#x}\n", tx.gas_price()));
  res.push_str(&format!("rlp_size: {}\n", tx.rlp_size()));
  if tx.public().is_some() {
    res.push_str(&format!("public: {:#x}\n", tx.public().unwrap()));
  }
  res.push_str(&format!("action: {:?}\n", tx.transaction.action));
  res.push_str(&format!("value: {:#x}\n", tx.transaction.value));
  res.push_str(&format!("storage_limit: {:#x}\n", tx.transaction.storage_limit));
  res.push_str(&format!("epoch_height: {}\n", tx.transaction.epoch_height));
  res.push_str(&format!("chain_id: {}\n", tx.transaction.chain_id));
  res.push_str(&format!("data: {:?}\n", tx.transaction.data));
  res.push_str(&format!("{}\n", "}"));
  res
}

pub fn block_to_json(b : &Block) -> String {
  let mut res = String::new();
  res.push_str(&format!("block: {}\n", '{'));
  res.push_str(&block_header_to_json(&(b.block_header)));
  let transaction_iter = b.transactions.iter();
  res.push_str(&format!("transactions: {}\n", '['));
  for val in transaction_iter {
    let transaction = Arc::clone(&val);
    res.push_str(&transaction_to_json(&transaction));
  }
  res.push_str(&format!("{}\n", ']'));
  res.push_str(
    &format!("approximated_rlp_size: {}\n", b.approximated_rlp_size_with_public)
  );
  res.push_str(
    &format!("approximated_rlp_size_with_public: {}\n", b.approximated_rlp_size_with_public)
  );
  res.push_str(&format!("{}\n", '}'));
  res
}

fn main() {
  let flags_conflux_home = "/data/docker-conflux";

  let mut blockchain_dir = String::from("");
  blockchain_dir.push_str(flags_conflux_home);
  blockchain_dir.push_str("/blockchain_db");

  let db_opts = rocksdb::DBOptions::default();

  let cf_opts = rocksdb::ColumnFamilyOptions::default();
  let mut cf_names = Vec::new();
  cf_names.push("default");
  cf_names.push("col0");
  cf_names.push("col1");
  cf_names.push("col2");
  cf_names.push("col3");

  let mut cfds = Vec::new();
  for cf_name in &cf_names {
    cfds.push((*cf_name, cf_opts.clone()));
  }

  print!("open blockchain (rocksdb) database from {} ...\n", blockchain_dir);
  let db = rocksdb::DB::open_cf_for_read_only(
    db_opts.clone(), &blockchain_dir, cfds.clone(), false
  ).expect("rocksdb error");
  let mut cf_handles = Vec::new();
  for cf_name in &cf_names {
    let cf_handle = db.cf_handle(
      cf_name
    ).expect("cf_handle error");
    cf_handles.push(cf_handle);
  }

  print!("tranvers database ...\n");
  let mut count = 0;
  // for cf_handle in &cf_handles {
  //   let mut iter = db.iter_cf(cf_handle);
  //   iter.seek(rocksdb::SeekKey::Start).unwrap();
  //   for (key, value) in &mut iter {
  //     count += 1;
  //   }
  //   drop(iter);
  // }
  // { // Misc
  //   let mut iter = db.iter_cf(&(cf_handles[1]));
  //   iter.seek(rocksdb::SeekKey::Start).unwrap();
  //   for (key, value) in &mut iter {
  //     print!("{}\n", value.len());
  //     count += 1;
  //   }
  //   drop(iter);
  // }
  { // Blocks
    let mut iter = db.iter_cf(&(cf_handles[2]));
    iter.seek(rocksdb::SeekKey::Start).unwrap();
    for (key, value) in &mut iter {
      let result = BlockHeader::decode_with_pow_hash(&(value.clone()));
      if result.is_ok() {
        print!("{}\n", '{');
        print!("key: {:#x}\n", H256::from_slice(&key));
        print!("value: {}\n", '{');
        let block_header = result.unwrap();
        let mut body_key = Vec::with_capacity(H256::len_bytes() + 1);
        let suffix: u8 = 2;
        body_key.extend_from_slice(&key);
        body_key.push(suffix);
        // let encoded = db.get_cf(&(cf_handles[2]), &key).unwrap().expect("get block");
        let body_value = db.get_cf(&(cf_handles[2]), &body_key);
        if body_value.is_ok() {
          let body_option = body_value.unwrap();
          if body_option.is_some() {
            let encoded = body_option.unwrap();
            let rlp = Rlp::new(&encoded);
            let block_body = Block::decode_body_with_tx_public(&rlp)
                             .expect("Wrong block rlp format!");
            let block = Block::new(block_header, block_body);
            print!("{}", block_to_json(&block));
          } else {
            print!("{}", block_header_to_json(&block_header));
          }
        } else {
          print!("{}", block_header_to_json(&block_header));
        }
        print!("{}\n", '}');

        count += 1;
      }
    }
    drop(iter);
  }
  // { // TransactionIndex (transaction_id -> block_id)
  //   let mut iter = db.iter_cf(&(cf_handles[2]));
  //   iter.seek(rocksdb::SeekKey::Start).unwrap();
  //   for (key, value) in &mut iter {
  //     count += 1;
  //   }
  //   drop(iter);
  // }
  // { // EpochNumbers
  //   let mut iter = db.iter_cf(&(cf_handles[3]));
  //   iter.seek(rocksdb::SeekKey::Start).unwrap();
  //   for (key, value) in &mut iter {
  //     count += 1;
  //   }
  //   drop(iter);
  // }
  print!("total: {}\n", count);

  print!("cleanup ...\n");
  for cf_handle in cf_handles {
    drop(cf_handle);
  }
  drop(db);

  print!("job finished successfully.\n");
  std::process::exit(0);
}

