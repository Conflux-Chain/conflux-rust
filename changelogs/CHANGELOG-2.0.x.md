# 2.0.1

## Improvements

- Add config parameter `get_logs_filter_max_block_number_range` for limiting the maximum gap between `from_block` and `to_block` during Core space log filtering (`cfx_getLogs`). Note: eSpace blocks correspond to epochs in Core space, so the range in `eth_getLogs` can be limited using `get_logs_filter_max_epoch_range`.