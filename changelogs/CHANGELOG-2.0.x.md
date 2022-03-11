# 2.0.1

## Improvements

- Add config parameter `get_logs_filter_max_block_number_range` for limiting the maximum gap between `from_block` and `to_block` during Core space log filtering (`cfx_getLogs`). Note: eSpace blocks correspond to epochs in Core space, so the range in `eth_getLogs` can be limited using `get_logs_filter_max_epoch_range`.
- Report error in `cfx_getLogs` and `eth_getLogs` if `get_logs_filter_max_limit` is configured but the query would return more logs. The previous behavior of `cfx_getLogs` was to silently truncate the result. The previous behavior of `eth_getLogs` was to raise an error when `filter.limit` is too low, regardless of how many logs the query would result in.
- Add config parameter `min_phase_change_normal_peer_count` to set the number of normal-phase peers needed for phase change. The default value is set to 3 to make it more robust.