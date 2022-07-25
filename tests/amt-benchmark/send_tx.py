import time


def send_transaction_with_goodput(encoded_transactions, send, node, base=0, log=print):
    if log is None:
        log = print

    start_time = time.time()

    tasks = enumerate(encoded_transactions)
    i, encoded = next(tasks)
    size = 0
    complete = False

    while not complete:
        time.sleep(1)
        goodtps = int(node.getgoodput())
        log(f"Current goodput: {goodtps}")
        while encoded.length + base < int(goodtps) + 50000:
            send(i, encoded)
            size += encoded.length
            try:
                i, encoded = next(tasks)
            except StopIteration:
                complete = True
                break

        log(f"Sent {base} transactions (in total)")

    time_used = time.time() - start_time
    log(f"Time used: {time_used}")
    return size


def wait_transaction_with_goodput(target, node, log=print):
    while True:
        goodput = int(node.getgoodput())
        if goodput == target:
            log(f"Good put reach target {target}")
            break
        else:
            log(f"Good put: {goodput}/{target}")
        time.sleep(1)

# self.node.p2ps[i % n_connections].send_protocol_packet(encoded.encoded + int_to_bytes(
#     TRANSACTIONS))

# def send_transaction_with_tps(encoded_transactions, send, send_tps, log=print):
#     start_time = time.time()
#
#     i = 0
#     batch_size = BATCH_SIZE
#     for encoded in encoded_transactions:
#         i += 1
#         if i * batch_size % send_tps == 0:
#             time_used = time.time() - start_time
#             time.sleep(i * batch_size / send_tps - time_used)
#         send(i, encoded)
#         if i * batch_size % 10000 == 0:
#             log("Sent %d transactions", i * batch_size)
#
#     time_used = time.time() - start_time
#     log(f"Time used: {time_used}")
#
#
# def wait_transaction_with_tps(node, log=print):
#     suc_empty = 0
#     while suc_empty < 10:
#         block_hash = node.cfx_getBestBlockHash()
#         block = node.cfx_getBlockByHash(block_hash, True)
#         tx_num = len(block["transactions"])
#         if tx_num == 0:
#             suc_empty += 1
#         else:
#             suc_empty = 0
#         log("Block height {}, txs {}".format(int(block["height"], 0), tx_num))
#         log(node.getgoodput())
#
#         time.sleep(1)
