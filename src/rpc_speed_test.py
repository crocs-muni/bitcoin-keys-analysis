#!/bin/python3

import bitcoin.rpc, time

bitcoin.SelectParams("mainnet")
rpc = bitcoin.rpc.RawProxy(btc_conf_file="/home/bitcoin-core/.bitcoin/bitcoin.conf") # RawProxy takes commands in hexa strings instead of structs, that is what we need
BLOCK_COUNT = rpc.getblockcount()

def test_n_blocks(n: int = 10000):

    time_getblockhash = float(0)
    time_getblock = float(0)
    time_getrawtransaction = float(0)
    n_getblockhash = 0
    n_getblock = 0
    n_getrawtransaction = 0

    for i in range(BLOCK_COUNT - n, BLOCK_COUNT):
        # getblockhash call
        start_time = time.perf_counter()
        block_hash = rpc.getblockhash(i)
        stop_time = time.perf_counter()
        time_getblockhash += (stop_time - start_time)
        n_getblockhash += 1

        # getblock call
        start_time = time.perf_counter()
        block_transactions = rpc.getblock(block_hash)['tx']
        stop_time = time.perf_counter()
        time_getblock += (stop_time - start_time)
        n_getblock += 1

        # getrawtransaction call
        for txid in block_transactions:
            start_time = time.perf_counter()
            rpc.getrawtransaction(txid, True)
            stop_time = time.perf_counter()
            time_getrawtransaction += (stop_time - start_time)
            n_getrawtransaction += 1

    print(f"Average time for getblockhash: {time_getblockhash * 1000 / n_getblockhash} ms (based on {n_getblockhash} measurments).")
    print(f"Average time for getblock: {time_getblock * 1000 / n_getblock} ms (based on {n_getblock} measurments).")
    print(f"Average time for getrawtransaction: {time_getrawtransaction * 1000 / n_getrawtransaction} ms (based on {n_getrawtransaction} measurments).")

from multiprocessing import Process
def test_n_processes(n_processes: int = 4, n_blocks: int = 10000):

    processes = [Process(target=test_n_blocks, args=(n_blocks, )) for i in range(n_processes)]
    for process in processes:
        process.start()
    for process in processes:
        process.join()
