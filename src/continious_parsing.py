#!/bin/python3

import os, sys, time
from threading import Thread
from multiprocessing import Process, Queue, Pipe

from parse import Parser, RPC 

class ContiniousParser:

    rpc = RPC()

    state_queue = Queue()
    state = \
    {
        "blocks": 0,         # Number of blocks, that were passed to the script. Same with transactions, inputs (vin's) and outputs (vout's).
        "transactions": 0,
        "inputs": 0,
        "outputs": 0,

        "failed_inputs": 0,  # Number of transaction inputs, in which we weren't able to find any public keys.
        "failed_outputs": 0, # Same, but only failed P2PK and P2TR outputs count (, because other types don't even have public keys in it).
        "ecdsa": 0,
        "schnorr": 0,
        "keys": 0,

        "parsed": set(),
        "target": set()
    }
    STATE_FILE = "state/parsing_state.json"

    # [(process1, busy: bool, (pipe1)), (process2, busy: bool, (pipe2))]
    parsers = []

    def start_parsers(self, parser_count:int=os.cpu_count()) -> bool:
        #TODO
        return False

    def assign_tasks(self) -> bool:
        #TODO
        pass

    def update_statistics(self, statistics: dict) -> None:
        #TODO
        pass

    def update_block_state(self, block_set: set) -> None:
        #TODO
        pass

    def measure_speed(self) -> None:
        #TODO
        pass

    start_time = int(time.time())
    def flush_state_to_file(self) -> bool:
        #TODO
        pass

    def restore_state_from_file(self) -> bool:
        #TODO
        pass

    def recover(self) -> bool:
        #TODO
        pass

    def send_email_on_event(self, event: str) -> bool:
        #TODO
        pass


if __name__ == "__main__":

    cp = ContiniousParser()
    if not cp.start_parsers():
        print("[ERROR] Could not start parsers!", file = sys.stderr)
        exit(1)

    while True: # parse (1), recover (2), repeat

        try:
            while True: #(1)

                cp.assign_tasks()

                # Backup state to file every 5 minutes
                if int(time.timr()) % (60*5) == 0:
                    cp.flush_state_to_file()

                # Measure speed every 10 minutes
                if int(time.time()) % (60*10) == 0:
                    t = Thread(target=cp.measure_speed())
                    t.daemon = True
                    t.start()

                time.sleep(1)

        except: #(2)

            if not cp.recover():
                print("[ERROR] Could not recover after failure!", file = sys.stderr)
                cp.send_email_on_event("recover_failure")
                exit(1)
