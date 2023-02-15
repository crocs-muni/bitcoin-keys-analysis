#!/bin/python3

import os, sys, time, traceback
import json, logging
from datetime import timedelta
from threading import Thread
from multiprocessing import Process, Queue

from bitcoin_public_key_parser import BitcoinPublicKeyParser, BitcoinRPC


class BitcoinParserManager:

    logger = logging.getLogger(__name__)

    file_handler = logging.FileHandler("logs/bitcoin_parser_manager.log")
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(funcName)s | %(lineno)d")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

    rpc = BitcoinRPC()
    rpc_process = None

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

        "tx_types": {},
        "parsed": [],
        "target": []
    }
    STATE_FILE = "state/bitcoin_parsing_state.json"

    # [[parser1, process1], [parser2, process2], ..]
    parsers = []

    task_queue = Queue()
    block_queue = Queue(10)
    transaction_queue = Queue(10000)
    progress_queue = Queue(20)
    block_progress = {}

    def set_target(self, target: range) -> None:
        self.state["target"] = list(target)

    def start_calling_rpc(self) -> bool:
        try:
            for block_n in list(set(self.state["target"]) - set(self.state["parsed"])):
                self.task_queue.put(block_n)

            self.rpc_process = Process(target=self.rpc.transactions_to_queue, args=(self.transaction_queue, self.block_queue, self.task_queue,))
            self.rpc_process.start()
            self.logger.info(f"Successfully started RPC-calling process. It's pid: {self.rpc_process.pid}.")
            return True
        except:
            self.logger.exception("Couldn't start calling RPC.")
            return False

    def create_parser(self) -> list:
        parser = BitcoinPublicKeyParser()
        process = Process(target=parser.process_transactions_from_queue, args=(self.transaction_queue, self.progress_queue,))
        process.start()
        return [parser, process]


    def start_parsers(self, parser_count: int = os.cpu_count()) -> bool:

        if self.parsers != []:
            pids = [parser[1].pid for parser in self.parsers]
            self.logger.warning(f"Was trying to start parsers, but there were already some parsers, their pids: {pids}. Terminating them.")
            for parser in self.parsers:
                parser[1].terminate()
            self.parsers = []

        if len(self.state["target"]) == 0:
            self.logger.error("Did not start the parsers because target is empty! Set it with Bitcoin.ParserManager.set_target().")
            return False

        if not self.start_calling_rpc():
            self.logger.error("Did not start the parsers because hadn't managed to start calling RPC.")
            return False

        while self.transaction_queue.empty():
            self.logger.warning("Still no transactions in the transaction queue.")
            time.sleep(0.5)

        self.parsers = [self.create_parser() for i in range(parser_count)]
        pids = [parser[1].pid for parser in self.parsers]
        self.logger.info(f"Successfully started {parser_count} parsers. Their pids are: {pids}")

        return True


    def track_progress(self) -> None:

        while not self.block_queue.empty():
            self.logger.debug("The block queue not empty.")
            block = None
            try:
                block = self.block_queue.get_nowait()
            except:
                break

            assert type(block) == dict
            assert "tx" in block.keys()
            assert type(block["tx"]) == list
            self.logger.debug(f"Got block {block['height']} from the block queue.")
            self.block_progress[block["height"]] = block["tx"]


        while not self.progress_queue.empty():

            parser_echo = None
            try:
                parser_echo = self.progress_queue.get_nowait()
            except:
                break
            assert type(parser_echo) != None
            self.logger.debug(f"Parser's echo: {parser_echo}.")

            self.update_block_progress(parser_echo[0])
            self.update_statistics(parser_echo[1])
            self.update_types(parser_echo[2])
            self.update_block_state()


    def update_block_progress(self, parsed_txid_list) -> None:
        self.logger.debug(f"Block_progress before: {self.block_progress}.")
        for txid in parsed_txid_list:
            for block_n, txid_list in self.block_progress.items():
                if txid in txid_list:
                    txid_list.remove(txid)
                    break
        self.logger.debug(f"Block_progress after: {self.block_progress}.")

    def update_block_state(self) -> None:
        for block_n, txid_list in self.block_progress.items():
            if len(txid_list) == 0 and block_n not in self.state["parsed"]:
                self.state["parsed"].append(block_n)

    def update_statistics(self, statistics: dict) -> None:
        for key, value in statistics.items():
            self.state[key] += value

    def update_types(self, types: dict) -> None:
        for month in types.keys():

            if not month in self.state["tx_types"].keys():
                self.state["tx_types"][month] = json.loads(json.dumps(BitcoinPublicKeyParser.INIT_TYPES_DICT)) # deep copy

            for tx_type, count in types[month].items():
                self.state["tx_types"][month][tx_type] += count


    def print_speed(self, start_timestamp) -> None:
        time_diff = int(time.time() - start_timestamp)
        if time_diff == 0:
            time_diff = 1   # avoid devision by zero

        self.logger.info(f"Running for {str(timedelta(seconds=time_diff))} and gathered {self.state['keys']} keys ({self.state['keys'] // time_diff} keys/sec).")

    def print_state(self) -> None:
        for key, value in self.state.items():
            if key != "tx_types" and key != "target" and key != "parsed":
                print(f"{key}: {value}")


    def all_tasks_done(self) -> None:
        for i, parser in enumerate(self.parsers):
            parser[1].join()
            self.logger.info(f"Joined parser (pid {parser[1].pid}) with exitcode {parser[1].exitcode}")
        self.parsers = []
        self.rpc_process.join()
        self.logger.info(f"Joined RPC-calling process (pid {self.rpc_process.pid}) with exitcode {self.rpc_process.exitcode}.")
        self.rpc_process = None

        print("-------[SUCCESS]-------")
        self.print_state()
        self.flush_state_to_file()


    def flush_state_to_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "w") as file:
                json.dump(self.state, file, indent = 2)

        except Exception as e:
            self.logger.exception("Could not flush the state to a file.")
            self.logger.warning(f"State: {self.state}")
            return False

        self.logger.info("Flushed the state to the file.")
        return True


    def restore_state_from_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "r") as file:
                self.state = json.load(file)

        except Exception as e:
            self.logger.exception("Could not restrore the state from a file.")
            return False

        self.logger.info("Restored state from the file.")
        return True


    """
        "Main" functions
    """

    def parse_range(self, range_to_parse: range, parser_count: int = os.cpu_count()) -> bool:
        self.set_target(range_to_parse)

        if not self.start_parsers(parser_count):
            self.logger.error("Could not start parsers!")
            return False

        start_timestamp = time.time()
        try:
            while True:

                self.track_progress()

                if set(self.state["target"]) == set(self.state["parsed"]):
                    self.print_speed(start_timestamp)
                    self.all_tasks_done()
                    return True

                # Backup state to file every 100k keys.
                if self.state["keys"] % 100000 == 0:
                    self.flush_state_to_file()
                    self.print_speed(start_timestamp)

        except Exception as e:
            self.logger.exception("Something went wrong. We are outside `parse` loop.")

        for parser in self.parsers:
            parser[1].terminate()
            self.logger.warning(f"Teminated parser (pid {parser[1].pid}) because an unexpected error happened.")
        self.logger.critical("Stoped parsing.")
        return False


if __name__ == "__main__":
    pm = BitcoinParserManager()
