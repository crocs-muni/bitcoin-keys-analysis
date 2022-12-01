#!/bin/python3

import os, sys, time, traceback
import json, logging
from datetime import timedelta
from threading import Thread
from multiprocessing import Process, Pipe

from parse import Parser, RPC

class ContiniousParser:

    logger = logging.getLogger(__name__)

    file_handler = logging.FileHandler("logs/continious_parsing.log")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(funcName)s | %(lineno)d")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)


    rpc = RPC()

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

        "parsed": [],
        "target": []
    }
    STATE_FILE = "state/parsing_state.json"

    # [[parser1, process1, pipe1_conn, task1, last_assigned_task_timestamp1], [parser2, process2, pipe2_conn, task2, .._timestamp2], ..]
    parsers = []
    task_stack = []

    def set_target(self, target: range) -> None:
        self.state["target"] = list(target)

    def generate_task_stack(self):
        self.task_stack = list(set(self.state["target"]) - set(self.state["parsed"]))
        self.task_stack.reverse()


    def create_parser(self) -> list:
        parser = Parser(self.rpc)
        parent_conn, child_conn = Pipe()
        process = Process(target=parser.process_blocks_from_pipe, args=(child_conn,))
        process.start()
        return [parser, process, parent_conn, [], time.time()]

    def start_parsers(self, parser_count: int = os.cpu_count()) -> bool:

        if self.parsers != []:
            pids = [parser[1].pid for parser in self.parsers]
            self.logger.warning(f"Was trying to start parsers, but there were already some parsers, their pids: {pids}. Terminating them.")
            for parser in self.parsers:
                parser[1].terminate()
            self.parsers = []

        if len(self.state["target"]) == 0:
            self.logger.error("Did not start the parsers because target is empty! Set it with ContiniousParser.set_target().")
            return False

        self.generate_task_stack()

        self.parsers = [self.create_parser() for i in range(parser_count)]
        pids = [parser[1].pid for parser in self.parsers]
        self.logger.info(f"Successfully started {parser_count} parsers. Their pids are: {pids}")

        return True

    def restart_parser(self, i: int, restart_timeout: int = 10) -> bool:
        timed_out_parser = self.parsers.pop(i)
        timed_out_task = timed_out_parser[3][:]
        old_pid = timed_out_parser[1].pid if timed_out_parser[1].is_alive() else None
        timed_out_parser[1].terminate()

        self.task_stack += timed_out_task
        self.logger.info(f"Put timed out task {timed_out_task} back to the task stack.")
        new_parser = self.create_parser()

        if new_parser[1].is_alive():
            self.parsers.append(new_parser)
            self.logger.info(f"Successfully restarted parser (pid {old_pid}). New pid is {new_parser[1].pid}.")
            return True

        self.logger.error(f"Failed to restart timed out parser (pid {old_pid}) with task {timed_out_task}.")
        return False

    def refill_parsers(self, parser_count: int) -> bool:
        self.logger.warning(f"We are lacking parsers! Current amount is {len(self.parsers)}, not {parser_count}.")
        for i in range(parser_count - len(self.parsers)):

            new_parser = self.create_parser()
            if new_parser[1].is_alive():
                self.parsers.append(new_parser)
                self.logger.info(f"Succesfully added a new parser with pid {new_parser[1].pid}.")

            else:
                self.logger.warning(f"Failed to add a new parser.")

        self.logger.info(f"Current amount of parsers: {len(self.parsers)}")
        return len(self.parsers) == parser_count


    def assign_tasks(self) -> bool:

        if len(self.parsers) == 0:
            self.logger.error("No tasks were assigned because there are no parsers!")
            return False

        to_return = False
        BATCH_SIZE = 1
        PARSER_TIMEOUT = BATCH_SIZE * 30 # usually one block is parsed in ~7 seconds, so 30 can be assumed as timeout.
        for i, parser in enumerate(self.parsers):

            pipe_conn = parser[2]
            if not pipe_conn.poll():
                if time.time() - parser[4] > PARSER_TIMEOUT:
                    self.logger.error(f"Parser (pid {parser[1].pid}) timed out.")
                    self.restart_parser(i)
                continue

            parser_response = pipe_conn.recv()
            if parser_response == 0: # Parser finished it's work
                parser[1].join()
                self.logger.info(f"Joined parser (pid {parser[1].pid}) with exitcode {parser[1].exitcode}")
                self.parsers.remove(parser)
                return False

            assert parser[3] == parser_response[0]  # otherwise parsed what we wanted it to parse.
            self.update_block_state(parser_response[0])
            self.update_statistics(parser_response[1])

            if len(self.task_stack) == 0:
                self.logger.info(f"No tasks were assigned because the task stack is empty! {len(self.parsers)} parsers still working.")
                pipe_conn.send(0)
                return False

            if len(self.task_stack) >= BATCH_SIZE:
                task = [self.task_stack.pop() for i in range(BATCH_SIZE)]
            else:
                task = self.task_stack[:]
                self.task_stack = []

            pipe_conn.send(task)
            parser[3] = task
            parser[4] = time.time()
            to_return = True

        return to_return


    def update_statistics(self, statistics: dict) -> None:
        for key, value in statistics.items():
            self.state[key] += value

    def update_block_state(self, completed_task: set) -> None:
        self.state["parsed"] += completed_task

    def print_speed(self, start_timestamp) -> None:
        time_diff = int(time.time() - start_timestamp)
        self.logger.info(f"Running for {str(timedelta(seconds=time_diff))} and gathered {self.state['keys']} keys ({self.state['keys'] // time_diff} keys/sec).")

    def print_state(self) -> None:
        for key, value in self.state.items():
            if key != "target" and key != "parsed":
                print(f"{key}: {value}")


    def all_tasks_done(self) -> None:
        for i, parser in enumerate(self.parsers):
            parser[1].join()
            self.logger.info(f"Joined parser (pid {parser[1].pid}) with exitcode {parser[1].exitcode}")
        self.parsers = []

        print("-------[SUCCESS]-------")
        self.print_state()
        self.flush_state_to_file()


    def flush_state_to_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "w") as file:
                json.dump(self.state, file, indent = 2)

        except Exception as e:
            self.logger.error("Could not flush the state to a file.")
            return False

        self.logger.info("Flushed the state to the file.")
        return True


    def restore_state_from_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "r") as file:
                self.state = json.load(file)

        except Exception as e:
            self.logger.error("Could not restrore the state from a file.")
            return False

        self.logger.info("Restored state from the file.")
        return True


    def recover(self, parser_count: int = os.cpu_count()) -> bool:
        self.logger.warning("Started recovery.")
        RECOVERY_TRIES = 5

        for i in range(RECOVERY_TRIES):

            if self.restore_state_from_file() and self.start_parsers(parser_count):
                self.generate_task_stack()
                self.logger.info("Successfull recovery.")
                return True
            time.sleep(10)

        self.logger.error("Failed recovery.")
        return False


    def send_email_on_event(self, event: str) -> bool:
        #TODO
        pass


    """
        "Main" functions
    """

    def parse_range(self, range_to_parse: range, parser_count: int = os.cpu_count()) -> bool:
        self.set_target(range_to_parse)

        if not self.start_parsers(parser_count):
            self.logger.error("Could not start parsers!")
            return False

        FAILURE_TOLERANCE = 3
        for i in range(FAILURE_TOLERANCE + 1): # parse (1), recover (2), repeat

            start_timestamp = time.time()
            try:
                while True: #(1)

                    assigned_some_tasks = self.assign_tasks()

                    if not assigned_some_tasks and set(self.state["target"]) == set(self.state["parsed"]):
                        self.all_tasks_done()
                        return True

                    # Backup state to file every 5 minutes
                    if int(time.time()) % (60*5) == 0:
                        self.flush_state_to_file()

                    # Print progress every 10 minutes
                    if int(time.time()) % (60*10) == 0:
                        self.print_speed(start_timestamp)

                    if len(self.parsers) < parser_count and len(self.task_stack) > 0:
                        self.refill_parsers(parser_count)

                    time.sleep(1)

            except Exception as e: #(2)

                self.logger.exception("Something went wrong. We are outside `parse` loop.")

                if i == FAILURE_TOLERANCE:
                    break

                if not self.recover(parser_count):
                    self.send_email_on_event("recover_failure")
                    return False

        self.logger.critical("Failure tolerance exceeded (failed {FAILURE_TOLERANCE} times) - exiting the script.")
        for parser in self.parsers:
            parser[1].terminate()
            self.logger.warning(f"Teminated parser (pid {parser[1].pid}) because the script exceeded failure tolerance.")
        return False

    def parse_forever():
        # TODO
        pass


if __name__ == "__main__":
    cp = ContiniousParser()
    cp.parse_range(range(739000, 739010), 4)
