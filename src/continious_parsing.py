#!/bin/python3

import os, sys, time, traceback
import json
from threading import Thread
from multiprocessing import Process, Pipe

from parse import Parser, RPC

class ContiniousParser:

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

    # [[parser1, process1, pipe1_conn, task1], [parser2, process2, pipe2_conn, task2], ..]
    parsers = []
    task_stack = []

    def set_target(self, target: range) -> None:
        self.state["target"] = list(target)

    def generate_task_stack(self):
        self.task_stack = list(set(self.state["target"]) - set(self.state["parsed"]))
        self.task_stack.reverse()

    def start_parsers(self, parser_count:int=os.cpu_count()) -> bool:

        if len(self.state["target"]) == 0:
            print("[ERROR] Did not start the parsers because target is empty! Set it with ContiniousParser.set_target().", file = sys.stderr)
            return False

        self.generate_task_stack()

        for i in range(parser_count):
            parser = Parser(self.rpc)
            parent_conn, child_conn = Pipe()
            process = Process(target=parser.process_blocks_from_pipe, args=(child_conn,))
            process.start()
            self.parsers.append([parser, process, parent_conn, []])

        return True


    def assign_tasks(self) -> bool:

        if len(self.parsers) == 0:
            print("No tasks were assigned because there are no parsers!")
            return False

        BATCH_SIZE = 1
        for parser in self.parsers:

            pipe_conn = parser[2]
            if not pipe_conn.poll():
                continue

            parser_response = pipe_conn.recv()
            if parser_response == 0: # Parser finished it's work
                parser[1].join()
                self.parsers.remove(parser)
                return False

            assert parser[3] == parser_response[0]  # otherwise parsed what we wanted it to parse.
            self.update_block_state(parser_response[0])
            self.update_statistics(parser_response[1])

            if len(self.task_stack) == 0:
                print("No tasks were assigned because the task stack is empty!")
                pipe_conn.send(0)
                return False

            if len(self.task_stack) >= BATCH_SIZE:
                task = [self.task_stack.pop() for i in range(BATCH_SIZE)]
            else:
                task = self.task_stack[:]
                self.task_stack = []

            pipe_conn.send(task)
            parser[3] = task


    def update_statistics(self, statistics: dict) -> None:
        for key, value in statistics.items():
            self.state[key] += value

    def update_block_state(self, completed_task: set) -> None:
        self.state["parsed"] += completed_task

    def measure_speed(self) -> None:
        MEASURMENT_DURATION = 60*5
        temp_keys = self.state["keys"]
        time.sleep(MEASURMENT_DURATION) # we can afford sleep() because we call this function in a separate thread.
        print(f"Speed: {(self.state['keys'] - temp_keys) // MEASURMENT_DURATION} keys/sec.")

    def print_state(self) -> None:
        for key, value in self.state.items():
            if key != "target" and key != "parsed":
                print(f"{key}: {value}")


    def flush_state_to_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "w") as file:
                json.dump(self.state, file, indent = 2)

        except Exception as e:
            print("[ERROR] Could not flush the state to a file:\n", e, file = sys.stderr)
            return False

        return True


    def restore_state_from_file(self) -> bool:
        try:
            with open(self.STATE_FILE, "r") as file:
                self.state = json.load(file)

        except Exception as e:
            print("[ERROR] Could not restrore the state from a file:\n", e, file = sys.stderr)
            return False

        return True


    def recover(self) -> bool:
        print("-------RECOVERING-------")
        RECOVER_TIMEOUT = 20
        start_time = int(time.time())

        while time.time() - start_time < RECOVER_TIMEOUT:
            if self.restore_state_from_file() and self.start_parsers():
                self.generate_task_stack()
                print("[RECOVERING] Success!")
                return True


    def send_email_on_event(self, event: str) -> bool:
        #TODO
        pass


    """
        "Main" functions
    """

    def parse_range(self, range_to_parse: range, parser_count:int=os.cpu_count()) -> bool:
        self.set_target(range(739000, 739010))

        if not self.start_parsers(parser_count):
            print("[ERROR] Could not start parsers!", file = sys.stderr)
            exit(1)

        while True: # parse (1), recover (2), repeat

            try:
                while True: #(1)

                    assigned_some_tasks = self.assign_tasks()

                    # If all tasks are done
                    if not assigned_some_tasks and (set(self.state["target"]) == set(self.state["parsed"])):
                        print("-------[SUCCESS]-------")
                        self.print_state()
                        self.flush_state_to_file()

                        for parser in self.parsers:
                            parser[1].join()
                        return True

                    # Backup state to file every 5 minutes
                    if int(time.time()) % (60*5) == 0:
                        self.flush_state_to_file()

                    # Measure speed every 10 minutes
                    """
                    if int(time.time()) % (60*10) == 0:
                        t = Thread(target=self.measure_speed())
                        t.daemon = True
                        t.start()
                    """
                    time.sleep(1)

            except Exception as e: #(2)

                print("-------[FAILURE]-------")
                traceback.print_exc()

                if not self.recover():
                    print("[ERROR] Could not recover after failure!", file = sys.stderr)
                    self.send_email_on_event("recover_failure")
                    return False

if __name__ == "__main__":
    cp = ContiniousParser()
    cp.parse_range(range(739000, 739010), 4)
