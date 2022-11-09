#!/usr/bin/python3

import bitcoin.rpc, json    # basic functionality
import sys                  # argv
import time, os             # Parser.print_statistics()

class RPC:
    bitcoin.SelectParams("mainnet")
    rpc = bitcoin.rpc.RawProxy() # RawProxy takes commands in hexa strings instead of structs, that is what we need

class Parser:

    """
        "Constants"
    """
    import op_codes
    OP_CODES = op_codes.OP_CODES


    ECDSA_SIG_LENGTHS = (146, 144, 142, 140, 138)   # Lengths of symbols in hex-encoded string. Divide by two and get number of bytes.
    ECDSA_PUBKEY_LENGTHS = (66, 130)

    # Schnorr signature in bitcoin itself is always 64 bytes, but it's possible to set non-default hash_type in 65th byte.
    #                                                                                   (see BIP341 - Common signature message)
    SCHNORR_SIG_LENGTHS = (128, 130)
    SCHNORR_PUBKEY_LENGTH = 64


    def __init__(self, RPC: object):
        self.rpc = RPC.rpc
        self.state = {"txid": "", "vin/vout": "", "n": -1} # Holds info about what is currently being parsed.
        self.start_time = time.time()

        self.statistics = \
        {
            "blocks": 0,         # Number of blocks, that were passed to the script. Same with transactions, inputs (vin's) and outputs (vout's).
            "transactions": 0,
            "inputs": 0,
            "outputs": 0,

            "failed_inputs": 0,  # Number of transaction inputs, in which we weren't able to find any public keys.
            "failed_outputs": 0, # Same, but only failed P2PK and P2TR outputs count (, because other types don't even have public keys in it).
            "ecdsa": 0,
            "schnorr": 0,
            "keys": 0
        }

        self.ecdsa_data = {}
        self.unmatched_ecdsa_data = {}
        self.schnorr_data = {}
        self.unmatched_schnorr_data = {}

        self.DICTS = [(self.ecdsa_data, "ecdsa_data"), (self.unmatched_ecdsa_data, "unmatched_ecdsa_data"),\
                      (self.schnorr_data, "schnorr_data"), (self.unmatched_schnorr_data, "unmatched_schnorr_data")]

        self.failed_inputs_list = []
        self.failed_outputs_list = []

        self.LISTS = [(self.failed_inputs_list, "failed_inputs"), (self.failed_outputs_list, "failed_outputs")]

    """
        "Print" functions
    """

    def print_statistics(self):
        try:
            print("\n", "=" * os.get_terminal_size().columns, sep = '')
        except:
            print("=============")
        print ("Gathered ", self.statistics["keys"], " keys: ", self.statistics["ecdsa"], " ECDSA keys, ", \
                self.statistics["schnorr"]," Schnorr Signature keys; in ", time.time() - self.start_time, " seconds.")
        print("Failed to parse ", self.statistics["failed_inputs"], " inputs ( {:0.2f}".format(self.statistics["failed_inputs"]/self.statistics["inputs"]*100),\
               "%) and ", self.statistics["failed_outputs"], " outputs ( {:0.2f}".format(self.statistics["failed_outputs"]/self.statistics["outputs"]*100), "%).")
        try:
            print("=" * os.get_terminal_size().columns)
        except:
            print("=============")

    def show_dict(self, dictionary):
        print(json.dumps(dictionary, indent = 2))

    def print_speed(self):
        print("Speed: {:0.2f} keys/sec".format(self.statistics["keys"]/(time.time() - self.start_time)))


    """
        Different "Helping" functions.
    """

    def get_previous_vout(self, vin):
        prev_transaction_id = vin["txid"]
        prev_transaction = self.rpc.getrawtransaction(prev_transaction_id, True)
        vout_num = vin["vout"]
        vout = prev_transaction["vout"][vout_num]
        return vout


    def increment_key_count(self, suspected_key):
        if len(suspected_key) in self.ECDSA_PUBKEY_LENGTHS:
            self.statistics["ecdsa"] += 1
        if len(suspected_key) == self.SCHNORR_PUBKEY_LENGTH:
            self.statistics["schnorr"] += 1
        self.statistics["keys"] += 1


    def reset_statistics(self):
        for key in self.statistics.keys():
            self.statistics[key] = 0


    """
        "Correct" keys and signatures functions
    """

    def correct_ecdsa_key(self, suspected_key):

        if len(suspected_key) not in self.ECDSA_PUBKEY_LENGTHS:
            return False
        if suspected_key[0] != '0':
            return False

        if suspected_key[1] in ('2', '3') and len(suspected_key) == 66:
            return True

        if suspected_key[1] == '4' and len(suspected_key) == 130:
            return True

        return False

    def correct_ecdsa_signature(self, signature):
        if len(signature) not in self.ECDSA_SIG_LENGTHS:
            return False

        if signature[:2] != "30" or signature[4:6] != "02":
            return False

        if signature[2] != '4': # Length of following data in one byte. Just check that it's about 0x40.
            return False

        return True

    def correct_schnorr_key(self, suspected_key):
        return len(suspected_key) == self.SCHNORR_PUBKEY_LENGTH

    def correct_schnorr_signature(self, signature):
        if len(signature) not in self.SCHNORR_SIG_LENGTHS:
            return False

        if len(signature) == 130:
            if signature[-2] != '0' and signature[-2] != '8':
                return False
            if signature[-1] not in ('0', '1', '2', '3'): # Checking non-default hash_type to be valid.
                return False

        return True


    """
        "Data" handling functions
    """

    def add_key_to_data_dict(self, suspected_key, signature, data_dict):
        if suspected_key not in data_dict.keys():
            self.increment_key_count(suspected_key)
            data_dict[suspected_key] = []
        assert self.state["txid"] != "" and self.state["vin/vout"] != "" and self.state["n"] != -1
        data_dict[suspected_key].append({'ID' : self.state["txid"], 'vin/vout': self.state["vin/vout"]+' '+str(self.state["n"]), 'signature' : signature})


    def add_key_to_unmatched_data_dict(self, suspected_key, sigs, data_dict):
        if suspected_key not in data_dict.keys():
            self.increment_key_count(suspected_key)
            data_dict[suspected_key] = []
        assert self.state["txid"] != "" and self.state["vin/vout"] != "" and self.state["n"] != -1
        data_dict[suspected_key].append({'ID' : self.state['txid'], 'vin/vout': self.state["vin/vout"]+' '+str(self.state["n"]), 'signatures' : sigs})


    def data_dict_full(self, data_dict):
        # Maximum key count to store in RAM before flushing to JSON. You can set much more, depends on your RAM size.
        # Average length of key record in JSON format is ~300B.
        max_key_count = 10000
        return len(data_dict) >= max_key_count


    # Flushes collected data to a JSON file.
    def flush_data_dict(self, file_name, data_dict):
        with open(file_name, 'w') as outfile:
            json.dump(data_dict, outfile, indent = 2)
        data_dict = {}

    def flush_data_list(self, file_name, data_list):
        with open(file_name, 'w') as outfile:
            for line in data_list:
                outfile.write(line + '\n')
        data_list = []

    # This functions goes trough all data dictionaries and checks, whether they need to be flushed.
    # Argument <exception> is a bool value to force flushing: for example, at the very end of the script.
    def flush_if_needed(self, n, exception):
        for dict_tup in self.DICTS: 
            if self.data_dict_full(dict_tup[0]) or (exception and dict_tup[0] != {}):
                file_name = "gathered-data/" + dict_tup[1] + "_" + str(n) + ".txt"
                self.flush_data_dict(file_name, dict_tup[0])

        for list_tup in self.LISTS:
            if self.data_dict_full(list_tup[0]) or (exception and list_tup[0] != []):
                file_name = "gathered-data/" + list_tup[1] + "_" + str(n) + ".txt"
                self.flush_data_list(file_name, list_tup[0])


    """
        "Extract" signature functions
    """

    def extract_signature_p2pk_p2pkh(self, vin):

        signature = vin['scriptSig']['hex']
        length = int(signature[:2], 16) # len of signature in bytes
        signature = signature[2: 2 + length*2]

        if not self.correct_ecdsa_signature(signature):
            signature = "NaN"

        return signature


    def extract_signature_p2wpkh(self, vin):
        if not "txinwitness" in vin.keys() or len(vin["txinwitness"]) < 2:
            return "NaN"

        signature = vin['txinwitness'][0]
        if not self.correct_ecdsa_signature(signature):
            signature = "NaN"
        return signature


    def extract_signature_p2tr(self, vin, i):
        if not "txinwitness" in vin.keys() or len(vin["txinwitness"]) <= i:
            return "NaN"

        signature = vin['txinwitness'][i]

        if not self.correct_schnorr_signature(signature):
            signature = "NaN"

        return signature


    """
        Serialized "Script" functions.
    """

    def load_stack_helper(self, script, stack) -> tuple:
        if len(script) < 2:
            return None, None
        command = script[:2]
        script = script[2:]

        # Non-push codes
        for hex_op in self.OP_CODES.keys():
            if command == hex_op:
                stack.append(self.OP_CODES[hex_op])
                return script, stack

        # OP_PUSHBYTES
        try:
            int(command, 16)
        except:
            print("Invalid script command '", command, "'", sep = '')
            return None, None

        length = int(command, 16) # Length in bytes
        if length < 76: # For values bigger than 76 bytes OP_PUSHDATA codes are used.
            length *= 2 # One byte is two letters in hex-encoded strings.
            stack.append(script[:length])
            script = script[length:]
            return script, stack

        # OP_PUSHDATA
        if command == "4c": # OP_PUSHDATA1
            length = int(script[:2], 16) * 2
            script = script[2:]
        if command == "4d": # OP_PUSHDATA2
            length = int(script[:4], 16) * 2
            script = script[4:]
        if command == "4e": # OP_PUSHDATA4
            length = int(script[:8], 16) * 2
            script = script[8:]

        if len(script) < length: # Supposed to never happen, but just to be sure.
            return None, None

        stack.append(script[:length])
        script = script[length:]
        return script, stack


    def load_stack(self, script, inputs):
        stack = inputs[:]
        while script != "":
            script, stack = self.load_stack_helper(script, stack)
            if script == None or stack == None:
                return []

        stack.reverse() # we want to use list.pop() later
        return stack


    def length_based_parse(self, stack):
        ecdsa_keys = []
        ecdsa_sigs = []
        schnorr_keys = []
        schnorr_sigs = []

        while stack != []:
            item = stack.pop()
            if item[:3] == "OP_":
                continue

            if self.correct_ecdsa_key(item):
                ecdsa_keys.append(item)
                continue

            if self.correct_ecdsa_signature(item):
                ecdsa_sigs.append(item)
                continue

            if self.correct_schnorr_key(item):
                schnorr_keys.append(item)
                continue

            if self.correct_schnorr_signature(item):
                schnorr_sigs.append(item)
                continue

            #print("Unknown stack item:", item)
            #return False

        return ecdsa_keys, ecdsa_sigs, schnorr_keys, schnorr_sigs


    def parse_serialized_script(self, script, inputs):
        stack = self.load_stack(script, inputs)
        temp_tuple = self.length_based_parse(stack)

        ecdsa_keys = temp_tuple[0]
        ecdsa_sigs = temp_tuple[1]
        schnorr_keys = temp_tuple[2]
        schnorr_sigs = temp_tuple[3]

        if len(ecdsa_keys) == 0 and len(schnorr_keys) == 0: # If no collected_data
            return False

        if len(ecdsa_keys) > 0:
            if len(ecdsa_keys) == 1 and len(ecdsa_sigs) == 1:
                self.add_key_to_data_dict(ecdsa_keys[0], ecdsa_sigs[0], self.ecdsa_data)
            elif len(ecdsa_keys) == 1 and len(ecdsa_sigs) == 0:
                self.add_key_to_data_dict(ecdsa_keys[0], "NaN", self.ecdsa_data)
            else:
                for key in ecdsa_keys:
                    self.add_key_to_unmatched_data_dict(key, ecdsa_sigs, self.unmatched_ecdsa_data)

        if len(schnorr_keys) > 0:
            if len(schnorr_keys) == 1 and len(schnorr_sigs) == 1:
                self.add_key_to_data_dict(schnorr_keys[0], schnorr_sigs[0], self.schnorr_data)
            elif len(schnorr_keys) == 1 and len(schnorr_sigs) == 0:
                self.add_key_to_data_dict(schnorr_keys[0], "NaN", self.schnorr_data)
            else:
                for key in ecdsa_keys:
                    self.add_key_to_unmatched_data_dict(key, schnorr_sigs, self.unmatched_schnorr_data)

        return True


    """
        Process "Input" functions
    """
    # The following functions return true if at least one key was extracted.

    def process_input_p2pk(self, vin):
        if not 'scriptSig' in vin.keys() or len(vin["scriptSig"]["asm"]) < 2: # 2nd statement is to not pass empty strings
            return False

        signature = self.extract_signature_p2pk_p2pkh(vin)
        if signature == "NaN": # If there is no signature, there is no sense in looking up the corresponding public key.
            return False

        vout = self.get_previous_vout(vin)
        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[0]

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(suspected_key, signature, self.ecdsa_data)
        return True


    def process_input_p2pkh(self, vin):

        if not 'scriptSig' in vin.keys() or len(vin['scriptSig']['asm'].split(" ")) != 2:
            return False
 
        suspected_key = vin['scriptSig']['asm'].split(" ")[1]
        if not self.correct_ecdsa_key(suspected_key):
            return False

        signature = self.extract_signature_p2pk_p2pkh(vin)

        self.add_key_to_data_dict(suspected_key, signature, self.ecdsa_data)
        return True


    def process_input_p2sh(self, vin):

        if not 'scriptSig' in vin.keys() or len(vin['scriptSig']['asm'].split(" ")) < 2:
            return False

        temp_stack = self.load_stack(vin['scriptSig']['hex'], [])
        temp_stack.reverse() # Later load_stack will be called again from parse_serialized_script(), so "unreverse" now.
        if len(temp_stack) < 2:
            return False

        script = temp_stack[-1]
        inputs = temp_stack[:-1]
        return self.parse_serialized_script(script, inputs)


    def process_input_p2wpkh(self, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) < 2:
            return False

        suspected_key = vin['txinwitness'][1]
        signature = self.extract_signature_p2wpkh(vin)

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(suspected_key, signature, self.ecdsa_data)
        return True


    def process_input_p2wsh(self, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) < 2:
            return False

        script = vin['txinwitness'][-1]
        inputs = vin['txinwitness'][:-1]
        return self.parse_serialized_script(script, inputs)


    # You might want to read this answer from Pieter Wuille (author of P2TR).
    """ https://bitcoin.stackexchange.com/questions/107154/what-is-the-control-block-in-taproot/107159#107159 """
    def process_input_p2tr(self, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) == 0:
            return False

        if len(vin['txinwitness']) == 1 and len(vin['txinwitness'][0]) in self.SCHNORR_SIG_LENGTHS:
            return self.handle_p2tr_keypath(vin)

        return self.handle_p2tr_scriptpath(vin)


    def handle_p2tr_keypath(self, vin):
        signature = self.extract_signature_p2tr(vin, 0)
        vout = self.get_previous_vout(vin)

        if "scriptPubKey" not in vout.keys():
            return False                                                    # This two if's are not necessary,
                                                                            # but if you are as pedantic as I am, you can leave them.
        if vout["scriptPubKey"]["type"] != "witness_v1_taproot":
            return False

        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[-1]  # As far as I'm concerned, there are always 2 elements.
                                                                    # The first one should be a version byte.
                                                                    # And the second one is a public key.

        if not self.correct_schnorr_key(suspected_key):
            return False

        self.add_key_to_data_dict(suspected_key, signature, self.schnorr_data)
        return True


    def handle_p2tr_scriptpath(self, vin):
        toreturn = False
        if len(vin['txinwitness']) < 3: # Should contain at least three things: some inputs for a script, the script and a control block.
            return toreturn

        control_block = vin['txinwitness'][-1]
        if (len(control_block) - 2) % 64 != 0: # "control block .. must have length 33 + 32m .. Fail if it does not have such a length." - BIP341
            return toreturn

        control_block = control_block[2:] # We don't need a leaf version and a sign bit, which are stored in the first byte.
        suspected_key = control_block[:64]

        if self.correct_schnorr_key(suspected_key):
            self.add_key_to_data_dict(suspected_key, "NaN", self.schnorr_data)
            toreturn = True

        script = vin["txinwitness"][-2]
        inputs = vin["txinwitness"][:-2]
        if self.parse_serialized_script(script, inputs):
            toreturn = True

        return toreturn


    """
        Process "Output" functions.
    """

    def process_output_p2pk(self, vout):

        if not 'scriptPubKey' in vout.keys() or len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) < 2:
            return False

        suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]
        signature = "NaN"

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(suspected_key, signature, self.ecdsa_data)
        return True


    def process_output_p2tr(self, vout):

        if (not "scriptPubKey" in vout.keys()) or (len(vout["scriptPubKey"]["asm"].split(' ')) != 2):
            return False

        scriptpubkey = vout["scriptPubKey"]["asm"].split(' ')
        if scriptpubkey[0] != '1': # Version byte
            return False

        suspected_key = scriptpubkey[1]
        if not self.correct_schnorr_key(suspected_key):
            return False

        self.add_key_to_data_dict(suspected_key, "NaN", self.schnorr_data)
        return True


    """
        "Main" functions
    """

    def process_transaction(self, txid):
        transaction = self.rpc.getrawtransaction(txid, True) # Getting transaction in verbose format

        self.state["txid"] = txid
        self.statistics["transactions"] += 1

        self.process_inputs(transaction)
        self.process_outputs(transaction)
        return True


    def process_inputs(self, transaction):
        self.state["vin/vout"] = "vin"
        for i in range(len(transaction["vin"])):
            vin = transaction["vin"][i]
            self.state["n"] = i
            self.statistics["inputs"] += 1
            try:

                # Run all extractors in turn, stop on success.
                if not (self.process_input_p2wpkh(vin) or \
                        self.process_input_p2wsh(vin) or \
                        self.process_input_p2tr(vin) or \
                        self.process_input_p2sh(vin) or \
                        self.process_input_p2pkh(vin) or \
                        self.process_input_p2pk(vin) or \
                        ('coinbase' in transaction['vin'][0].keys())): # Coinbase input, so don't count as failed.

                    self.statistics["failed_inputs"] += 1
                    self.failed_inputs_list.append(self.state["txid"] + ':' + str(self.state["n"]))

            except (ValueError, IndexError) as e:
                self.statistics["failed_inputs"] += 1
                self.failed_inputs_list.append(self.state["txid"] + ':' + str(self.state["n"]))


    def process_outputs(self, transaction):
        self.state["vin/vout"] = "vout"
        for i in range(len(transaction["vout"])):
            vout = transaction["vout"][i]
            self.state["n"] = i
            self.statistics["outputs"] += 1

            if (vout["scriptPubKey"]["type"] == "pubkey" and not self.process_output_p2pk(vout)) or \
               (vout["scriptPubKey"]["type"] == "witness_v1_taproot" and not self.process_output_p2tr(vout)):
                self.statistics["failed_outputs"] += 1
                self.failed_outputs_list.append(self.state["txid"] + ':' + str(self.state["n"]))


    def process_block(self, n):
        self.statistics["blocks"] += 1
        block_hash = self.rpc.getblockhash(n)
        block_transactions = self.rpc.getblock(block_hash)['tx']

        for txid in block_transactions:
            self.process_transaction(txid)


    def process_blocks(self, start, end):

        for n in range(start, end):
            self.process_block(n)
            self.flush_if_needed(n, False)

            if n % 10 == 0:
                self.print_speed()

        self.flush_if_needed(n, True)
        self.print_statistics()

    def process_blocks_from_pipe(self, pipe_conn):
        pipe_conn.send(([], {}))  # initiates communication
        while True:

            if not pipe_conn.poll():
                time.sleep(1)
                continue

            task = pipe_conn.recv()
            if task == 0:
                pipe_conn.send(0) # Finished work signal.
                self.flush_if_needed(0, True)
                return True
            assert type(task) == list

            for block_n in task:
                self.process_block(block_n)
                self.flush_if_needed(block_n, False)

            to_send = (task, self.statistics)
            pipe_conn.send(to_send)
            self.reset_statistics()


if __name__ == "__main__":
    rpc = RPC()
    parser = Parser(rpc)
