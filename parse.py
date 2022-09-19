#!/usr/bin/python3

import bitcoin, bitcoin.rpc, struct, time, os, json

class Parser:

    # change path to bitcoin.conf if you have different data structure
    # raw Proxy takes commands in hexa strings instead of structs, that is what we need
    bitcoin.SelectParams("mainnet")  # we will be using the production blockchain
    rpc = bitcoin.rpc.RawProxy(btc_conf_file="/home/xyakimo1/crocs/.bitcoin-data/bitcoin.conf")

    blocks = 0              # Number of blocks, that were passed to the script. Same with transactions, inputs (vin's) and outputs (vout's).
    transactions = 0
    inputs = 0
    outputs = 0

    failed_inputs = 0       # Number of transaction inputs, in which we weren't able to find any public keys.
    failed_outputs = 0      # Same, but only failed P2PK and P2TR outputs count (, because other types don't even have public keys in it).
    ecdsa = 0
    schnorr = 0
    keys = 0

    import op_codes
    OP_CODES = op_codes.OP_CODES

    def print_statistics(self, start_time):
        print("\n", "=" * os.get_terminal_size().columns, sep = '')
        print ("Gathered ", self.keys, " keys: ", self.ecdsa, " ECDSA keys, ", \
                self.schnorr," Schnorr Signature keys; in ", time.perf_counter() - start_time, " seconds.")
        print("Failed to parse ", self.failed_inputs, " inputs ( {:0.2f}".format(self.failed_inputs/self.inputs*100),\
               "%) and ", self.failed_outputs, " outputs ( {:0.2f}".format(self.failed_outputs/self.outputs*100), "%).")
        print("=" * os.get_terminal_size().columns)


    ecdsa_data = {}
    unmatched_ecdsa_data = {}
    schnorr_data = {}
    unmatched_schnorr_data = {}

    DICTS = [(ecdsa_data, "ecdsa_data"), (unmatched_ecdsa_data, "unmatched_ecdsa_data"),\
             (schnorr_data, "schnorr_data"), (unmatched_schnorr_data, "unmatched_schnorr_data")]

    ECDSA_SIG_LENGTHS = (146, 144, 142)   # Lengths of symbols in hex-encoded string. Divide by two and get number of bytes.
    ECDSA_PUBKEY_LENGTHS = (66, 130)

    # Schnorr signature in bitcoin itself is always 64 bytes, but it's possible to set non-default hash_type in 65th byte.
    #                                                                                   (see BIP341 - Common signature message)
    SCHNORR_SIG_LENGTHS = (128, 130)
    SCHNORR_PUBKEY_LENGTH = 64

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
            if signature[-1] not in ('0', '1', '2', '3'):
                return False

        return True


    def increment_key_count(self, suspected_key):
        if len(suspected_key) in self.ECDSA_PUBKEY_LENGTHS:
            self.ecdsa += 1
        if len(suspected_key) == self.SCHNORR_PUBKEY_LENGTH:
            self.schnorr += 1
        self.keys += 1

    def add_key_to_data_dict(self, transaction, suspected_key, signature, data_dict):
        if suspected_key not in data_dict.keys():
            self.increment_key_count(suspected_key)
            data_dict[suspected_key] = []
        data_dict[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})

    def add_key_to_unmatched_data_dict(self, transaction, suspected_key, sigs, data_dict):
        if suspected_key not in data_dict.keys():
            self.increment_key_count(suspected_key)
            data_dict[suspected_key] = []
        data_dict[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})


    def extract_signature_p2pk_p2pkh(self, vin):

        signature = vin['scriptSig']['hex']
        length = int(signature[:2], 16) # len of signature in bytes
        signature = signature[2: 2 + length*2]

        if not self.correct_ecdsa_signature(signature):
            signature = "NaN"

        return signature


    # This function tries to process a Pay to Public Key Hash transaction
    # ScriptSig: contains signature and public key
    # Locking script: contains hash of public key
    # returns true if key was extracted
    def process_input_p2pkh(self, transaction, vin):

        if not 'scriptSig' in vin.keys() or len(vin['scriptSig']['asm'].split(" ")) != 2:
            return False
 
        suspected_key = vin['scriptSig']['asm'].split(" ")[1]
        if not self.correct_ecdsa_key(suspected_key):
            return False

        signature = self.extract_signature_p2pk_p2pkh(vin)

        self.add_key_to_data_dict(transaction, suspected_key, signature, self.ecdsa_data)
        return True


    # This function tries to process a Pay to Public Key transaction. Those are mostly old transaction mining BTC
    # ScriptSig: Either not here (mining) or includes signature
    # Locking script: contains public key followed by Checksig OP code
    # returns true if key was extracted or if spending of this output was detected and only signature is likely present. Other extractors MUST run prior in case output has something valuable

    def get_previous_vout(self, vin):
        prev_transaction_id = vin["txid"]
        prev_transaction = self.rpc.getrawtransaction(prev_transaction_id, True)
        vout_num = vin["vout"]
        vout = prev_transaction["vout"][vout_num]
        return vout

    def process_input_p2pk(self, transaction, vin):
        if not 'scriptSig' in vin.keys() or len(vin["scriptSig"]["asm"]) < 2: # 2nd statement is to not pass empty strings
            return False

        signature = self.extract_signature_p2pk_p2pkh(vin)
        if signature == "NaN": # If there is no signature, there is no sense in looking up the corresponding public key.
            return False

        vout = self.get_previous_vout(vin)
        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[0]

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(transaction, suspected_key, signature, self.ecdsa_data)
        return True


    def process_output_p2pk(self, transaction, vout):

        if not 'scriptPubKey' in vout.keys() or len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) < 2:
            return False

        suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]
        signature = "NaN"

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(transaction, suspected_key, signature, self.ecdsa_data)
        return True


    # This function tries to process a Pay to Script hash transaction. This is a newer type of transaction with seceral subtypes
    # ScriptSig: Contains signatures. Last entry is the unlocking script that needs to be further parsed to extract public key
    # Locking script: contains a few instructions and hash of script that unlocks the spending
    # returns true if key was extracted
    def process_input_p2sh(self, transaction, vin):

        if not 'scriptSig' in vin.keys() or len(vin['scriptSig']['asm'].split(" ")) < 2:
            return False

        temp_stack = self.load_stack(vin['scriptSig']['hex'], [])
        temp_stack.reverse() # Later load_stack will be called again from parse_serialized_script(), so "unreverse" now.
        print(temp_stack)
        if len(temp_stack) < 2:
            return False

        script = temp_stack[-1]
        inputs = temp_stack[:-1]
        return self.parse_serialized_script(transaction, script, inputs)


    def extract_signature_p2wpkh(self, vin):
        if not "txinwitness" in vin.keys() or len(vin["txinwitness"]) < 2:
            return "NaN"

        signature = vin['txinwitness'][0]
        if not self.correct_ecdsa_signature(signature):
            signature = "NaN"
        return signature

    # This function tries to process a Pay to Witness Public Key transaction. Those are new SegWit transactions
    # We do not care about scriptPubKey or Sigscript in this case
    # Segwith contains signature and public key
    # returns true if key was extracted
    def process_input_p2wpkh(self, transaction, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) < 2:
            return False

        suspected_key = vin['txinwitness'][1]
        signature = self.extract_signature_p2wpkh(vin)

        if not self.correct_ecdsa_key(suspected_key):
            return False

        self.add_key_to_data_dict(transaction, suspected_key, signature, self.ecdsa_data)
        return True


    # This function tries to process a Pay to Witness Script Hash transaction. Those are very new SegWit transactions for Lightning L2 transactions underlaying settlement
    # Segwith contains signature(s) and script
    # returns true if key was extracted
    def process_input_p2wsh(self, transaction, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) < 2:
            return False

        script = vin['txinwitness'][-1]
        inputs = vin['txinwitness'][:-1]
        return self.parse_serialized_script(transaction, script, inputs)


    def extract_signature_p2tr(self, vin, i):
        if not "txinwitness" in vin.keys() or len(vin["txinwitness"]) <= i:
            return "NaN"

        signature = vin['txinwitness'][i]

        if not self.correct_schnorr_signature(signature):
            signature = "NaN"

        if len(signature) == 130:
            signature = signature[:-2]  # Removing 'hash_type' byte (BIP341 - Common signature message)

        return signature


    def handle_p2tr_keypath(self, transaction, vin):
        signature = self.extract_signature_p2tr(vin, 0)
        vout = self.get_previous_vout(vin)

        if "scriptPubKey" not in vout.keys():
            return False                                                    # This two if's are not necessary,
                                                                            # but if you are as pedantic as I am, you can leave them.
        if vout["scriptPubKey"]["type"] != "witness_v1_taproot":
            return False

        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[-1]  # As far as I'm concerned, there are always 2 elements.
                                                                    # The first one, I guess, is a version byte.
                                                                    # And the second one is a public key.

        if not self.correct_schnorr_key(suspected_key):
            return False

        self.add_key_to_data_dict(transaction, suspected_key, signature, self.schnorr_data)
        return True


    def handle_p2tr_scriptpath(self, transaction, vin):
        toreturn = False
        if len(vin['txinwitness']) < 3: # Should contain at least three things: some inputs for a script, the script and a control block.
            return toreturn

        control_block = vin['txinwitness'][-1]
        if (len(control_block) - 2) % 64 != 0: # "control block .. must have length 33 + 32m .. Fail if it does not have such a length." - BIP341
            return toreturn

        control_block = control_block[2:] # We don't need a leaf version and a sign bit, which are stored in the first byte.
        suspected_key = control_block[:64]

        if self.correct_schnorr_key(suspected_key):
            self.add_key_to_data_dict(transaction, suspected_key, "NaN", self.schnorr_data)
            toreturn = True

        script = vin["txinwitness"][-2]
        inputs = vin["txinwitness"][:-2]
        if self.parse_serialized_script(transaction, script, inputs):
            print("Successful P2TR [SCRIPT]!!! TXID:", transaction["txid"])
            toreturn = True

        return toreturn

    def process_output_p2tr(self, transaction, vout):

        if (not "scriptPubKey" in vout.keys()) or (len(vout["scriptPubKey"]["asm"].split(' ')) != 2):
            return False

        scriptpubkey = vout["scriptPubKey"]["asm"].split(' ')
        if scriptpubkey[0] != '1': # Version byte
            return False

        suspected_key = scriptpubkey[1]
        if not self.correct_schnorr_key(suspected_key):
            return False

        self.add_key_to_data_dict(transaction, suspected_key, "NaN", self.schnorr_data)
        return True


    # Essential to read. From Pieter Wuille, author of P2TR.
    """ https://bitcoin.stackexchange.com/questions/107154/what-is-the-control-block-in-taproot/107159#107159 """
    def process_input_p2tr(self, transaction, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) == 0:
            return False

        if len(vin['txinwitness']) == 1 and len(vin['txinwitness'][0]) in self.SCHNORR_SIG_LENGTHS:
            return self.handle_p2tr_keypath(transaction, vin)

        return self.handle_p2tr_scriptpath(transaction, vin)


    def data_dict_full(self, data_dict):
        # Maximum key count to store in RAM before flushing to JSON. You can set much more, depends on your RAM size.
        # Guess it, or use my formula below.
        # Note that 400 B - average length of key record in JSON format (including pubkey, txid, time and sig)

        #RAM_SIZE = 6    # place amount of RAM in GB, that you want to dedicate to the script.
        #max_key_count = RAM_SIZE * 1024 * 1024 / 400
        max_key_count = 10000

        return len(data_dict) >= max_key_count

    # Flushes collected data to a JSON file.
    def flush_data_dict(self, file_name, data_dict):
        with open(file_name, 'w') as outfile:
            json.dump(data_dict, outfile, indent = 2)
        data_dict = {}

    # This functions goes trough all data dictionaries and checks, whether they need to be flushed.
    # Argument <exception> is a bool value to force flushing: for example, at the very end of the script
    def flush_if_needed(self, n, exception):
        for dict_tup in self.DICTS: 
            if self.data_dict_full(dict_tup[0]) or (exception and dict_tup[0] != {}):
                file_name = "gathered-data/" + dict_tup[1] + "_" + str(n) + ".txt"
                self.flush_data_dict(file_name, dict_tup[0])


    def process_inputs(self, transaction):
        for i in range(len(transaction["vin"])):
            vin = transaction["vin"][i]
            self.inputs += 1
            try:

                # Run all extractors in turn, stop on success.
                if not (self.process_input_p2wpkh(transaction, vin) or \
                        self.process_input_p2wsh(transaction, vin) or \
                        self.process_input_p2tr(transaction, vin) or \
                        self.process_input_p2sh(transaction, vin) or \
                        self.process_input_p2pkh(transaction, vin) or \
                        self.process_input_p2pk(transaction, vin) or \
                        ('coinbase' in transaction['vin'][0].keys())): # Coinbase input, so don't count as failed.

                    self.failed_inputs += 1
                    print("Failed transaction input: ", transaction["txid"], ":", i, sep = '')

            except (ValueError, IndexError) as e:
                self.failed_inputs += 1
                print("Failed transaction input: ", transaction["txid"], ":", i, sep = '')



    def process_outputs(self, transaction):
        for i in range(len(transaction["vout"])):
            vout = transaction["vout"][i]
            self.outputs += 1

            if (vout["scriptPubKey"]["type"] == "pubkey" and not self.process_output_p2pk(transaction, vout)) or \
               (vout["scriptPubKey"]["type"] == "witness_v1_taproot" and not self.process_output_p2tr(transaction, vout)):
                self.failed_outputs += 1
                print("Failed transaction output: ", transaction["txid"], ":", i, sep = '')

    def process_block(self, n):
        self.blocks += 1
        block_hash = self.rpc.getblockhash(n)
        block_transactions = self.rpc.getblock(block_hash)['tx']

        for transaction_hash in block_transactions:

            self.transactions += 1
            transaction = self.rpc.getrawtransaction(transaction_hash, True) # Getting transaction in verbose format

            self.process_inputs(transaction)
            self.process_outputs(transaction)


    # Main functions, takes natural numbers start, end which are the indexes of Bitcoin blocks
    # if start is 0, then the parsing starts at the genesis block
    def process_blocks(self, start, end):

        for n in range(start, end):
            self.process_block(n)
            self.flush_if_needed(n, False)

        self.flush_if_needed(n, True)



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

        stack.reverse()
        return stack # we want to use list.pop() later


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

            print("Unknown stack item:", item)
            #return False

        return ecdsa_keys, ecdsa_sigs, schnorr_keys, schnorr_sigs


    def parse_serialized_script(self, transaction, script, inputs):
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
                self.add_key_to_data_dict(transaction, ecdsa_keys[0], ecdsa_sigs[0], self.ecdsa_data)
            else:
                for key in ecdsa_keys:
                    self.add_key_to_unmatched_data_dict(transaction, key, ecdsa_sigs, self.unmatched_ecdsa_data)

        if len(schnorr_keys) > 0:
            if len(schnorr_keys) == 1 and len(schnorr_sigs) == 1:
                self.add_key_to_data_dict(transaction, schnorr_keys[0], schnorr_sigs[0], self.schnorr_data)
            else:
                for key in ecdsa_keys:
                    self.add_key_to_unmatched_data_dict(transaction, key, schnorr_sigs, self.unmatched_schnorr_data)

        return True

#Example of use:
if __name__ == "__main__":
    parser = Parser()
    #start_time = time.perf_counter()
    #parser.process_blocks(739000, 739001)
    #parser.print_statistics(start_time)
    stack = parser.load_stack("20f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac", ["7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"])
    print(stack)
