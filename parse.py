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

    def print_statistics(self, start_time):
        print("\n", "=" * os.get_terminal_size().columns, sep = '')
        print ("Gathered ", Parser.keys, " keys: ", Parser.ecdsa, " ECDSA keys, ", \
                Parser.schnorr," Schnorr Signature keys; in ", time.perf_counter() - start_time, " seconds.")
        print("Failed to parse ", Parser.failed_inputs, " inputs ( {:0.2f}".format(Parser.failed_inputs/Parser.inputs*100),\
               "%) and ", Parser.failed_outputs, " outputs ( {:0.2f}".format(Parser.failed_outputs/Parser.outputs*100), "%).")
        print("=" * os.get_terminal_size().columns)


    ecdsa_data = {}
    unmatched_ecdsa_data = {}
    schnorr_data = {}
    unmatched_schnorr_data = {}

    DICTS = [(ecdsa_data, "ecdsa_data"), (unmatched_ecdsa_data, "unmatched_ecdsa_data"),\
             (schnorr_data, "schnorr_data"), (unmatched_schnorr_data, "unmatched_schnorr_data")]

    ECDSA_SIG_LENGTHS = (148, 146, 144, 142, 140)   # Lengths of symbols in hex-encoded string. Divide by two and get number of bytes.
    ECDSA_PUBKEY_LENGTHS = (66, 130)

    # Schnorr signature in bitcoin itself is always 64 bytes, but it's possible to set non-default hash_type in 65th byte.
    #                                                                                   (see BIP341 - Common signature message)
    SCHNORR_SIG_LENGTHS = (128, 130)
    SCHNORR_PUBKEY_LENGTH = 64

    def correct_ecdsa_key(self, suspected_key):
        return (len(suspected_key) in Parser.ECDSA_PUBKEY_LENGTHS) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4'))

    def correct_schnorr_key(self, suspected_key):
        return len(suspected_key) == Parser.SCHNORR_PUBKEY_LENGTH


    def increment_key_count(self, suspected_key):
        if len(suspected_key) in Parser.ECDSA_PUBKEY_LENGTHS:
            Parser.ecdsa += 1
        if len(suspected_key) == Parser.SCHNORR_PUBKEY_LENGTH:
            Parser.schnorr += 1
        Parser.keys += 1

    def add_key_to_data_dict(self, transaction, suspected_key, signature, data_dict):
        if suspected_key not in data_dict.keys():
            Parser.increment_key_count(self, suspected_key)
            data_dict[suspected_key] = []
        data_dict[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})

    def add_key_to_unmatched_data_dict(self, transaction, suspected_key, sigs, data_dict):
        if suspected_key not in data_dict.keys():
            Parser.increment_key_count(self, suspected_key)
            data_dict[suspected_key] = []
        data_dict[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})


    def extract_signature_p2pk_p2pkh(self, vin):

        signature = vin['scriptSig']['hex']
        length = int(signature[:2], 16) # len of signature in bytes
        signature = signature[2: 2 + length*2]

        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
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
        if not Parser.correct_ecdsa_key(self, suspected_key):
            return False

        signature = Parser.extract_signature_p2pk_p2pkh(self, vin)

        Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.ecdsa_data)
        return True


    # This function tries to process a Pay to Public Key transaction. Those are mostly old transaction mining BTC
    # ScriptSig: Either not here (mining) or includes signature
    # Locking script: contains public key followed by Checksig OP code
    # returns true if key was extracted or if spending of this output was detected and only signature is likely present. Other extractors MUST run prior in case output has something valuable

    def get_previous_vout(self, vin):
        prev_transaction_id = vin["txid"]
        prev_transaction = Parser.rpc.getrawtransaction(prev_transaction_id, True)
        vout_num = vin["vout"]
        vout = prev_transaction["vout"][vout_num]
        return vout

    def process_input_p2pk(self, transaction, vin):
        if not 'scriptSig' in vin.keys():
            return False

        signature = Parser.extract_signature_p2pk_p2pkh(self, vin)
        if signature == "NaN": # If there is no signature, there is no sense in looking up the corresponding public key.
            return False

        vout = Parser.get_previous_vout(self, vin)
        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[0]

        if not Parser.correct_ecdsa_key(self, suspected_key):
            return False

        Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.ecdsa_data)
        return True


    def process_output_p2pk(self, transaction, vout):

        if not 'scriptPubKey' in vout.keys() or len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) < 2:
            return False

        suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]
        signature = Parser.extract_signature_p2pk(self, transaction)

        if not Parser.correct_ecdsa_key(self, suspected_key):
            return False

        Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.ecdsa_data)
        return True


    # In case of checksig pass i = 0, same for p2wsh and p2tr
    def extract_signature_p2sh(self, vin, i):
        script_sig = vin["scriptSig"]["hex"]
        if script_sig[:2] == "00":
            script_sig = script_sig[2:]

        sigs = []
        while script_sig[:2] != "04" and script_sig != "":   # 0x04 is hex of OP_PUSHDATA1 after which redeem script goes
            length = int(script_sig[:2], 16)
            signature = script_sig[2: 2 + length*2]
            sigs.append(signature)
            script_sig = script_sig[2 + length*2:]

        signature = sigs[i]
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            signature = "NaN"
        return signature

    def extract_signature_p2wsh(self, vin, i):
        signature = vin['txinwitness'][i + 1] # Skipping the empty item
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2WSH] Failed signature:", signature)
            signature = "NaN"
        return signature

    def extract_signature_p2tr(self, vin, i):
        signature = vin['txinwitness'][i]

        if not len(signature) in Parser.SCHNORR_SIG_LENGTHS:
            signature = "NaN"

        if len(signature) == 130:
            signature = signature[:-2]  # Removing 'hash_type' byte (BIP341 - Common signature message)

        return signature


    def handle_checksig(self, transaction, vin, script, transaction_type):
        if ' ' in script:
            suspected_key = script.split(' ')[0] # blocks in 2019 get parsed with signature[all] pubkey somescript
        else:
            suspected_key = script[:-2]

        if transaction_type == "P2SH":
            signature = Parser.extract_signature_p2sh(self, vin, 0)
        if transaction_type == "P2WSH":
            signature = Parser.extract_signature_p2wsh(self, vin, 0)
        if transaction_type == "P2TR":
            signature = Parser.extract_signature_p2tr(self, vin, 0)


        if transaction_type in ("P2SH", "P2WSH"):
            if not Parser.correct_ecdsa_key(self, suspected_key):
                return False
            Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.ecdsa_data)

        if transaction_type == "P2TR":
            if not Parser.correct_schnorr_key(self, suspected_key):
                return False
            Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.schnorr_data)
        
        return True

    # Make me more clean pls
    def handle_checkmultisig(self, transaction, vin, script, transaction_type):
        toreturn = False
        if script[0] == '1' and script[1] == '4': # Transactions found in block 570006 that break the script completely
            return False

        num_sigs = int(script[1], 16)   # Checking the number of signatures present
        script = script[2:-2]           # Cutting instructions at beginning and end"
        num_keys = int(script[-1], 16)  # Format should be <num of signatures required> <pubkey1> ... <pubkeyn> <num of all pubkeys>
        script = script[:-2]            # Cutting counter at beginning and end"

        sigs = []
        for j in range(num_sigs):

                if transaction_type == "P2SH":
                    signature = Parser.extract_signature_p2sh(self, vin, j)
                if transaction_type == "P2WSH":
                    signature = Parser.extract_signature_p2wsh(self, vin, j)
                if transaction_type == "P2TR":
                    signature = Parser.extract_signature_p2tr(self, vin, j)
                sigs.append(signature)

        for i in range(num_keys):
            key_len = int(script[:2], 16)
            suspected_key = script[2:(key_len*2) + 2]
            script = script[((key_len*2) + 2):]

            # Choose dictionary to save data to
            if num_sigs == num_keys:
                data_dict = Parser.ecdsa_data
                if transaction_type == "P2TR":
                    data_dict = Parser.schnorr_data
            else:
                data_dict = Parser.unmatched_ecdsa_data
                if transaction_type == "P2TR":
                    data_dict = Parser.unmatched_schnorr_data


            if (transaction_type in ("P2SH, P2WSH") and Parser.correct_ecdsa_key(self, suspected_key))\
            or (transaction_type == "P2TR" and Parser.correct_schnorr_key(self, suspected_key)):
                if num_sigs == num_keys:
                    Parser.add_key_to_data_dict(self, transaction, suspected_key, sigs[i], data_dict)
                else:
                    Parser.add_key_to_unmatched_data_dict(self, transaction, suspected_key, sigs, data_dict)
                toreturn = True

        return toreturn

    # This function <<saves>> found data (if any) to data dictionaries.
    # Returns true at least one key was extracted.
    # Note that <transaction_type> argument is one of these: "P2SH", "P2WSH", "P2TR".
    def parse_serialized_script(self, transaction, vin, script, transaction_type):

        if not transaction_type in ("P2SH", "P2WSH", "P2TR"):
            print("You have mistake in your code. Please read caption of parse_serialized_script().")
            return False

        if script[-1] == 'c' and script[-2] == 'a': # Checksig instruction in hex is "ac"
            return Parser.handle_checksig(self, transaction, vin, script, transaction_type)

        if script[-1] == 'e' and script[-2] == 'a': # Checkmultisig instruction in hex is "ae"
            return Parser.handle_checkmultisig(self, transaction, vin, script, transaction_type)

        return False


    # This function tries to process a Pay to Script hash transaction. This is a newer type of transaction with seceral subtypes
    # ScriptSig: Contains signatures. Last entry is the unlocking script that needs to be further parsed to extract public key
    # Locking script: contains a few instructions and hash of script that unlocks the spending
    # returns true if key was extracted
    def process_input_p2sh(self, transaction, vin):

        if not 'scriptSig' in vin.keys() or len(vin['scriptSig']['asm'].split(" ")) < 2:
            return False

        script = vin['scriptSig']['asm'].split(" ")[-1]
        return Parser.parse_serialized_script(self, transaction, vin, script, "P2SH")


    def extract_signature_p2wpkh(self, vin):
        signature = vin['txinwitness'][0]
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
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
        signature = Parser.extract_signature_p2wpkh(self, vin)

        if not Parser.correct_ecdsa_key(self, suspected_key):
            return False

        Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.ecdsa_data)
        return True


    # This function tries to process a Pay to Witness Script Hash transaction. Those are very new SegWit transactions for Lightning L2 transactions underlaying settlement
    # Segwith contains signature(s) and script
    # returns true if key was extracted
    def process_input_p2wsh(self, transaction, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) < 2:
            return False

        script = vin['txinwitness'][-1]
        return Parser.parse_serialized_script(self, transaction, vin, script, "P2WSH")
 

    def handle_p2tr_keypath(self, transaction, vin):
        signature = Parser.extract_signature_p2tr(self, vin, 0)
        vout = Parser.get_previous_vout(self, vin)

        if "scriptPubKey" not in vout.keys():
            return False                                                    # This two if's are not necessary,
                                                                            # but if you are as pedantic as I am, you can leave them.
        if vout["scriptPubKey"]["type"] != "witness_v1_taproot":
            return False

        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[-1]  # As far as I'm concerned, there are always 2 elements.
                                                                    # The first one, I guess, is a version byte.
                                                                    # And the second one is a public key.

        if not Parser.correct_schnorr_key(self, suspected_key):
            return False

        Parser.add_key_to_data_dict(self, transaction, suspected_key, signature, Parser.schnorr_data)
        return True


    def handle_p2tr_scriptpath(self, transaction, vin):
        toreturn = False
        if len(vin['txinwitness']) < 3: # Should contain at least three things: some inputs for a script, the script and a control block.
            return toreturn

        control_block = vin['txinwitness'][-1]
        if (len(control_block) - 2) % 64 != 0: # Explanation on the link below. Too long to paste it here.
            return toreturn

        control_block = control_block[2:] # We don't need a leaf version and a sign bit, which are stored in the first byte.
        suspected_key = control_block[:64]

        if Parser.correct_schnorr_key(self, suspected_key):
            Parser.add_key_to_data_dict(self, transaction, suspected_key, "NaN", Parser.schnorr_data)
            toreturn = True

        script = vin["txinwitness"][-2]
        if Parser.parse_serialized_script(self, transaction, vin, script, "P2TR"):
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
        if not Parser.correct_schnorr_key(self, suspected_key):
            return False

        Parser.add_key_to_data_dict(self, transaction, suspected_key, "NaN", Parser.schnorr_data)
        return True


    # Essential to read. From Pieter Wuille, author of P2TR.
    """ https://bitcoin.stackexchange.com/questions/107154/what-is-the-control-block-in-taproot/107159#107159 """
    def process_input_p2tr(self, transaction, vin):

        if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) == 0:
            return False

        if len(vin['txinwitness']) == 1 and len(vin['txinwitness'][0]) in Parser.SCHNORR_SIG_LENGTHS:
            return Parser.handle_p2tr_keypath(self, transaction, vin)

        return Parser.handle_p2tr_scriptpath(self, transaction, vin)


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
        for dict_tup in Parser.DICTS: 
            if Parser.data_dict_full(self, dict_tup[0]) or (exception and dict_tup[0] != {}):
                file_name = "gathered-data/" + dict_tup[1] + "_" + str(n) + ".txt"
                Parser.flush_data_dict(self, file_name, dict_tup[0])


    def process_inputs(self, transaction):
        for i in range(len(transaction["vin"])):
            vin = transaction["vin"][i]
            Parser.inputs += 1
            try:

                # Run all extractors in turn, stop on success.
                if not (Parser.process_input_p2wpkh(self, transaction, vin) or \
                        Parser.process_input_p2wsh(self, transaction, vin) or \
                        Parser.process_input_p2tr(self, transaction, vin) or \
                        Parser.process_input_p2sh(self, transaction, vin) or \
                        Parser.process_input_p2pkh(self, transaction, vin) or \
                        Parser.process_input_p2pk(self, transaction, vin) or \
                        ('coinbase' in transaction['vin'][0].keys())): # Coinbase input, so don't count as failed.

                    Parser.failed_inputs += 1
                    print("Failed transaction input: ", transaction["txid"], ":", i, sep = '')

            except (ValueError, IndexError) as e:
                Parser.failed_inputs += 1
                print("Failed transaction input: ", transaction["txid"], ":", i, sep = '')



    def process_outputs(self, transaction):
        for i in range(len(transaction["vout"])):
            vout = transaction["vout"][i]
            Parser.outputs += 1

            if (vout["scriptPubKey"]["type"] == "pubkey" and not Parser.process_output_p2pk(self, transaction, vout)) or \
               (vout["scriptPubKey"]["type"] == "witness_v1_taproot" and not Parser.process_output_p2tr(self, transaction, vout)):
                Parser.failed_outputs += 1
                print("Failed transaction output: ", transaction["txid"], ":", i, sep = '')

    def process_block(self, n):
        Parser.blocks += 1
        block_hash = Parser.rpc.getblockhash(n)
        block_transactions = Parser.rpc.getblock(block_hash)['tx']

        for transaction_hash in block_transactions:

            Parser.transactions += 1
            transaction = Parser.rpc.getrawtransaction(transaction_hash, True) # Getting transaction in verbose format

            Parser.process_inputs(self, transaction)
            Parser.process_outputs(self, transaction)


    # Main functions, takes natural numbers start, end which are the indexes of Bitcoin blocks
    # if start is 0, then the parsing starts at the genesis block
    def process_blocks(self, start, end):

        for n in range(start, end):
            Parser.process_block(self, n)
            Parser.flush_if_needed(self, n, False)

        Parser.flush_if_needed(self, n, True)


#Example of use:
if __name__ == "__main__":
    parser = Parser()
    start_time = time.perf_counter()
    parser.process_blocks(739000, 739001)
    parser.print_statistics(start_time)
