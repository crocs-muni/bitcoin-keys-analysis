#!/usr/bin/python3

import bitcoin, bitcoin.rpc, struct, time, os, json

class Parser:
    failed = 0
    inputs = 0
    ecdsa = 0
    schnorr = 0
    keys = 0
    saved_data = {}
    unmatched_data = {}

    ECDSA_SIG_LENGTHS = (148, 146, 144, 142, 140)   # Lengths of symbols in hex-encoded string. Divide by two and get number of bytes.
    ECDSA_PUBKEY_LENGTHS = (66, 130)

    # Schnorr signature in bitcoin itself is always 64 bytes, but it's possible to set non-default hash_type in 65th byte.
    #                                                                                   (watch BIP341 - Common signature message)
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

    def add_key_to_saved_data(self, transaction, suspected_key, signature):
        if suspected_key not in Parser.saved_data.keys():
            Parser.increment_key_count(self, suspected_key)
            Parser.saved_data[suspected_key] = []
        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})

    def add_key_to_unmatched_data(self, transaction, suspected_key, sigs):
        if suspected_key not in Parser.unmatched_data.keys():
            Parser.increment_key_count(self, suspected_key)
            Parser.unmatched_data[suspected_key] = []
        Parser.unmatched_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})


    def extract_signature_p2pkh(self, vin):

        signature = vin['scriptSig']['asm'].split(" ")[0]
        signature = signature.replace("[ALL]", "")
        # A function like remove_sighash_flags() is needed, which will remove all flags, not only [ALL].
        # But idk what are they in Bitcoin Core asm format. 
        # Or just cut off last byte?

        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2PKH] Failed signature:", signature)
            signature = "NaN"

        return signature


    # This function tries to process a Pay to Public Key Hash transaction
    # ScriptSig: contains signature and public key
    # Locking script: contains hash of public key
    # returns true if key was extracted
    def process_transaction_p2pkh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:

            if not 'scriptSig' in vin.keys(): # this is a mining block and has no scriptSig
                continue

            if len(vin['scriptSig']['asm'].split(" ")) < 2: # scriptSig should contain a signature and a public key
                continue
 
            suspected_key = vin['scriptSig']['asm'].split(" ")[1]
            signature = Parser.extract_signature_p2pkh(self, vin)

            if Parser.correct_ecdsa_key(self, suspected_key):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        return toreturn




    def extract_signature_p2pk(self, transaction):

        if not "scriptSig" in transaction["vin"][0].keys():
            return "NaN"

        signature = transaction['vin'][0]['scriptSig']['hex']
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2PK] Failed signature:", signature)
            signature = "NaN"

        return signature

    # This function tries to process a Pay to Public Key transaction. Those are mostly old transaction mining BTC
    # ScriptSig: Either not here (mining) or includes signature
    # Locking script: contains public key followed by Checksig OP code
    # returns true if key was extracted or if spending of this output was detected and only signature is likely present. Other extractors MUST run prior in case output has something valuable
    def process_transaction_p2pk(self, transaction):
        toreturn = False
        for vout in transaction['vout']:

            if not 'scriptPubKey' in vout.keys():
                continue

            if len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) < 2: #splitting on the instruction, len should be 2"
                continue

            suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]
            signature = Parser.extract_signature_p2pk(self, transaction)

            if Parser.correct_ecdsa_key(self, suspected_key):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        for vin in transaction['vin']:
            if 'scriptSig' in vin.keys():
                # Input contains signature only, so we have seen the key for this transaction already
                if len(vin['scriptSig']['hex']) in Parser.ECDSA_SIG_LENGTHS:
                    toreturn = True

        return toreturn

    # I suppose these two functions can be connected to one?
    def extract_signature_p2sh_checksig(self, vin):
        signature = vin['scriptSig']['asm'].split("[ALL] ")[0].split(" ")[1] # Skipping an extra zero here that was added due to bugs
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2SH][OP_CHECKSIG] Failed signature:", signature)
            signature = "NaN"
        return signature

    def extract_signature_p2sh_multisig(self, vin, i):
        signature = vin['scriptSig']['asm'].replace("[ALL]", "").split(" ")[i+1] # Skipping over the first 0 here as well
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2SH][OP_CHECKMULTISIG] Failed signature:", signature)
            signature = "NaN"
        return signature

    # In case of checksig pass i = 0, same for p2tr
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
            signature = Parser.extract_signature_p2sh_checksig(self, vin)
        if transaction_type == "P2WSH":
            signature = Parser.extract_signature_p2wsh(self, vin, 0)
        if transaction_type == "P2TR":
            signature = Parser.extract_signature_p2tr(self, vin, 0)

        if transaction_type in ("P2SH", "P2WSH") and not Parser.correct_ecdsa_key(self, suspected_key):
            return False
        if transaction_type == "P2TR" and not Parser.correct_schnorr_key(self, suspected_key):
            return False

        Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
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
                    signature = Parser.extract_signature_p2sh_multisig(self, vin, j)
                if transaction_type == "P2WSH":
                    signature = Parser.extract_signature_p2wsh(self, vin, j)
                if transaction_type == "P2TR":
                    signature = Parser.extract_signature_p2tr(self, vin, j)
                sigs.append(signature)

        for i in range(num_keys):
            key_len = int(script[:2], 16)
            suspected_key = script[2:(key_len*2) + 2]
            script = script[((key_len*2) + 2):]

            if (transaction_type in ("P2SH, P2WSH") and Parser.correct_ecdsa_key(self, suspected_key))\
            or (transaction_type == "P2TR" and Parser.correct_schnorr_key(self, suspected_key)):
                if num_sigs == num_keys:
                    Parser.add_key_to_saved_data(self, transaction, suspected_key, sigs[i])
                else:
                    Parser.add_key_to_unmatched_data(self, transaction, suspected_key, sigs)
                toreturn = True

        return toreturn

    # This function <<saves>> found data (if any) to Parser.saved_data or Parser.unmatched_data.
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
    def process_transaction_p2sh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:
            if not 'scriptSig' in vin.keys():
                continue

            if len(vin['scriptSig']['asm'].split(" ")) < 2: #splitting on the separator, len should be 2 or more"
                continue

            script = vin['scriptSig']['asm'].split(" ")[-1]
            if Parser.parse_serialized_script(self, transaction, vin, script, "P2SH"):
                toreturn = True
                
        return toreturn


    def extract_signature_p2wpkh(self, vin):
        signature = vin['txinwitness'][0]
        if len(signature) not in Parser.ECDSA_SIG_LENGTHS:
            #print("[P2WPKH] Failed signature:", signature)
            signature = "NaN"
        return signature

    # This function tries to process a Pay to Witness Public Key transaction. Those are new SegWit transactions
    # We do not care about scriptPubKey or Sigscript in this case
    # Segwith contains signature and public key
    # returns true if key was extracted
    def process_transaction_p2wpkh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:

            if not 'txinwitness' in vin.keys():
                continue

            if len(vin['txinwitness']) < 2:
                continue

            suspected_key = vin['txinwitness'][1]
            signature = Parser.extract_signature_p2wpkh(self, vin)

            if Parser.correct_ecdsa_key(self, suspected_key):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        return toreturn


    # This function tries to process a Pay to Witness Script Hash transaction. Those are very new SegWit transactions for Lightning L2 transactions underlaying settlement
    # Segwith contains signature(s) and script
    # returns true if key was extracted
    def process_transaction_p2wsh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:

            if not 'txinwitness' in vin.keys():
                continue

            if len(vin['txinwitness']) < 2:
                continue

            script = vin['txinwitness'][-1]
            if Parser.parse_serialized_script(self, transaction, vin, script, "P2WSH"):
                toreturn = True

        return toreturn
 

    def handle_p2tr_keypath(self, transaction, vin, rpc):
        signature = Parser.extract_signature_p2tr(self, vin, 0)

        prev_transaction_id = vin["txid"]
        prev_transaction = rpc.getrawtransaction(prev_transaction_id, True)
        vout_num = vin["vout"]
        vout = prev_transaction["vout"][vout_num]

        if "scriptPubKey" not in vout.keys():
            print("Failed p2tr vout: no 'scriptPubKey'!")
            return False                                                    # This two if's are not necessary,
                                                                            # but if you are as pedantic as I am, you can leave them.
        if vout["scriptPubKey"]["type"] != "witness_v1_taproot":
            print("Failed p2tr vout: type is not 'witness_v1_taproot'")
            return False

        suspected_key = vout["scriptPubKey"]["asm"].split(' ')[-1]  # As far as I'm concerned, there are always 2 elements.
                                                                    # The first one, I guess, is a version byte.
        #suspected_key = vout["scriptPubKey"]["asm"].split(' ')[1]  # And the second one is a public key. So idk what's better - '[-1]' or '[1]'?

        if not Parser.correct_schnorr_key(self, suspected_key):
            print("Failed p2tr vout: suspected key (", suspected_key, ") is not ", Parser.SCHNORR_PUBKEY_LENGTH/2, " bytes long!", sep = '')
            return False

        Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
        print("Successful P2TR [KEYPATH]!!! TXID:", transaction["txid"])
        return True


    def handle_p2tr_scriptpath(self, transaction, vin):
        toreturn = False
        if len(vin['txinwitness']) < 3: # Should contain at least three things: some inputs for a script, the script and a control block.
            #print("Failed P2TR [SCRIPTPATH] witness has less than 3 elements. TXID:", transaction["txid"])
            return toreturn

        control_block = vin['txinwitness'][-1]
        if (len(control_block) - 2) % 64 != 0: # Explanation on the link below. Too long to paste it here.
            #print("Failed P2TR [SCRIPTPATH] controlblock bad format!")
            return toreturn

        control_block = control_block[2:]
        suspected_key = control_block[:64]

        if Parser.correct_schnorr_key(self, suspected_key):
            Parser.add_key_to_saved_data(self, transaction, suspected_key, "NaN")
            print("Successful P2TR [SCRIPTPATH][CONTROLBLOCK]!!! TXID:", transaction["txid"])
            toreturn = True

        script = vin["txinwitness"][-2]
        if Parser.parse_serialized_script(self, transaction, vin, script, "P2TR"):
            print("Successful P2TR [SCRIPTPATH]!!! TXID:", transaction["txid"])
            toreturn = True

        return toreturn


    # Essential to read. From Pieter Wuille, author of P2TR.
    """ https://bitcoin.stackexchange.com/questions/107154/what-is-the-control-block-in-taproot/107159#107159 """
    def process_transaction_p2tr(self, transaction, rpc):
        toreturn = False

        for vin in transaction['vin']:

            if not 'txinwitness' in vin.keys() or len(vin['txinwitness']) == 0:
                continue

            if len(vin['txinwitness']) == 1 and len(vin['txinwitness'][0]) in Parser.SCHNORR_SIG_LENGTHS:
                if Parser.handle_p2tr_keypath(self, transaction, vin, rpc):
                    toreturn = True

            elif Parser.handle_p2tr_scriptpath(self, transaction, vin):
                toreturn = True

        return toreturn
    
    # This functions simply flush collected data to a JSON file.
    def flush_saved_data(self, file_name):
        with open(file_name, 'w') as outfile:
            json.dump(Parser.saved_data, outfile, indent = 2)
        Parser.saved_data = {}

    def flush_unmatched(self, file_name):
        with open(file_name, 'w') as outfile:
            json.dump(Parser.unmatched_data, outfile, indent = 2)
        Parser.unmatched_data = {}




    # Main functions, takes natural numbers start, end which are the indexes of Bitcoin blocks
    # if start is 0, then the parsing starts at the genesis block
    def process_blocks(self, start, end):
        bitcoin.SelectParams("mainnet")  # we will be using the production blockchain
        rpc = bitcoin.rpc.RawProxy(btc_conf_file=os.path.join(os.getcwd(), ".bitcoin-data/bitcoin.conf"))
        # change path to bitcoin.conf if you have different data structure
        # raw Proxy takes commands in hexa strings instead of structs, that is what we need

        start_time = time.perf_counter()
        for n in range(start, end):
            file_counter_saved = 0    # counters needed for creating output file names. 
            file_counter_unmatched = 0

            block_hash = rpc.getblockhash(n)
            block_transactions = rpc.getblock(block_hash)['tx']
            for transaction_hash in block_transactions: # iterating over all transactions in a block
                Parser.inputs += 1
                transaction = rpc.getrawtransaction(transaction_hash, True) # Getting transaction in verbose format to get all the needed parsed details
                try:
                    # Running all extractors, last check is if transaction is new version of mining and contains no public key, only hash of miner pub key
                    if not (Parser.process_transaction_p2pkh(self, transaction) or Parser.process_transaction_p2tr(self, transaction, rpc) or Parser.process_transaction_p2sh(self, transaction) or Parser.process_transaction_p2wpkh(self, transaction) or Parser.process_transaction_p2wsh(self, transaction) or Parser.process_transaction_p2pk(self, transaction) or ('coinbase' in transaction['vin'][0].keys())):
                        Parser.failed += 1
                        print("Failed transaction ", transaction_hash)
                except (ValueError, IndexError) as e:
                    Parser.failed += 1
                    print("Failed transaction ", transaction_hash)

                # Maximum key count to store in RAM before flushing to JSON. You can set much more, depends on your RAM size.
                # Guess it, or use my formula below.
                # Note that 400 B - average length of key record in JSON format (including pubkey, txid, time and sig)

                #RAM_SIZE = 6    # place amount of RAM in GB, that you want to dedicate to the script.
                #max_key_count = RAM_SIZE * 1024 * 1024 / 400

                max_key_count = 10000

                # It doesn't really matter, if block number in file name and actual block number for a key will differ,
                #   so the only exception of max_key_count is the very last transaction of the very last block.
                if len(Parser.saved_data) >= max_key_count or (n == end - 1 and transaction_hash == block_transactions[-1]):
                    # change names here and below if you need to
                    file_name = "gathered-data/data_" + str(n) + '_' + str(file_counter_saved) + ".txt"
                    Parser.flush_saved_data(self, file_name)
                    file_counter_saved += 1

                if len(Parser.unmatched_data) >= max_key_count or (n == end - 1 and transaction_hash == block_transactions[-1]):
                    file_name = "gathered-data/unmatched_" + str(n) + '_' + str(file_counter_unmatched) + ".txt"
                    Parser.flush_unmatched(self, file_name)
                    file_counter_unmatched += 1

        print ("Processed ", Parser.inputs, " transactions and gathered ", Parser.keys, " keys: ", Parser.ecdsa, " ECDSA keys, ", Parser.schnorr," Schnorr Signature keys; in ", time.perf_counter() - start_time, " seconds.")

#Example of use:
parser = Parser()
parser.process_blocks(739000, 739020)
