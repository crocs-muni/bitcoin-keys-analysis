#!/usr/bin/python3

import bitcoin, bitcoin.rpc, struct, time, os, json

class Parser:
    failed = 0
    inputs = 0
    short = 0
    keys = 0
    saved_data = {}
    unmatched_data = {}

    SIGNATURE_LENGTHS = (148, 146, 144, 142, 140) # lengths of symbols in hex-encoded string. Divide by two and get number of bytes.

    def correct_ecdsa_key(self, suspected_key):
        return (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4'))

    def add_key_to_saved_data(self, transaction, suspected_key, signature):
        if suspected_key not in Parser.saved_data.keys():
            if (len(suspected_key) == 66):
                Parser.short += 1
            Parser.keys += 1
            Parser.saved_data[suspected_key] = []
        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})

    def add_key_to_unmatched_data(self, transaction, suspected_key, sigs):
        if suspected_key not in Parser.unmatched_data.keys():
            if (len(suspected_key) == 66):
                Parser.short += 1
            Parser.keys += 1
            Parser.unmatched_data[suspected_key] = []
        Parser.unmatched_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})


    def extract_signature_p2pkh(self, vin):

        signature = vin['scriptSig']['asm'].split(" ")[0]
        signature = signature.replace("[ALL]", "")
        # A function like remove_sighash_flags() is needed, which will remove all flags, not only [ALL].
        # But idk what are they in Bitcoin Core asm format.  
        # Or just cut off last byte?

        if len(signature) not in Parser.SIGNATURE_LENGTHS:
            print("Failed signature:", signature)
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
 
            signature = Parser.extract_signature_p2pkh(self, vin)
            suspected_key = vin['scriptSig']['asm'].split(" ")[1]

            if (Parser.correct_ecdsa_key(self, suspected_key)):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        return toreturn




    def extract_signature_p2pk(self, transaction):
        signature = "NaN"
        if ('scriptSig' in transaction['vin'][0].keys()) and (len(transaction['vin'][0]['scriptSig']['hex']) in Parser.SIGNATURE_LENGTHS):
            signature = transaction['vin'][0]['scriptSig']['hex']
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

            if (len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) < 2): #splitting on the instruction, len should be 2"
                continue

            signature = Parser.extract_signature_p2pk(self, transaction)
            suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]

            if (Parser.correct_ecdsa_key(self, suspected_key)):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        for vin in transaction['vin']:
            if 'scriptSig' in vin.keys():
                # Input contains signature only, so we have seen the key for this transaction already
                if (len(vin['scriptSig']['hex']) in Parser.SIGNATURE_LENGTHS):
                    toreturn = True

        return toreturn


    # Make me more clean pls
    def handle_checksig(self, transaction, vin, script):
        if(' ' in script):
            suspected_key = script.split(' ')[0] # blocks in 2019 get parsed with signature[all] pubkey somescript
        else:
            suspected_key = script[:-2]

        signature = vin['scriptSig']['asm'].split("[ALL] ")[0].split(" ")[1] # Skipping an extra zero here that was added to BTC script due to bugs
        if len(signature) not in Parser.SIGNATURE_LENGTHS:
            signature = "NaN"

        if (Parser.correct_ecdsa_key(self, suspected_key)):
            Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
            return True


    def handle_checkmultisig(self, transaction, vin, script):
        toreturn = False
        if (script[0] == '1' and script[1] == '4'): # Transactions found in block 570006 that break the script completely
            return False

        num_sigs = int(script[1], 16) # Checking the number of signatures present
        script = script[2:-2] # Cutting instructions at beginning and end"
        num_keys = int(script[-1], 16) # Bit hacky but should work, format should be num of signatures required pubkey1 ... pubkeyn num of all pubkeys
        script = script[:-2] # Cutting counter at beginning and end"

        if (num_sigs == num_keys):
            for i in range(num_keys):

                signature = vin['scriptSig']['asm'].replace("[ALL]", "").split(" ")[i+1] # Skipping over the first 0 here as well 
                if len(signature) not in Parser.SIGNATURE_LENGTHS:
                    signature = "NaN"

                key_len = int(script[:2], 16)
                suspected_key = script[2:(key_len*2) + 2]
                script = script[((key_len*2) + 2):]

                if (Parser.correct_ecdsa_key(self, suspected_key)):
                    Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                    toreturn = True

        else:
            sigs = []
            for j in range(num_sigs):
                signature = vin['scriptSig']['asm'].replace("[ALL]","").split(" ")[j+1]
                #print(len(signature))  See notes.txt
                #print(signature)
                if len(signature) not in Parser.SIGNATURE_LENGTHS:
                    signature = "NaN"
                sigs.append(signature)

            for i in range(num_keys):
                key_len = int(script[:2], 16)
                suspected_key = script[2:(key_len*2) + 2]
                script = script[((key_len*2) + 2):]

                if (Parser.correct_ecdsa_key(self, suspected_key)):
                    Parser.add_key_to_unmatched_data(self, transaction, suspected_key, sigs)
                    toreturn = True

        return toreturn

    # This function <<saves>> found data (if any) to Parser.saved_data or Parser.unmatched_data.
    # Returns true at least one key was extracted.
    def parse_serialized_script(self, transaction, vin):
        script = vin['scriptSig']['asm'].split(" ")[-1]

        if script[-1] == 'c' and script[-2] == 'a': # Checksig instruction in hex is "ac"
            return Parser.handle_checksig(self, transaction, vin, script)

        if script[-1] == 'e' and script[-2] == 'a': # Checkmultisig instruction in hex is "ae"
            return Parser.handle_checkmultisig(self, transaction, vin, script)

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

            if Parser.parse_serialized_script(self, transaction, vin):
                toreturn = True
                
        return toreturn
    
    # This function tries to process a Pay to Witness Public Key transaction. Those are new SegWit transactions
    # We do not care about scriptPubKey or Sigscript in this case
    # Segwith contains signature and public key
    # returns true if key was extracted
    def process_transaction_p2wpkh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:

            if not 'txinwitness' in vin.keys():
                continue

            if (len(vin['txinwitness']) < 2):
                continue

            signature = vin['txinwitness'][0]
            if len(signature) not in Parser.SIGNATURE_LENGTHS:
                signature = "NaN"

            suspected_key = vin['txinwitness'][1]
            if (Parser.correct_ecdsa_key(self, suspected_key)):
                Parser.add_key_to_saved_data(self, transaction, suspected_key, signature)
                toreturn = True

        return toreturn


    # This function tries to process a Pay to Witness Script Hash transaction. Those are very new SegWit transactions for Lightning L2 transactions underlaying settlement
    # Segwith contains signature(s) and script
    # returns true if key was extracted
    def process_transaction_p2wsh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:
            if 'txinwitness' in vin.keys():
                if (len(vin['txinwitness']) > 1):
                    redeem_script = vin['txinwitness'][-1]
                    if (redeem_script[-1] == 'c') and (redeem_script[-2] == 'a'): # Found checksig instruction so one key will be in front of it"
                        signature = vin['txinwitness'][1] # Skipping the empty item
                        suspected_key = redeem_script[:-2]
                        if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                            if suspected_key not in Parser.saved_data.keys():
                                if (suspected_key[1] in ('2', '3')):
                                    Parser.short += 1
                                Parser.keys += 1
                                Parser.saved_data[suspected_key] = []
                            if len(signature) not in Parser.SIGNATURE_LENGTHS:
                                signature = "NaN"
                            Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                            toreturn = True
                    if (redeem_script[-1] == 'e') and (redeem_script[-2] == 'a'): # Found checkmultisig instruction so multiple keys key will be in front of it"
                        num_sigs = int(redeem_script[1], 16) # Checking the number of signatures present
                        redeem_script = redeem_script[2:-2] # Cutting instructions at beginning and end"
                        num_keys = int(redeem_script[-1], 16) # Bit hacky but should work, format should be num of verifications required pubkey1 ... pubkeyn num of all pubkeys
                        redeem_script = redeem_script[:-2] # Cutting counter at beginning and end"
                        if (num_sigs == num_keys):
                            for i in range(num_keys):
                                signature = vin['txinwitness'][i + 1]
                                key_len = int(redeem_script[:2], 16)
                                suspected_key = redeem_script[2:(key_len + 1)*2]
                                redeem_script = redeem_script[(2 + (key_len*2)):]
                                if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                    if suspected_key not in Parser.saved_data.keys():
                                        if (len(suspected_key) == 66):
                                            Parser.short += 1
                                        Parser.keys += 1
                                        Parser.saved_data[suspected_key] = []
                                    if len(signature) not in Parser.SIGNATURE_LENGTHS:
                                        signature = "NaN"
                                    Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                                    toreturn = True
                        else:
                            sigs = []
                            for j in range(num_sigs):
                                signature = vin['txinwitness'][j + 1]
                                if len(signature) not in Parser.SIGNATURE_LENGTHS:
                                    signature = "NaN"
                                sigs.append(signature)
                            for i in range(num_keys):
                                key_len = int(redeem_script[:2], 16)
                                suspected_key = redeem_script[2:(key_len + 1)*2]
                                redeem_script = redeem_script[(2 + (key_len*2)):]
                                if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                    if suspected_key not in Parser.unmatched_data.keys():
                                        if (len(suspected_key) == 66):
                                            Parser.short += 1
                                        Parser.keys += 1
                                        Parser.unmatched_data[suspected_key] = []
                                    Parser.unmatched_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})
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
                    if not (Parser.process_transaction_p2pkh(self, transaction) or Parser.process_transaction_p2sh(self, transaction) or Parser.process_transaction_p2wpkh(self, transaction) or Parser.process_transaction_p2wsh(self, transaction) or Parser.process_transaction_p2pk(self, transaction) or ('coinbase' in transaction['vin'][0].keys())):
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

        print ("Processed ", Parser.inputs, " transactions and gathered ", Parser.keys, " keys, ", Parser.short, " short keys in ", time.perf_counter() - start_time, " seconds.")

#Example of use:
parser = Parser()
parser.process_blocks(739000, 739001)
