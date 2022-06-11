import bitcoin, bitcoin.rpc, struct, time, os, json

class Parser:
    failed = 0
    inputs = 0
    short = 0
    keys = 0
    saved_data = {}
    unmatched_data = {}
    # This function tries to process a Pay to Public Key Hash transaction
    # ScriptSig: contains signature and public key
    # Locking script: contains hash of public key
    # returns true if key was extracted
    def process_transaction_p2pkh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:
            if 'scriptSig' in vin.keys(): # this is not a mining block and has a scriptSig
                if (len(vin['scriptSig']['asm'].split("[ALL] ")) > 1) or (len(vin['scriptSig']['asm'].split(" ")) > 1): # scriptSig contains signature and public key
                    if (len(vin['scriptSig']['asm'].split("[ALL] ")) > 1):
                        suspected_key = vin['scriptSig']['asm'].split("[ALL] ")[1]
                        signature = vin['scriptSig']['asm'].split("[ALL] ")[0]
                    else:
                        suspected_key = vin['scriptSig']['asm'].split(" ")[1] # Sometimes they are separated by space for some reason, rather rare
                        signature = vin['scriptSig']['asm'].split(" ")[0]
                    if len(signature) not in (148, 144, 146, 142):
                        signature = "NaN"
                    if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                        if (len(suspected_key) == 66):
                            Parser.short += 1
                        Parser.keys += 1
                        if suspected_key not in Parser.saved_data.keys():
                            Parser.saved_data[suspected_key] = []
                        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                        toreturn = True
        return toreturn

    # This function tries to process a Pay to Public Key transaction. Those are mostly old transaction mining BTC
    # ScriptSig: Either not here (mining) or includes signature
    # Locking script: contains public key followed by Checksig OP code
    # returns true if key was extracted or if spending of this output was detected and only signature is likely present. Other extractors MUST run prior in case output has something valuable
    def process_transaction_p2pk(self, transaction):
        toreturn = False
        for vout in transaction['vout']:
            if 'scriptPubKey' in vout.keys():
                if (len(vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")) > 1): #splitting on the instruction, len should be 2"
                    suspected_key = vout['scriptPubKey']['asm'].split(" OP_CHECKSIG")[0]
                    if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                        if (len(suspected_key) == 66):
                            Parser.short += 1
                        Parser.keys += 1
                        if suspected_key not in Parser.saved_data.keys():
                            Parser.saved_data[suspected_key] = []
                        if ('scriptSig' in transaction['vin'][0].keys()) and (len(transaction['vin'][0]['scriptSig']['hex']) in (148, 144, 146, 142)):
                            signature = transaction['vin'][0]['scriptSig']['hex']
                        else:
                            signature = "NaN"
                        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                        toreturn = True
        for vin in transaction['vin']:
            if 'scriptSig' in vin.keys():
                if (len(vin['scriptSig']['hex']) in (148, 144, 146, 142)): # Input contains signature only so we have seen the key for this transaction already
                    toreturn = True
        return toreturn
    
    # This function tries to process a Pay to Script hash transaction. This is a newer type of transaction with seceral subtypes
    # ScriptSig: Contains signatures. Last entry is the unlocking script that needs to be further parsed to extract publick key
    # Locking script: contains a few instructions and hash of script that unlocks the spending
    # returns true if key was extracted
    def process_transaction_p2sh(self, transaction):
        toreturn = False
        for vin in transaction['vin']:
            if 'scriptSig' in vin.keys():
                if (len(vin['scriptSig']['asm'].split("[ALL] ")) > 1): #splitting on the separator, len should be 2 or more"
                    redeem_script = vin['scriptSig']['asm'].split("[ALL] ")[-1]
                    if (redeem_script[-1] == 'c') and (redeem_script[-2] == 'a'): # Found checksig instruction so one key will be in front of it"
                        if(' ' in redeem_script):
                            suspected_key = redeem_script.split(' ')[0] # blocks in 2019 get parsed with signature[all] pubkey somescript
                        else:
                            suspected_key = redeem_script[:-2]
                        signature = vin['scriptSig']['asm'].split("[ALL] ")[0].split(" ")[1] # Skipping an extra zero here that was added to BTC script due to bugs
                        if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                            if (suspected_key[1] in ('2', '3')):
                                Parser.short += 1
                            Parser.keys += 1
                            if suspected_key not in Parser.saved_data.keys():
                                Parser.saved_data[suspected_key] = []
                            if len(signature) not in (148, 144, 146, 142):
                                signature = "NaN"
                            Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                            toreturn = True
                    if (redeem_script[-1] == 'e') and (redeem_script[-2] == 'a'): # Found checkmultisig instruction so multiple keys key will be in front of it"
                        if (redeem_script[0] == '1' and redeem_script[1] == '4'): # Transactions found in block 570006 that break the script completely
                            return False
                        num_sigs = int(redeem_script[1]) # Checking the number of signatures present
                        redeem_script = redeem_script[2:-2] # Cutting instructions at beginning and end"
                        num_keys = int(redeem_script[-1]) # Bit hacky but should work, format should be num of signatures required pubkey1 ... pubkeyn num of all pubkeys
                        redeem_script = redeem_script[:-2] # Cutting counter at beginning and end"
                        if (num_sigs == num_keys):
                            for i in range(num_keys):
                                signature = vin['scriptSig']['asm'].replace("[ALL]", "").split(" ")[i+1] # Skipping over the first 0 here as well 
                                key_len = int(redeem_script[:2], 16)
                                suspected_key = redeem_script[2:(key_len + 1)*2]
                                redeem_script = redeem_script[(2 + (key_len*2)):]
                                if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                   if (len(suspected_key) == 66):
                                       Parser.short += 1
                                   Parser.keys += 1
                                   if suspected_key not in Parser.saved_data.keys():
                                       Parser.saved_data[suspected_key] = []
                                   if len(signature) not in (148, 144, 146, 142):
                                       signature = "NaN"
                                   Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                                   toreturn = True
                        else:
                            sigs = []
                            for j in range(num_sigs):
                                signature = vin['scriptSig']['asm'].replace("[ALL]","").split(" ")[j+1]
                                if len(signature) not in (148, 144, 146, 142):
                                    signature = "NaN"
                                sigs.append(signature)
                            for i in range(num_keys):
                                key_len = int(redeem_script[:2], 16)
                                suspected_key = redeem_script[2:(key_len + 1)*2]
                                redeem_script = redeem_script[(2 + (key_len*2)):]
                                if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                    if (len(suspected_key) == 66):
                                        Parser.short += 1
                                    Parser.keys += 1
                                    if suspected_key not in Parser.unmatched_data.keys():
                                        Parser.unmatched_data[suspected_key] = []
                                    Parser.unmatched_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})
                                    toreturn = True
                            
                        
        return toreturn
    
    # This function tries to process a Pay to Witness Public Key transaction. Those are new SegWit transactions
    # We do not care about scriptPubKey or Sigscript in this case
    # Segwith contains signature and public key
    # returns true if key was extracted
    def process_transaction_p2wpk(self, transaction):
        toreturn = False
        for vin in transaction['vin']:
            if 'txinwitness' in vin.keys():
                signature = vin['txinwitness'][0]
                if (len(vin['txinwitness']) > 1): 
                    suspected_key = vin['txinwitness'][-1]
                    if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                        if (len(suspected_key) == 66):
                            Parser.short += 1
                        Parser.keys += 1
                        if suspected_key not in Parser.saved_data.keys():
                            Parser.saved_data[suspected_key] = []
                        if len(signature) not in (148, 144, 146, 142):
                            signature = "NaN"
                        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                        toreturn = True
                if (not toreturn) and (len(vin['txinwitness']) > 2):
                    suspected_key = vin['txinwitness'][-2] #some transactions have signature, key and then something else on the last position, small fraction of all, no idea why
                    if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                        if (len(suspected_key) == 66):
                            Parser.short += 1
                        Parser.keys += 1
                        if suspected_key not in Parser.saved_data.keys():
                            Parser.saved_data[suspected_key] = []
                        if len(signature) not in (148, 144, 146, 142):
                            signature = "NaN"
                        Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
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
                            if (suspected_key[1] in ('2', '3')):
                                Parser.short += 1
                            Parser.keys += 1
                            if suspected_key not in Parser.saved_data.keys():
                                Parser.saved_data[suspected_key] = []
                            if len(signature) not in (148, 144, 146, 142):
                                signature = "NaN"
                            Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                            toreturn = True
                    if (redeem_script[-1] == 'e') and (redeem_script[-2] == 'a'): # Found checkmultisig instruction so multiple keys key will be in front of it"
                        num_sigs = int(redeem_script[1]) # Checking the number of signatures present
                        redeem_script = redeem_script[2:-2] # Cutting instructions at beginning and end"
                        num_keys = int(redeem_script[-1]) # Bit hacky but should work, format should be num of verifications required pubkey1 ... pubkeyn num of all pubkeys
                        redeem_script = redeem_script[:-2] # Cutting counter at beginning and end"
                        if (num_sigs == num_keys):
                            for i in range(num_keys):
                                signature = vin['txinwitness'][i + 1]
                                key_len = int(redeem_script[:2], 16)
                                suspected_key = redeem_script[2:(key_len + 1)*2]
                                redeem_script = redeem_script[(2 + (key_len*2)):]
                                if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                   if (len(suspected_key) == 66):
                                       Parser.short += 1
                                   Parser.keys += 1
                                   if suspected_key not in Parser.saved_data.keys():
                                       Parser.saved_data[suspected_key] = []
                                   if len(signature) not in (148, 144, 146, 142):
                                       signature = "NaN"
                                   Parser.saved_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signature' : signature})
                                   toreturn = True
                        else:
                            sigs = []
                            for j in range(num_sigs):
                                signature = vin['txinwitness'][j + 1]
                                if len(signature) not in (148, 144, 146, 142):
                                    signature = "NaN"
                                sigs.append(signature)
                            for i in range(num_keys):
                               key_len = int(redeem_script[:2], 16)
                               suspected_key = redeem_script[2:(key_len + 1)*2]
                               redeem_script = redeem_script[(2 + (key_len*2)):]
                               if (len(suspected_key) in (66, 130)) and (suspected_key[0] == '0') and (suspected_key[1] in ('2', '3', '4')):
                                   if (len(suspected_key) == 66):
                                       Parser.short += 1
                                   Parser.keys += 1
                                   if suspected_key not in Parser.unmatched_data.keys():
                                       Parser.unmatched_data[suspected_key] = []
                                   Parser.unmatched_data[suspected_key].append({'ID' : transaction['txid'], 'time' : transaction['time'], 'signatures' : sigs})
                                   toreturn = True
        return toreturn
    
    # Main functions, takes natural numbers start, end which are the indexes of Bitcoin blocks
    # if start is 0, then the parsing starts at the genesis block
    def process_blocks(self, start, end):
        bitcoin.SelectParams("mainnet")  # we will be using the production blockchain
        rpc = bitcoin.rpc.RawProxy(btc_conf_file=os.path.join(os.getcwd(), "bitcoin.conf"))  # raw Proxy takes commands in hexa strings instead of structs, that is what we need
        start_time = time.perf_counter()
        for n in range(start, end):
            block_hash = rpc.getblockhash(n)
            block_transactions = rpc.getblock(block_hash)['tx']
            for transaction_hash in block_transactions: # iterating over all transactions in a block
                Parser.inputs += 1
                transaction = rpc.getrawtransaction(transaction_hash, True) # Getting transaction in verbose format to get all the needed parsed details
                try:
                    # Running all extractors, last check is if transaction is new version of mining and contains no public key, only hash of miner pub key
                    if not (Parser.process_transaction_p2pkh(self, transaction) or Parser.process_transaction_p2sh(self, transaction) or Parser.process_transaction_p2wpk(self, transaction) or Parser.process_transaction_p2wsh(self, transaction) or Parser.process_transaction_p2pk(self, transaction) or ('coinbase' in transaction['vin'][0].keys())):
                        Parser.failed += 1
                        print("Failed transaction ", transaction_hash)
                except (ValueError, IndexError) as e:
                    Parser.failed += 1
                    print("Failed transaction ", transaction_hash)
                if (len(Parser.saved_data) % 100000) == 0:
                    name = "data_" + str(n) + ".txt"
                    with open(name, 'w') as outfile:
                        json.dump(Parser.saved_data, outfile)
                    Parser.saved_data = {}
                if ((len(Parser.unmatched_data) % 100000) == 0) and (len(Parser.unmatched_data) != 0):
                    name = "unmatched_" + str(n) + ".txt"
                    with open(name, 'w') as outfile:
                        json.dump(Parser.unmatched_data, outfile)
                    Parser.unmatched_data = {} 
        name = "data_" + str((end - 1)) + ".txt"
        with open(name, 'w') as outfile:
            json.dump(Parser.saved_data, outfile)
        name = "unmatched_" + str((end - 1)) + ".txt"
        with open(name, 'w') as outfile:
            json.dump(Parser.unmatched_data, outfile)
        print ("Processed ", Parser.inputs, " transactions and gathered ", Parser.keys, " keys, ", Parser.short, " short keys in ", time.perf_counter() - start_time, " seconds.")

#Example of use:
parser = Parser()
parser.process_blocks(1, 10)
