#!/bin/python3

def demo():

    YELLOW='\033[1;33m'
    PURPLE='\033[0;35m'
    NO_COLOR='\033[0m'

    print("\nHi, we appreciate your interest in our project! Let us show you a couple of examples on how you can use the script:\n")

    print("    - ", PURPLE, "Parser.process_transaction(", NO_COLOR, "self, txid: ", YELLOW, "str", PURPLE, ")", NO_COLOR, "\n", sep = '')
    print("     Main goal of this function is to extract all the public keys envolved in the transaction specified in <txid> argument.")
    print("     The keys will be saved in the following Python dictionaries which can later be dumped into a JSON file:\n\n\
        Parser.ecdsa_data,\n\
        Parser.unmatched_ecdsa_data,\n\
        Parser.schnorr_data,\n\
        Parser.unmatched_schnorr_data\n\n\
 depending on the type of the public key and amount of corresponding signatures.")
    print("     <unmatched> in name of a dictionary means that the script can't be sure which of the found signatures corresponds to the key.")
    print("     Try to run the following:\n\n         parser.process_transaction('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098')")
    print("         parser.show_dict(parser.ecdsa_data) # prints out the dictionary in a readable way with JSON indent.")

    print("\n   - ", PURPLE, "Parser.process_block(", NO_COLOR, "self, n:", YELLOW, " int", PURPLE, ")", NO_COLOR, "\n", sep = '')
    print("     This function simply calls <Parser.process_transaction()> function for all transactions in block of height <n>.")

    print("\n   - ", PURPLE, "Parser.process_blocks(", NO_COLOR, "self, start: ", YELLOW, "int", NO_COLOR, ", end: ", YELLOW, "int", PURPLE, ")", NO_COLOR, "\n", sep = '')
    print("     This function calls <Parser.process_block()> for all blocks in <range(start, end)>, flushes the collected data to .txt files (to <gathered-data> subdirectory, which you'll have to create) with <Parser.flush_if_needed()> function at the very end of itself and every 10000 keys not ot exhaust RAM, and prints out parsing statistics.")
    print("     Try to run the following:\n\n         parser.process_blocks(1, 100)\n")

    print("We've shown you the main functions that we expect you to use. You can discover more by looking through the source code of the script.")
    print("You can also implement other functionality on top of what we've done. GLHF!")



if __name__ == "__main__":
    demo()
