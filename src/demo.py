#!/bin/python3

def demo():

    # Don't forget to update other/demo.txt file if you change demo.
    # Yes, this is a complete mess, but fixing it is not the top priority now.

    YELLOW='\033[1;33m'
    PURPLE='\033[0;35m'
    NO_COLOR='\033[0m'


    print("\nHi, we appreciate your interest in our project!")
    print("Let us show you a couple of examples on how you can use the script.\n")

    print("    - BitcoinPublicKeyParser.", PURPLE, "process_transaction", NO_COLOR, "(self, txid: ", YELLOW, "str", NO_COLOR, ")\n", sep = '')
    print("    Main goal of this function is to extract all the public keys envolved in the transaction specified in <txid> argument.")
    print("    Try to run the following:\n\n        parser.process_transaction('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098')")
    print("        parser.show_dict(parser.ecdsa_data) # prints out the dictionary in a readable way with JSON indent.")

    print("\n    - BitcoinPublicKeyParser.", PURPLE, "process_block", NO_COLOR, "(self, n:", YELLOW, " int", NO_COLOR, ")\n", sep = '')
    print("    This function simply calls <BitcoinPublicKeyParser.process_transaction()> function for all transactions in block of height <n>.")

    print("\n    - BitcoinPublicKeyParser.", PURPLE, "process_block_range", NO_COLOR, "(self, range_to_parse: ", YELLOW, "range", NO_COLOR, ")\n", sep="")
    print("    This function calls <BitcoinPublicKeyParser.process_block()> for all blocks in the specified range and flushes the collected data to .json and .txt files (to <gathered-data> subdirectory).")
    print("    Try to run the following:\n")
    print("        parser.process_block_range(range(1, 100))\n")
    print("    And then have a look into <gathered-data> subdirectory.")

    print("\n    - BitcoinPublicKeyParser.", PURPLE, "process_range_in_multiprocess(", NO_COLOR, "self, block_from: ", YELLOW, "int,", NO_COLOR, " block_to: ", YELLOW, "int", NO_COLOR, ", parser_count: ", YELLOW, "int", NO_COLOR, " = 10)\n", sep="")

    print("    Just like the name says, this function processes a block range in multiple processes. However, it's a primitive multiproccessing: it just calls <BitcoinPublicKeyParser.process_block_range()> in a such way that the tasks for each individual process don't overlap.\n")

    print("This are the main functions that we expect you to use. You can discover more by looking through the source code of the script.")
    print("You can also implement other functionality on top of what we've done.\n")


    print("\nNow lets talk about the output format. The keys will be saved in the following Python dictionaries which can later be dumped into a JSON file:\n\n\
        BitcoinPublicKeyParser.", PURPLE, "ecdsa_data,", NO_COLOR,"\n\
        BitcoinPublicKeyParser.", PURPLE, "unmatched_ecdsa_data,", NO_COLOR, "\n\
        BitcoinPublicKeyParser.", PURPLE, "schnorr_data,", NO_COLOR, "\n\
        BitcoinPublicKeyParser.", PURPLE, "unmatched_schnorr_data", NO_COLOR, "\n\n\
    depending on the type of the public key and amount of corresponding signatures.", sep="")
    print("    <unmatched> in name of a dictionary means that the script can't be sure which of the found signatures corresponds to the key.")

    print("\nNow, you also need to know is that there are ", PURPLE, "two modes", NO_COLOR, " of parsing: with verbosity set to True and with verbosity set to False.", sep="")
    print("With verbosity set to", YELLOW, " False ", NO_COLOR, "abovementioned dictionaries are of format\n", sep="")

    print("    {\n", PURPLE,\
    "        'number of block'", NO_COLOR, ": [", YELLOW, "list of all keys found in the block", NO_COLOR, "],\n\
        ...\n\
    }\n", sep="")

    print("With verbosity set to ", YELLOW, "True", NO_COLOR, " the format is the following:\n", sep="")
    print("    {\n        '", PURPLE, "found public key", NO_COLOR, "': [", sep="")
    print("            {")
    print(f"                '{YELLOW}ID{NO_COLOR}': 'ID of a transaction, in which this key was found',")
    print(f"                '{YELLOW}vin/vout{NO_COLOR}': ' where exactly in the transaction',")
    print(f"                '{YELLOW}signature{NO_COLOR}': 'corresponding signature or NaN'")
    print("            },"),
    print("            {")
    print("                ..other occurencies of this key..")
    print("            },"),
    print("            ...")
    print("        ]")
    print("        ..further keys..")
    print("    }")

    print("\nTo change verbosity use BitcoinPublicKeyParser.", PURPLE, "set_verbosity", NO_COLOR, "() function. By default verbosity is set to False.", sep="")


    print("\nThe last thing you need to now is that there is also a BitcoinPublicKeyParser.", PURPLE,"types", NO_COLOR, " dictionary, which contains information about how many transactions there were in a given month and of what types. Try to parse something and have a look inside it!", sep="")

    print("\nThat's it! GLHF!")




if __name__ == "__main__":
    demo()
