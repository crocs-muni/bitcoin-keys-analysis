#!/usr/bin/python3

import sys
import json
import math

YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NO_COLOR='\033[0m'

if len(sys.argv) < 2:
    print("USAGE: ./print_json_keys.py <keys>.\nWhere <keys> is path to a JSON file generated with parse.py", file = sys.stderr)
    exit(1)

for name in sys.argv[1:]:
    print("---", name, " ---")
    file = open(name)
    dict = json.load(file)
    file.close()

    def draw_pipeline(spaces: int): # it's hard to give reasonable names, but I hope it's not that important.
        print(' ' * spaces, end = '')
        print("|--> ", end = '')

    key_count = 0
    for key in dict.keys():
        key_count += 1
        print(key_count, ". Key: ", YELLOW, key, NO_COLOR, sep = '')

        tx_count = 0
        for tx in dict[key]:
            tx_count += 1
            spaces = math.ceil(math.log(key_count, 10)) + len(". K")
            draw_pipeline(spaces)
            print(tx_count, ". Transaction: ", PURPLE, tx["ID"], NO_COLOR, sep = '')
            """ # Uncomment to print time and signature
            draw_pipeline(key_count // 10 + len(". K") + tx_count//10 + len(". T") + len("|--> "))
            print("Time: ", tx["time"], sep = '')
            """
            if "signature" in tx.keys():
                draw_pipeline(spaces +  len(". T"))
                print("Signature: ", tx["signature"], sep = '')
            elif "signatures" in tx.keys():
                for i in range(len(tx["signatures"])):
                    draw_pipeline(spaces + len(". T"))
                    print(i+1, ". Signature: " , tx["signatures"][i], sep = '')

exit(0)
