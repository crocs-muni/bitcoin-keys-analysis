#!/bin/python3
import json, os

ecdsa_key_set = set()
schnorr_key_set = set()
DIR = "/home/xyakimo1/crocs/gathered-data/"

for filename in os.listdir(DIR):

    filename = DIR + filename
    f = open(filename, "r")
    data = json.load(f).keys()

    if "ecdsa" in filename:
        for textkey in data:
            item = bytes.fromhex(textkey[2:34])
            ecdsa_key_set.add(item)

    if "schnorr" in filename:
        for textkey in data:
            item = bytes.fromhex(textkey[2:34])
            schnorr_key_set.add(item)

    f.close()


keys_file = open("ecdsa_keys_set", "wb")
for key in ecdsa_key_set:
    keys_file.write(key)
keys_file.close()
print(len(ecdsa_key_set), "ECDSA keys have been written to <ecdsa_keys_set>")

keys_file = open("schnorr_keys_set", "wb")
for key in schnorr_key_set:
    keys_file.write(key)
keys_file.close()
print(len(schnorr_key_set), "Schnorr Signature keys have been written to <schnorr_keys_set>")
