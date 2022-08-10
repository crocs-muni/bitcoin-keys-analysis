#!/bin/python3
import json, os

ecdsa_key_set = set()
schnorr_key_set = set()
DIR = "/home/xyakimo1/crocs/gathered-data/"

for filename in os.listdir(DIR):

    filename = DIR + filename
    if os.path.isdir(filename):
        continue

    f = open(filename, "r")
    data = json.load(f).keys()

    if "ecdsa" in filename:
        for textkey in data:
            item = bytes.fromhex(textkey[2:34])
            ecdsa_key_set.add(item)

    if "schnorr" in filename:
        for textkey in data:
            item = bytes.fromhex(textkey[:32]) # Have to learn more about Schnorr Signatures
            schnorr_key_set.add(item)

    f.close()

filename = DIR + "binary_key_sets/" + "ecdsa_key_set"
keys_file = open(filename, "wb")
for key in ecdsa_key_set:
    keys_file.write(key)
keys_file.close()
print(len(ecdsa_key_set), "ECDSA keys have been written to", filename)

filename = DIR + "binary_key_sets/" + "schnorr_key_set"
keys_file = open(filename, "wb")
for key in schnorr_key_set:
    keys_file.write(key)
keys_file.close()
print(len(schnorr_key_set), "Schnorr Signature keys have been written to", filename)
