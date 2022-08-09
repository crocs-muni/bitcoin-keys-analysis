import json, os
k = set()
for filename in os.listdir(os.curdir):
	if "data" in filename:
		f = open(filename, "r")
		data = json.load(f).keys()
		for textkey in data:
			item = bytes.fromhex(textkey[2:34])
			k.add(item)
keys_file = open("keys_set", "wb")
for key in k:
	keys_file.write(key)
keys_file.close()
