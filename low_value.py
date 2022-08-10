import os
gathered_keys = set()
num_keys = os.path.getsize("keys_set") // 16
f = open("keys_set", "rb")
g = open("found_low_value", "w")
for i in range (num_keys):
	gathered_keys.add(f.read(16))

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
K = GF(p)
a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
E = EllipticCurve(K, (a, b))
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
E.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)

X = 0*G
for i in range(2**32):
	X = X + G
	temp = bytes.fromhex(Integer((X).xy()[0]).hex()[:32])
	if temp in gathered_keys:
		g.write(str(i) + "\n")
	if (i % 100000) == 0:
		print(i)
g.close()
