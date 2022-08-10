import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

p = 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
q = 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917


with open("../key.pub") as f:
    content = f.read()
    
pub_key = RSA.import_key(content)
n, e = pub_key.n, pub_key.e
print("N =", n)
print("e =", e)

assert n == p * q

phi_n = (p - 1) * (q - 1)
d = inverse(e, phi_n)

private_key = RSA.construct((n, e, d))
cipher_rsa = PKCS1_OAEP.new(private_key)

with open("../secret.enc") as f:
    secret = f.read().encode()

secret = base64.b64decode(secret)
text = cipher_rsa.decrypt(secret).decode()

print("Plain text:", text)