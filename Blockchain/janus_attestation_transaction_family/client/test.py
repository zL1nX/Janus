from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

# Generate a private key
private_key = ECC.generate(curve='secp256k1')

# Create a public key from the private key
public_key = private_key.public_key()

# Sign a message
message = b'My message'
hash_obj = SHA256.new(message)
signer = DSS.new(private_key, 'fips-186-3')
signature = signer.sign(hash_obj)

# Verify the signature
hash_obj = SHA256.new(message)
verifier = DSS.new(public_key, 'fips-186-3')
try:
    verifier.verify(hash_obj, signature)
    print("Signature is valid.")
except ValueError:
    print("Signature is not valid.")