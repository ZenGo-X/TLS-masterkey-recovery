import os
from abc import ABC, abstractmethod

from asn1crypto.keys import PublicKeyInfo
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from prf import prf as _prf

#import ec_curves
def print_hex(b):
    return ':'.join('{:02X}'.format(a) for a in b)



def main():
    print("calculating TLS master_sercet")

# paintext values taken from traffic PCAP file, should be refactored into parameters
    client_random = bytes.fromhex('64d34a0100000000000000000000000000000000000000000000000000000000')
    server_random = bytes.fromhex('64d34a013d27d7d87c349888e5843796d970e0b42b7b64a8444f574e47524401')
    server_public_key_raw = bytes.fromhex('04c1070dba8144b6d6cec82375be84db88162b3f361e145e239bb6765af61cb91fdb65049bfb46b4d4375cf9fa80b6e1d9b875a797d864b662172e168a174e3d1c')

#  client's ephemeral private key is a known value 
    private_key = 1

    key = ec.derive_private_key(
            private_value = private_key,
            curve=ec.SECP256R1(),
            backend=default_backend(),
        )
    args = (
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo
    )
    der = key.public_key().public_bytes(*args)

    info = PublicKeyInfo.load(der)
   
    header = der[:len(der) - len(server_public_key_raw)]
    server_public_key = load_der_public_key(header + server_public_key_raw, default_backend())

    pre_master_secret = key.exchange(ec.ECDH(), server_public_key)
    print(print_hex(pre_master_secret))
    master_secret = _prf(pre_master_secret, b'master secret', client_random + server_random, SHA384(), 48)
    print(print_hex(master_secret))

#saving to master file
    file = open("masterkey.txt","w+")
    file.write("CLIENT_RANDOM " + client_random.hex() + " " +  master_secret.hex() + "\n")
    file.close()

if __name__ == "__main__":
    main()
