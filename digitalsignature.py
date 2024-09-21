'''
Security Protocols
Digital Signatures
Olivia Takkinen
'''

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import hashlib
import base64

def key_pair(identifier):
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()
    
    private_key = identifier + "_private_pem.pem"
    public_key = identifier + "_pubic_key.pem"

    with open(private_key, 'w') as pr:
        pr.write(private_pem)
    with open(public_key, 'w') as pu:
        pu.write(public_pem)

    return identifier

#take file as input and hash it with SHA-256
def hash(textfile):
    sha256 = hashlib.sha256()
    mv = memoryview(bytearray(128*1024))

    with open(textfile, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv),0):
            sha256.update(mv[:n])

    digest = base64.b64encode(sha256.digest())

    with open('digest.txt', 'w+') as f:
        f.write(str(digest)[2:])
    return 

def encryption(identifier):
    with open('digest.txt', 'r') as file:
        plaintext =  bytes(file.read(), 'utf-8')
        
    file_name = identifier + "_private_pem.pem"
    pr_key = RSA.import_key(open(file_name, 'r').read())

    #encrypt file content // RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(pr_key)
    encrypted = cipher_rsa.encrypt(plaintext)
   
    #add encrypted version to a file
    asym_enc = open('signtag.txt', 'w+')
    asym_enc.write(str(encrypted))
    asym_enc.close()

    print("Encrypted: ", encrypted)
    return 

def decryption(signtag, public_key):
    with open(signtag, 'r') as file:
        ciphertext = file.read()
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    decrypted = cipher_rsa.decrypt(ciphertext)
    print("Decrypted: ", decrypted.decode("utf-8"))
    return

#check integrity of a file 
def unhash():
    sha256 = hashlib.sha256()
    mv = memoryview(bytearray(128*1024))

    with open('text.txt', 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv),0):
            sha256.update(mv[:n])

    counted_hash = base64.b64encode(sha256.digest())
    counted_hash = str(counted_hash)[2:]

    hash_file = 'digest.txt'
    with open(hash_file, 'r') as file:
        hash_content = file.read()
        file.close()

    #hash_content = (hash_content)[2:]
    #hash = str.encode(hash_content.decode)
    #hash_content = base64.b64encode(hash_content.encode())
    
    print(hash_content) #hash read from file 
    print(counted_hash) #hash counted by program 
    
    if hash_content == counted_hash:
        print("integrity safe")
    else:
        print("integrity in danger")
    return

run = True
while run:
    task = input("sign file or verify signature s/v: ")
    if task == "s":
        #generate keys
        identifier = input("enter chosen name: ")
        keys = key_pair(identifier)

        textfile = input("Open file to sign: ")

        #hash text file
        hash(textfile)

        #sign the generated digest with user's private key
        encryption(identifier)

    #verify the signature tag of received message
    elif task == "v":
        signtag = input("give signature tag: ")
        message = input("give message: ")
        key = input("give key as pem file")
        
        with open(key, 'r') as file:
            public_key = RSA.import_key(file.read())

        with open(signtag, 'r') as file:
            tag = file.read()

        with open(message, 'r') as file:
            message = file.read()

        #decryption(tag, public_key)
        unhash()
    run = False