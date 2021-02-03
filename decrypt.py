# decrypt.py
# by Daryl Poyner

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
backend = default_backend()

#=======================================================================================================================
# Functions
#=======================================================================================================================
# This function repeatedly prompts for input until something other than whitespace is entered.
def getInput(prompt):
    while True:
        text = input(prompt).strip()
        if len(text) != 0:
            return text
#=======================================================================================================================
# Main Program
#=======================================================================================================================

# Check for command line args, and if none prompt user for details
if len(sys.argv) != 1:
    if len(sys.argv) <= 2:
        print("Incorrect number of arguments.\nUsage: encrypt passphrase filename message")
        exit(1)
    else:
        # Process command line args as input
        passphrase = sys.argv[1]
        filename = sys.argv[2]
        args = 1
else:
    # Get user input for passphrase and filename
    passphrase = getInput("Please enter the passphrase: ")
    filename = getInput("Please enter the filename: ")
    args = 0

try:
    # Open the file and seperate cyphertext, iv and padding character
    file = open(filename, "r")
    buffer = file.readline()
    ct = bytes.fromhex(buffer[:-1])
    buffer = file.readline()
    iv = bytes.fromhex(buffer[:-1])
    padding = buffer[-1:]
    file.close()

except:
    print('File not found')
    exit(1)
    

# Derive the 256 bit key from the passphrase, using the IV as salt
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=iv, iterations=100000, backend=backend)
key = kdf.derive(passphrase.encode('UTF-8'))

# Decrypt the message
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize()

try:
    # Will throw an exception if the wrong key is used
    text = pt.decode('UTF-8')
    # Strip padding characters
    text = text.strip(padding)
    # Display decrypted plaintext
    print(text)
    if args == 1:
        file = open(filename, "w")
        file.write(text)
        file.close()

except:
    print('Incorrect Password')
    exit(1)

#=======================================================================================================================
