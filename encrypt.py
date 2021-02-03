# encrypt.py
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

# Padding character
padding = "@"

# Check for command line args, and if none prompt user for details
if len(sys.argv) != 1:
    if len(sys.argv) <= 3:
        print("Incorrect number of arguments.\nUsage: encrypt passphrase filename message")
        exit(1)
    else:
        # Process command line args as input
        passphrase = sys.argv[1]
        filename = sys.argv[2]
        message = ''
        for i in range(3, len(sys.argv)):
            message += str(sys.argv[i])
            if i < len(sys.argv)-1:
                message += ' '
else:
    # Get user input for passphrase, filename and message
    passphrase = getInput("Please enter a passphrase: ")
    filename = getInput("Please enter the filename: ")
    message = getInput("Please enter the message to encrypt: ")

#Generate Initialisation Vector (also used to salt the password for key generation)
iv = os.urandom(16)

# Make sure the message is a multiple of 16 bytes and if not pad
p_bytes = 16 - (len(message) % 16)

if p_bytes != 0:
    for i in range(0, p_bytes):
        message+=padding

# Derive a 256 bit key from the passphrase, using the IV as salt
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=iv, iterations=100000, backend=backend)
key = kdf.derive(passphrase.encode('UTF-8'))

# Encrypt the message
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ct = encryptor.update(message.encode('UTF-8')) + encryptor.finalize()

# Write cyphertext, iv and padding character to file
try:
    file = open(filename, "w")
    file.write(ct.hex())
    file.write('\n')
    file.write(iv.hex())
    file.write(padding)
    file.close()

except:
    print('File not writable')
    exit(1)

#=======================================================================================================================
