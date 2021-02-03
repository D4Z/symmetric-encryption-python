Simple Symmetric Python Encryption using cryptography.io module. https://cryptography.io

Encryption Program

The encryption program can be executed with or without command line arguments. If the program receives the correct number of arguments, it processes the first argument as the passphrase, the second argument as the filename and all subsequent arguments are processed as the message text. This is to allow other programs to use the encryption and decryption functionality by calling it from the command line. If no command line arguments have been entered, the program will prompt the user for the password, filename and message.

A random 128bit Initialisation Vector (IV) is generated, which is also used to salt the password which is used to derive the 256bit encryption key used to encrypt the plaintext data, derived using the PBKDF2HMAC algorithm.
The message length is checked and padded with ‘@’ to 16bytes, then encrypted with the 256bit derived key using AES256 algorithm in CBC mode. The resulting cyphertext is written to the supplied file, along with the IV and padding character.

Decryption Program

The decryption program can also be executed with or without command line arguments. If the program receives the correct number of arguments, it processes the first argument as the passphrase, the second argument as the filename. If no command line arguments have been entered, the program will prompt the user for the password and filename.
The file containing the cyphertext is opened and read, and the data is separated into the cyphertext, the IV and the padding character. The encryption/decryption key is then derived from the password/iv combination, and this is used to decrypt the cyphertext. The padding character is then removed from the resulting plaintext, which is then displayed to the user. If an incorrect password is entered, the program will throw an exception, output an error message and exit.

Program Usage Instructions

If the cryptography module has not been installed it can be installed with the command:
pip install cryptography
encryption.py

The encryption program can be executed by executing the command:

python3 encrypt.py

If command line arguments are to be used, the format is:

python3 encrypt.py <password> <filename> <message to encrypt>

<password> Password used to generate the encryption key.
<filename> Name of the file to store cyphertext/iv/padding character.
<message to encrypt> The text of the message to be encrypted.

decryption.py

The decryption program can be executed by executing the command:

python3 decrypt.py

If command line arguments are to be used, the format is:

python3 decrypt.py <password> <filename>

<password> Password that used to generate the encryption key.
<filename> Name of the file containing the cyphertext/iv/padding character.