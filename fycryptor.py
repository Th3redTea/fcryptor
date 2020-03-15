#!/usr/bin/python3 

# This is a simple script to encrypt and decrypt files using AES encryption alogorithm #

from Crypto.Hash import SHA256
from  Crypto.Cipher import AES
from Crypto import Random
import sys
import argparse
import os



# Create a command-line argument for the script using argparser

def arguments():
    global argument
    # create a parser object with a description of what the script do
    parser = argparse.ArgumentParser(description="This is a script to encrypt/decrypt files using AES algorithms")
    parser.add_argument('-m',
                        help='mode to encrypt/decrypt a specific file')  # Adding "-m" which stands for mode that can be used
    parser.add_argument('-k', help='The key to use in encryption operation',
                        required=True)  # the key argument and it is required
    parser.add_argument('-f', help='File to decrypt or encrypt', required=True,
                        type=str)  # file argument which is also required
    argument = parser.parse_args()
    return (argument.m,  argument.k, argument.f)  # returns data from the options specified from parser.parse_args()


'''this fucntion encrypt the Key using SHA256 (padding it)'''


def genkey():
    global key
    hash = SHA256.new(str(argument.k).encode("utf-8"))
    key = hash.digest()
    return key

# Function of encryption
def AES_encrypt(file):
    chunk_size = 64 * 1024  # chunk size we should pull out of the file

    file_size = str(os.path.getsize(file)).zfill(16)

    rnd_num = Random.new()  # creat a random number with Random generator
    IV = rnd_num.read(16)  # generate Initialization Vector 16 bytes

    Obej = AES.new(key=key, mode=AES.MODE_CBC, IV=IV)  # creat a AES Object with mode CBC and an IV


    with open(file,
              "rb") as to_encrypt:  # open the file we want to encrypt and read it as "rb" which stands for 'read
        #  binary'

        with open( "enc_" +file, "wb") as encrypted_file:  # open a new file which will be our encrypted output file
            # The longer the key, the stronger the encryption.
            encrypted_file.write(str(file_size).encode("utf-8"))
            encrypted_file.write(IV)
            while True:
                chunk = to_encrypt.read(
                    chunk_size)  # read the original file chunk PS: we already specified the chunk size to read
                if len(chunk) == 0:  # We can't encrypt a empty file
                    print("file is empty. Exiting...")
                    sys.exit()
                # we need to add padding...
                elif len(chunk) % 16 != 0:
                    chunk += " ".encode("utf-8") * (
                        16 - (len(chunk) % 16))  # we need to convert ' ' to bytes / AES_blocksize = 16
                    encrypted_file.write(Obej.encrypt(
                        chunk))  # Here we encrypt the chunk of the original file and write it to our new file using the AES obect
                    print("Encryptin...")
                    print("done!")
                    sys.exit()  # Exit the programme after the encrypting is done

# Function of decryption
def AES_decrypt(file):
    with open("enc_" +file, "rb") as to_decrypt:  # Open the encrypted file withe the "read binary" mode
        chunk_size = 64 * 1024  # chunk size

        file_size = int(to_decrypt.read(16))
        IV = to_decrypt.read(16)
        Obej2 = AES.new(key=key, mode=AES.MODE_CBC, IV=IV)  # create an AES decryption object
        with open("dec_" +file, "wb") as decrypted_file:  # Create a new   file  with "write binary" mode
                while True:
                    chunk = to_decrypt.read(chunk_size)  # chunk of the encrypted file

                    decrypted_file.write(Obej2.decrypt(chunk))

                    decrypted_file.truncate(file_size)
                    print("done!")
                    sys.exit()


# The main program where we connect all functions with each other
def main():
    if argument.m == "encrypt":  # the encrypt mode
        genkey()
        AES_encrypt(argument.f)
    if argument.m == "decrypt":  # the decrypt mode
        genkey()
        AES_decrypt(argument.f)


if __name__ == '__main__':
    arguments()
    main()
