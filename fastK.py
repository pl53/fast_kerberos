#! /bin/env python2.7

import argparse
import getpass
import hashlib
import os
import subprocess
from itertools import starmap, cycle

def encrypt(message, key):
    # single letter encrpytion.
    def enc(c, k): return chr((ord(k) + ord(c)) % 256)

    return "".join(starmap(enc, zip(message, cycle(key))))

def decrypt(message, key):
    # single letter decryption.
    def dec(c, k): return chr((ord(c) - ord(k)) % 256)

    return "".join(starmap(dec, zip(message, cycle(key))))

FILENAME = os.path.join(os.getenv("HOME", '.'), ".password.encrypted")

parser = argparse.ArgumentParser()
parser.add_argument("--init", action="store_true", help="store encrypted password")
args = parser.parse_args()

short_pass = getpass.getpass("Input short passcode "
        "(it is the passcode to encrypt your real password): ")
hash_obj = hashlib.sha512((short_pass + 'a').encode("utf-8"))

# Pad random number of '0' to hide the password length
# 3-7 should be reasonable, long paddings don't make sense
short_num = reduce(lambda accum, c: accum*62 + ord(c) - ord('A'), short_pass, 0)
start_index = short_num % 5 + 3 # padding length

if (args.init): # store password
    short_pass_again = getpass.getpass("Input the short passcode again: ")
    if short_pass != short_pass_again:
        print ("Short passcodes don't match!")
        exit(1)

    password = getpass.getpass("Input the password: ")
    password_again = getpass.getpass("Input the password again: ")

    if password != password_again:
        print ("Passwords don't match!")
        exit(1)

    if len(password) > 500: # It would be insane ...
        print ("password is too long. Are your serious?")
        exit(1)

    padded_password = start_index*'0' + password # padd password to hide its length
    encryped_password = encrypt(padded_password, hash_obj.hexdigest())

    with open(FILENAME, "w") as fp:
        fp.write(encryped_password)

    print("Encrypted password: " + encryped_password)
    print("Password stored successfully!")

else: # read password and use it to acquire kerberos ticket
    try:
        with open(FILENAME, "r") as fp:
            encrypted_password = fp.read()
    except IOError:
        print ("FATAL: no password stored!")
        print ("Please use 'easyK.py --init' to store password first.")
        exit(1)

    FNULL = open(os.devnull, 'w') # do not send output from kerberos to console
    password = decrypt(encrypted_password, hash_obj.hexdigest())
    echo = subprocess.Popen(["/bin/echo", password[start_index:]], stdout=subprocess.PIPE)
    kinit = subprocess.Popen(["/usr/kerberos/bin/kinit"], stdin=echo.stdout, \
                stdout=FNULL, stderr=subprocess.STDOUT)
    rcode = kinit.wait()

    if rcode == 0:
        print("Acquire Kerberos ticket successfully!")
    else:
        print("Failed to acquire Kerberos ticket!")
