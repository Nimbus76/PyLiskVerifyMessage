"""
Interactive Verification of Lisk Signed Message.

To Sign A Message, You may use Lisk Hub by
creating a URL in the following format:
lisk://sign-message?message=In Lisk We Trust

The pynacl libary is required. Try python -m pip install pynacl

"""

import nacl.encoding
import nacl.signing
import binascii
import sys


def main():
    """Message Verification."""
    header()

    check_another = True

    while check_another is True:

        try:

            msg = getmessage()

            message, public_key, signature = parse_user_signature(msg)

            verified_message = verify_message(message, signature, public_key)

            lisk_address = getAddressFromPublicKey(public_key)

            check_another = success(message, verified_message, public_key,
                                    lisk_address)

        except:

            check_another = failure()


def header():
    """Print program header and instructions."""
    print('''
-----------------------------------------------------
            _   ___           __
           / | / (_)___ ___  / /_  __  _______
          /  |/ / / __ `__ \/ __ \/ / / / ___/
         / /|  / / / / / / / /_/ / /_/ (__  )
        /_/ |_/_/_/ /_/ /_/_.___/\__,_/____/

 _    __          _ ____
| |  / /__  _____(_) __/_  __
| | / / _ \/ ___/ / /_/ / / /
| |/ /  __/ /  / / __/ /_/ /
|___/\___/_/  /_/_/  \__, /
                    /____/
-----------------------------------------------------
          LISK SIGNED MESSAGE VERIFICATION

-----------------------------------------------------

WINDOWS COMMAND:
    CTRL-V THEN ENTER TO PASTE
    CTRL-Z THEN ENTER TO SUBMIT

OS X:
    COMMAND-V THEN ENTER TO PASTE
    CTRL-D TO SUBMIT

PYTHON IDLE:
    CTRL-V THEN ENTER TO PASTE
    CTRL-D TO SUBMIT

NOTE: PyNaCl Library Required.
Try:  python -m pip install pynacl
      https://github.com/pyca/pynacl/

-----------------------------------------------------
Paste Signed Message Below:
''')


def getmessage():
    """Get Lisk Signed Message from user."""
    msg = sys.stdin.readlines()

    message = ''.join(msg)

    return message


def parse_user_signature(message):
    """Isolate message, public key, and singature from Lisk Signed Message."""
    msgStartIndex = message.find('-----MESSAGE') + 18

    msgEndIndex = message.find('-----PUBLIC') - 1

    pkStartIndex = message.find('-----PUBLIC') + 21

    pkEndIndex = message.find('-----SIGNATURE') - 1

    sigStartIndex = pkEndIndex + 21

    sigEndIndex = message.find('-----END') - 1

    msg = message[msgStartIndex:msgEndIndex]

    pk = message[pkStartIndex:pkEndIndex]

    sig = message[sigStartIndex:sigEndIndex]

    return msg, pk, sig


def verify_message(message, signature, public_key):
    """Verify signature against message and public key."""
    msgBytes = digestMessage(message)

    signatureBytes = hex_to_bytes(signature)

    verify_key = nacl.signing.VerifyKey(public_key,
                                        encoder=nacl.encoding.HexEncoder)

    verified_message = verify_key.verify(msgBytes, signatureBytes)

    return verified_message


def digestMessage(message):
    """Prepare and double-hash message."""
    SIGNED_MESSAGE_PREFIX = 'Lisk Signed Message:\n'

    SIGNED_MESSAGE_PREFIX_LENGTH = int_to_varint(len(SIGNED_MESSAGE_PREFIX))

    SIGNED_MESSAGE_PREFIX_BYTES = bytes(SIGNED_MESSAGE_PREFIX, 'utf-8')

    msgBytes = bytes(message, 'utf-8')

    msgLenBytes = int_to_varint(len(message))

    dataBytes = SIGNED_MESSAGE_PREFIX_LENGTH + SIGNED_MESSAGE_PREFIX_BYTES \
        + msgLenBytes + msgBytes

    hash = nacl.bindings.crypto_hash_sha256

    return hash(hash(dataBytes))


def getAddressFromPublicKey(publicKey):
    """Get Lisk address from public key in Lisk Signed Message."""
    publicKey = bytes(publicKey, 'utf-8')

    publicKey = binascii.unhexlify(publicKey)

    publicKeyHash = nacl.bindings.crypto_hash_sha256(publicKey)

    i = 0

    pkBytes = bytearray()

    while i < 8:

        pkBytes.append(publicKeyHash[7-i])

        i += 1

    liskAddress = str(int.from_bytes(pkBytes, byteorder='big')) + 'L'

    return liskAddress


def success(message, verified_message, public_key, lisk_address):
    """Display Success Message and determine exit intention."""
    print()

    print('''-----------------------------------------------------
         _____                                __
        / ___/__  _______________  __________/ /
        \__ \/ / / / ___/ ___/ _ \/ ___/ ___/ /
       ___/ / /_/ / /__/ /__/  __(__  |__  )_/
      /____/\__,_/\___/\___/\___/____/____(_)

-----------------------------------------------------
           SIGNATURE SUCCESSFULLY VERIFIED
                The Signature is Valid
-----------------------------------------------------''')

    print('Message: \t' + message)
    print('Lisk Address: \t' + lisk_address)
    print('Public Key: \t' + public_key)
    print('''
-----------------------------------------------------
               Please Vote for Nimbus
           Donate to 12313256070705265970L

-----------------------------------------------------''')
    return check_another_sig()


def failure():
    """Display failure message and determine exit intention."""
    print('''-----------------------------------------------------

               ______      _ __         __
              / ____/___ _(_) /__  ____/ /
             / /_  / __ `/ / / _ \/ __  /
            / __/ / /_/ / / /  __/ /_/ /
           /_/    \__,_/_/_/\___/\__,_/

-----------------------------------------------------
           SIGNATURE VERIFICATION FAILED
            The Signature is Not Valid
-----------------------------------------------------
               Please Vote for Nimbus
           Donate to 12313256070705265970L
-----------------------------------------------------''')

    return check_another_sig()


def check_another_sig():
    """Determine exit intention."""
    check = input("Check Another Signature? (y/n):")

    print()

    if check.lower() == 'y':

        print('Paste Signed Message Below:')

        return True

    else:

        return False


def int_to_varint(val):
    """Convert integer into varible integer."""
    if val < 253:
        return val.to_bytes(1, 'little')
    elif val <= 65535:
        return b'\xfd'+val.to_bytes(2, 'little')
    elif val <= 4294967295:
        return b'\xfe'+val.to_bytes(4, 'little')
    else:
        return b'\xff'+val.to_bytes(8, 'little')


def hex_to_bytes(hexed):
    """Convert from hexadecimal to bytes."""
    if len(hexed) & 1:

        hexed = '0' + hexed

    return bytes.fromhex(hexed)


main()
