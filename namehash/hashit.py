#!/usr/bin/python3

"""
This module mostly is a command line wrapper for hashlib.
Hashing however is agumented to being able to convert the hash to arbitrary base (not only hex).
"""


import hashlib
from hashlib import algorithms_available, algorithms_guaranteed


default_digest_size=128

generic_encodings = {
        'a': ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
        'b': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        'c': '23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ+-=.?#%&@,_~01loIO/\\',
        'e': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"',
        'h': '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
        'H': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
        'x': '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ#%&+,-./=?@\\_~',
        'y': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#%&+,-./=?@\\_~',
    }

encodings = {
        'bin': generic_encodings['h'][:2],
        'oct': generic_encodings['h'][:8],
        'num': generic_encodings['h'][:10],
        'hex': generic_encodings['h'][:16],
        'abc26': 'abcdefghijklmnopqrstuvwxyz',
        'ABC26': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'base32': 'abcdefghijklmnopqrstuvwxyz234567',
        'bh32':  generic_encodings['h'][:32],
        'bech32': 'qpzry9x8gf2tvdw0s3jn54khce6muq7l',
        'zb32':  'ybndrfg8ejkmcpqxot1uwisza345h769',
        'cb32':  '0123456789abcdefghjkmnpqrstvwxyz',
        'gh32':  '0123456789bcdefghjkmnpqrstuvwxyz',
        'abc36': 'abcdefghijklmnopqrstuvwxyz0123456789',
        'base36': generic_encodings['h'][:36],
        'abc52': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'ABC52': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'bb58': '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        'bf58': '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
        'base64': generic_encodings['b'],
        'copy76': generic_encodings['x'],
        'copY76': generic_encodings['y'],
        'base85': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~',
        'basE91': generic_encodings['e'],
        'base95': generic_encodings['a'],
        'bh95'  : generic_encodings['h'],
    }


HASH = 0
BYTES = 1
HEX = 2
INT = 3


def hash_bytes(bytes_object, algorithm, bytes_salt = b''):
    """
    Hash some 'bytes_object' with hash function 'algorithm'.

    Parameters:
        bytes_object:     bytes object for hashing
        algorithm (str):  algorithm identifier as given by algorithms_available
        bytes_salt:       bytes salt

    Returns:
        hash of bytes_object
    """
    alg = hashlib.new(algorithm)
    alg.update(bytes_object)
    alg.update(bytes_salt)
    return alg
def hash_object(str_able, algorithm, salt = ''):
    """
    Hash some 'str_able' object with hash function 'algorithm', if provided by adding 'salt'.

    Parameters:
        str_able:               object for hashing
        algorithm (str):        algorithm identifier as given by algorithms_available
        salt (str-able object): (defaults to '') str(salt) will be appended to str(text) before hashing

    Returns:
        hash of str_able (optionally with salt)
    """
    return hash_str(str(str_able), algorithm, str(salt))
def hash_str(text, algorithm, salt = ''):
    """
    Hash some 'text' with hash function 'algorithm', if provided by adding 'salt'.

    Parameters:
        text (str):      object for hashing
        algorithm (str): algorithm identifier as given by algorithms_available
        salt (str):      (defaults to '') str(salt) will be appended to str(text) before hashing

    Returns:
        hash of text (optionally with salt)
    """
    return hash_bytes(text.encode('utf-8'), algorithm, salt.encode('utf-8'))


def hashed_to_bytes(hashed):
    """
    Takes return value of hash_* function and converts it to bytes hash.
    """
    if hashed.digest_size:
        return hashed.digest()
    else:
        hashed.digest(default_digest_size)
def hashed_to_hex(hashed):
    """
    Takes return value of hash_* function and converts it to hex str hash.
    """
    if hashed.digest_size:
        return hashed.hexdigest()
    else:
        hashed.hexdigest(default_digest_size)
def hashed_to_int(hashed):
    """
    Takes return value of hash_* function and converts it to int.
    """
    bytes_hash = hashed_to_bytes(hashed)
    ret = 0
    for digit in bytes_hash:
        ret *= 256
        ret += digit
    return ret
def hashed_to_base(hashed, base):
    """
    Takes return value of hash_* function and converts it to number with base 'base'.
    """
    return int_to_base(hashed_to_int(hashed), base)
def int_to_base(number, base):
    """
    Takes int number and converts it to number with base 'base'.

    Parameters:
        number (int): number for conversion
        base:         either from encodings / generic_encodings dictionary or some iterable
                      given iterable will be treated as base of len(_)

    Returns:
        number converted to base as an iterable
    """
    if base in encodings:
        base = encodings[base]
    elif base in generic_encodings:
        base = generic_encodings[base]
    base = list(base)
    ret = []
    if number == 0:
        ret.append(base[0])
    else:
        length = len(base)
        while number > 0:
            number, r = divmod(number, length)
            ret.append(base[r])
            #ret = [base[r]] + ret
    return ret[::-1]
#    return ret
#    return reversed(ret)
# efficiency comment: seems to be fastest to use append above and [::-1] here


def hash_bytes_to_bases(bytes_object, algorithm, salt = b'', *bases):
    """
    Combination of hash_bytes(), hash_to_int() and int_to_base() for efficiency.
    """
    hashed = hash_bytes(bytes_object, algorithm, salt)
    number = hashed_to_int(hashed)
    ret = {base: int_to_base(number, base) for base in bases}
    return ret
def hash_str_to_bases(text, algorithm, salt = '', *bases):
    """
    Wrapper for hash_bytes_to_bases.
    """
    return hash_bytes_to_bases(text.encode('utf-8'), algorithm, salt.encode('utf-8'), *bases)
def hash_object_to_bases(str_able, algorithm, salt = '', *bases):
    """
    Wrapper for hash_bytes_to_bases.
    """
    return hash_str_to_bases(str(str_able), algorithm, str(salt), *bases)


def hash(hash_me, algorithm, salt = '', digestbase = HASH):
    """
    General wrapper to hash 'hash_me' object with arbitrary base.
    This function is relatively slow due to several if clauses.
    If speed is a requirement use `hash_str_to_bases()`.

    Parameters:
        hash_me:    object for hashing
        algorithm:  algorithm from algorithms_available
        salt:       salt to be used, defaults to ''
        digestbase: digestbase from constants of this module, defaults to HASH object
                    also keys from encodings / generic_encodings and arbitrary iterables are possible

    Returns:
        Hash as calculated by the parameters with base as given by digestbase.
        If digestbase is HASH it will return the original 
    """
    if type(hash_me) == bytes:
        hashed = hash_bytes(hash_me, algorithm, salt)
    elif type(hash_me) == str:
        hashed = hash_str(hash_me, algorithm, salt)
    else:
        hashed = hash_object(hash_me, algorithm, salt)
    if digestbase == HASH:
        return hashed
    elif digestbase == BYTES:
        return hashed_to_bytes(hashed)
    elif digestbase == HEX:
        return hashed_to_hex(hashed)
    elif digestbase == INT:
        return hashed_to_int(hashed)
    else:
#    elif digestbase in encodings or digestbase in generic_encodings or isiterable(digestbase):
        return hashed_to_base(digestbase)


def verify(text, algorithm, hashed, salt = b'', base = HEX):
    """
    Verify that 'text' with hash function 'algorithm' (and if provided 'salt') hashes to 'hashed'.
    """
    return hash(text, algorithm, salt, base) == hashed


def __do_parse():
    """
    In case we call this module from command line we want to parse the arguments given.
    This function is used for that purpose.
    """
    import argparse

    parser = argparse.ArgumentParser(description = 'Hash some text.')
    #TODO

    return parser.parse_args()


if __name__ == '__main__':
    args = __do_parse()
    #TODO

