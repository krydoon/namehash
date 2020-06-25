#!/usr/bin/python3

"""
This module mostly is a command line wrapper for hashlib.
Hashing however is agumented to being able to convert the hash to arbitrary base (not only hex).
"""


import hashlib
import math
import uuid
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
        'HEX': generic_encodings['H'][:16],
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
    return int_to_base(hashed_to_int(hashed), base, fill_digits(hashed, base))
def int_to_base(number, base, fill_digits = 0):
    """
    Takes int number and converts it to number with base 'base'.

    Parameters:
        number (int): number for conversion
        base:         either from encodings / generic_encodings dictionary or some iterable
                      given iterable will be treated as base of len(_)

    Returns:
        number converted to base as an iterable
    """
    base = __get_base_iterable(base)
    return __int_to_base(number, base, fill_digits = fill_digits)

def __int_to_base(number, base, fill_digits = 0):
    ret = []
    if number == 0:
        ret.append(base[0])
    else:
        length = len(base)
        while number > 0:
            number, r = divmod(number, length)
            ret.append(base[r])
            #ret = [base[r]] + ret
    while len(ret) < fill_digits:
        ret.append(base[0])
    return ret[::-1]
#    return ret
#    return reversed(ret)
# efficiency comment: seems to be fastest to use append above and [::-1] here
def __get_base_iterable(base):
    if base in encodings:
        base = encodings[base]
    elif base in generic_encodings:
        base = generic_encodings[base]
    elif type(base) == str and len(base) > 0 and base[0] in generic_encodings and base[1:].isnumeric():
        count = int(base[1:])
        base = generic_encodings[base[0]][:count]
    base = list(base)
    return base


def fill_digits(hashed, target_base):
    """
    Given some hash and a target_base this function can be used to figure out how many digits we should expect.
    """
    base = __get_base_iterable(target_base)
    return __fill_digits(hashed, len(base))

__bytelog = math.log(256)
def __fill_digits(hashed, base_length):
    return math.ceil(hashed.digest_size * __bytelog / math.log(base_length))

def hash_bytes_to_bases(bytes_object, algorithm, *bases, salt = b''):
    """
    Combination of hash_bytes(), hash_to_int() and int_to_base() for efficiency.

    Parameters:
        base in bases can be any key from encodings or generic_encodings or any iterable, e.g. '0123456789'
    """
    # First we generate the hash of interest.
    hashed = hash_bytes(bytes_object, algorithm, salt)
    # Then we convert it to a number.
    number = hashed_to_int(hashed)
    # The following is an optimisation in the case of several bases with same length.
    bases = {name: __get_base_iterable(name) for name in bases}
    base_len_dic = {len(bases[name]): [] for name in bases}
    for name in bases:
        base_len_dic[len(bases[name])].append(name)
    ret = {}
    for length in base_len_dic:
        base_names = base_len_dic[length]
        fill_digits = __fill_digits(hashed, length)
        # In case only one base of that length is asked for we use regular computation.
        if len(base_names) == 1:
            name = base_names[0]
            ret[name] = __int_to_base(number, bases[name], fill_digits = fill_digits)
        # In case of multiple bases with the same length we use a dummy conversion to map all the others.
        else:
            dummy_base = range(length)
            conversion = __int_to_base(number, dummy_base, fill_digits = fill_digits)
            for name in base_names:
                base = bases[name]
                base_conversion = [base[index] for index in conversion]
                ret[name] = base_conversion
    return ret
def hash_str_to_bases(text, algorithm, *bases, salt = ''):
    """
    Wrapper for hash_bytes_to_bases.
    """
    return hash_bytes_to_bases(text.encode('utf-8'), algorithm, salt = salt.encode('utf-8'), *bases)
def hash_object_to_bases(str_able, algorithm, *bases, salt = ''):
    """
    Wrapper for hash_bytes_to_bases.
    """
    return hash_str_to_bases(str(str_able), algorithm, salt = str(salt), *bases)


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
        return hashed_to_base(hashed, digestbase)


def verify(text, algorithm, hashed, salt = b'', base = HEX):
    """
    Verify that 'text' with hash function 'algorithm' (and if provided 'salt') hashes to 'hashed'.
    """
    properhash = hash(text, algorithm, salt, base)
    if type(hashed) == str:
        properhash = ''.join(properhash)
    return properhash == hashed


def __do_parse():
    """
    In case we call this module from command line we want to parse the arguments given.
    This function is used for that purpose.
    """
    import argparse

    parser = argparse.ArgumentParser(description = 'Hash some text.')
    parser.add_argument('text', help = 'text for hashing', type = str, nargs = '?')
    parser.add_argument('algorithm', help = 'specify algorithm(s), defaults to \"guaranteed\"', default = 'guaranteed', nargs = '*')
    parser.add_argument('-s', '--salt', help = 'give specific salt to augment text with', type = str, default = '')
    parser.add_argument('-r', '--randomsalt', help = 'use random salt', action = 'store_true')
    parser.add_argument('-l', '--list', help = 'list \"guaranteed\" and \"available\" algorithms', action = 'store_true')
    parser.add_argument('-b', '--base', help = 'define base(s) for output, defaults to \"hex\"', default = ['hex'], nargs = '+')
    parser.add_argument('-x', '--showbases', help = 'show bases that are generically available', action = 'store_true')
    parser.add_argument('-v', '--verify', help = 'verify given hash to be correct', type = str)

    return parser.parse_args()


def __case_not_quite_sensitive(s):
    for c in s:
        if c in 'abcdefghijklmnopqrstuvwxyz':
            return s.lower()+'0'
        elif c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            return s.lower()+'1'
    return s

if __name__ == '__main__':
    args = __do_parse()
    if args.list:
        print('Guaranteed algorithms (used for \"-a guaranteed\" option):', *sorted(algorithms_guaranteed), sep = '\n    ')
        print('Available algorithms (used for \"-a available\" or \"-a all\" options):', *sorted(algorithms_available), sep = '\n    ')
    elif args.showbases:
        print('Builtin base encodings:')
        print(*[name.rjust(10) + ': \"' + encodings[name] + '\"' for name in sorted(encodings, key = __case_not_quite_sensitive)], sep = '\n')
        print('Builtin generic encodings:')
        print(*[name.rjust(10) + ': \"' + generic_encodings[name] + '\"' for name in sorted(generic_encodings, key = __case_not_quite_sensitive)], sep = '\n')
        print('Generic encodings may also be used in the form _[0-9]+, for instance \"h5\" gives encoding \"01234\"')
    elif args.verify:
        assert(len(args.algorithm) == 1)
        assert(len(args.base) == 1)
        assert(args.text)
        assert(not args.randomsalt)
        print(verify(args.text, args.algorithm[0], args.verify, args.salt, args.base[0]))
    elif args.text:
        salt = args.salt
        if args.randomsalt:
            salt += uuid.uuid4().hex
        if args.algorithm == 'all' or args.algorithm == 'available':
            algorithms = algorithms_available
        elif args.algorithm == 'guaranteed':
            algorithms = algorithms_guaranteed
        else:
            algorithms = args.algorithm
        if args.base == 'hex':
            bases = ['hex']
        else:
            bases = args.base
        max_base_length = max([len(str(name)) for name in bases])
        if len(salt) > 0:
            print('Using salt: \"', salt, '\"', sep = '')
        for algorithm in algorithms:
            result = hash_str_to_bases(args.text, algorithm, *bases, salt = salt)
            print('Algorithm', algorithm, 'gives:')
            print(*[str(base).rjust(max_base_length+2) + ': \"' + ''.join(result[base]) + '\"' for base in result], sep = '\n')
    else:
        print('No input given, no interactive mode available yet.')

