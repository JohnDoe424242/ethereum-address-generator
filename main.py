#!/bin/env python3
from mnemonic import Mnemonic
from keccak import Keccak
from eccrypto import curve

import hashlib
import hmac
import argparse
import time
from getpass import getpass


def sha3_keccak(input_bytes):
    return Keccak().keccak256(input_bytes)


def parse_path(path):
    """
    Parsing seed address path.
    Method from 'two1.bitcoin.crypto'
    """
    if isinstance(path, str):
        # Remove trailing "/"
        p = path.rstrip("/").split("/")
    elif isinstance(path, bytes):
        p = path.decode('utf-8').rstrip("/").split("/")
    else:
        p = list(path)

    return p


def from_path(root_key, path):
    """
    Generate keys from path.
    Method from 'two1.bitcoin.crypto'
    """
    p = parse_path(path)

    if p[0] == "m":
        p = p[1:]

    keys = [root_key]
    for i in p:
        if isinstance(i, str):
            hardened = i[-1] == "'"
            index = int(i[:-1], 0) | 0x80000000 if hardened else int(i, 0)
        else:
            index = i
        k = keys[-1]

        keys.append(from_parent(parent_key=k, index=index))

    return keys


def from_parent(parent_key, index):
    """
    Generate child private key from parent private key.
    Method from 'two1.bitcoin.crypto'.
    """

    if index < 0 or index > 0xffffffff:
        raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

    # Get curve n parameter.
    curve_n = int(curve.params['n'])

    # Unpack parent key
    parent_key, hmac_key = parent_key

    if index & 0x80000000:
        hmac_data = b'\x00' + parent_key.to_bytes(length=32, byteorder='big')
    else:
        # Create default curve public key from private
        public_key = curve.private_to_public(
            parent_key.to_bytes(length=32, byteorder='big'))

        # Get public key coordinates
        x, y = curve.decode_public_key(public_key)
        x = int.from_bytes(x, byteorder='big')
        y = int.from_bytes(y, byteorder='big')

        # Generate hmac data
        hmac_data = (bytes([(y & 0x1) + 0x02]) +
                     x.to_bytes(curve._backend.public_key_length, 'big'))
    hmac_data += index.to_bytes(length=4, byteorder='big')

    I = hmac.new(hmac_key, hmac_data, hashlib.sha512).digest()
    Il, Ir = I[:32], I[32:]

    parse_Il = int.from_bytes(Il, 'big')
    if parse_Il >= curve_n:
        return None

    child_key = (parse_Il + parent_key) % curve_n
    if child_key == 0:
        # Incredibly unlucky choice
        return None

    return child_key, Ir


def get_public_from_private(private_key):
    """
    :param private_key: private key as hex
    :return: public key as hex
    """
    public_key = curve.private_to_public(
        int(private_key, 16).to_bytes(length=32, byteorder='big'))
    return public_key.hex()[2:]


def get_address_from_public_key(public_key):
    """
    :param public_key: public key as hex
    :return: address str
    """
    public_keccak = sha3_keccak(bytes.fromhex(public_key)).hex()
    return '0x' + public_keccak[-40:]


def create_pk():
    return curve.new_private_key().hex()


def create_phrase():
    mn = Mnemonic()
    return mn.generate()


def generate_addresses(phrase, number=1):
    """
    Generate list of dicts with keys 'pk' and 'address'
    """
    result = []
    master_seed = b'Bitcoin seed'
    for i in range(number):
        seed_address_path = "m/44'/60'/0'/0/" + str(i)
        mn = Mnemonic()
        mn_seed = mn.to_seed(phrase)

        _I = hmac.new(master_seed, mn_seed, hashlib.sha512).hexdigest()
        master_key = (int(_I[:64], 16), bytes.fromhex(_I[64:]))
        keys = from_path(root_key=master_key, path=seed_address_path)
        private_key = keys[-1][0].to_bytes(length=32, byteorder='big').hex()
        public_key = get_public_from_private(private_key)
        address = get_address_from_public_key(public_key)
        result.append({'pk': private_key, 'address': address})
    return result


def generate_address_from_pk(pk_hex):
    public_key = get_public_from_private(pk_hex)
    address = get_address_from_public_key(public_key)
    return address


_mnemonic_test = "view naive desk recycle scorpion sorry glide wrong moment top magnet slight"
_private_key_test = "d0f8db5f41f857307ef80f2a97d2ac2b0186322e8b8105e0ecac6131ff408a6b"
_address_test = "0xefdb65b2ae9f3440856f3d0a9ca24490c74e50ee"

_address = generate_addresses(_mnemonic_test)[0]['address']
_address_pk = generate_address_from_pk(_private_key_test)
assert (_address_test == _address == _address_pk)


def write_to_temp_file(str_data):
    timestamp = int(time.time())
    filename = f'result_{timestamp}.txt'
    with open(filename, 'w') as fl:
        fl.write(str_data)


def run_phrase_creation(stdout, addresses_number):
    new_phrase = create_phrase()
    dict_list = generate_addresses(new_phrase, addresses_number)
    lines = [new_phrase]
    for d in dict_list:
        lines.append(f"{d['pk']}:{d['address']}")
    print_line = '\n'.join(lines)
    if stdout:
        print(print_line)
    else:
        write_to_temp_file(print_line)


def run_pk_creation(stdout=False):
    new_pk = create_pk()
    new_address = generate_address_from_pk(new_pk)
    line = f"{new_pk}:{new_address}"
    if stdout:
        print(line)
    else:
        write_to_temp_file(line)


def run_generation_from_phrase(stdout, addresses_number):
    phrase = getpass('Enter mnemonic phrase (not echoed):')
    dict_list = generate_addresses(phrase, addresses_number)
    lines = [phrase]
    for d in dict_list:
        lines.append(f"{d['pk']}:{d['address']}")
    print_line = '\n'.join(lines)
    if stdout:
        print(print_line)
    else:
        write_to_temp_file(print_line)


def run_generation_from_pk(stdout):
    pk = getpass('Enter private key (not echoed):')
    new_address = generate_address_from_pk(pk)
    if stdout:
        print(new_address)
    else:
        line = f"{pk}:{new_address}"
        write_to_temp_file(line)


def run_phrase_check():
    phrase = getpass('Enter mnemonic phrase (not echoed):')
    check_result = Mnemonic().check(phrase)
    if check_result:
        print("Phrase is OK")
    else:
        print("Phrase may be corrupted!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-cm',
        help='Create new mnemonic phrase and derive N addresses (default:10)',
        nargs='?',
        type=int,
        const=10,
        metavar='N',
        default=False)
    parser.add_argument('-cp',
                        help='Create new private key',
                        action='store_true')
    parser.add_argument(
        '-gm',
        help=
        'Generate addresses and private keys from mnemonic phrase (default:10)',
        nargs='?',
        type=int,
        const=10,
        metavar='N',
        default=False)
    parser.add_argument('-gp',
                        help='Generate address from private key',
                        action='store_true')
    parser.add_argument('-c',
                        help='Check mnemonic phrase',
                        action='store_true')
    parser.add_argument('-s',
                        help='Print result to stdout instead of file',
                        action='store_true')
    args = parser.parse_args()
    if args.cm:
        run_phrase_creation(args.s, args.cm)
    elif args.cp:
        run_pk_creation(args.s)
    elif args.gm:
        run_generation_from_phrase(args.s, args.gm)
    elif args.gp:
        run_generation_from_pk(args.s)
    elif args.c:
        run_phrase_check()
    else:
        parser.print_help()
