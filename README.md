# Ethereum address generator
This repository contains 4 files that will allow you to generate Ethereum (or BSC or something) addresses without using external dependencies. Because of the small size (about 1000 lines) you can check every line of code.

1. `eccrypto.py` based on `imachug/sslcrypto`
2. `keccak.py` based on `mattkelly/KeccakInPython`
3. `mnemonic.py` based on `trezor/python-mnemonic` 
4. `main.py` brings them all together

To minimize the size of the code as much as possible, all optional functionality has been removed from these files.

## Examples
`main.py` can be executable or can be used as `python3 main.py`. In the following we will assume that it is executable.

`./main.py -cm` will create file `result_unixtime.txt` with mnemonic phrase and 10 addresses with private keys

`./main.py -cm -s` will print mnemonic phrase and 10 addresses with private keys to stdout

`./main.py -gm 20` will ask you to enter the mnemonic phrase (not echoed) and then create file `result_unixtime.txt` with 20 addresses + private keys

`./main.py -h` will print help message
