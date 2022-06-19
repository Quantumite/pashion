# pashion README
## General Information
- Author: Austin Norby
- Date 06/19/2022
- Description: A simple python hash cracker. This script makes use of Python's hashlib module. The script will accept single or multiple hashes or guesses in an attempt to crack the hash.
- Tested on Windows 10 with Python 3.10.2

## Video Link
- [Link]()

## Installation
- This was not turned into a python module so there is no installation. Place in the directory and run using Python 3 (tested on Python 3.10.2).

## Help Menu
```python
usage: main.py [-h] [-v] [-g GUESS] [-G GUESS_FILE] [-d HASH] [-D HASH_FILE] [-a HASH_NAME]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Print extra information during execution. Useful for debugging.
  -g GUESS, --guess GUESS
                        Supply a single guess to check against any provided hash(es).
  -G GUESS_FILE, --guess_file GUESS_FILE
                        Supply a file name that holds many guesses. Format: single guess per line.
  -d HASH, --digest HASH
                        Supply a single hash/digest to be checked against guess(es). Format: hexadecimal or binary.
  -D HASH_FILE, --digest_file HASH_FILE
                        Supply a file name that holds many hashes/digests. Format: single hash/digest per line.
  -a HASH_NAME, --algorithm HASH_NAME
                        Supply the hash algorithm you intended to use during execution. Algorithms available: {'sha384', 'sha256', 'sha3_512', 'shake_128', 'md4', 'sha512_224', 'sha512_256', 'sha224',        
                        'sha3_256', 'sm3', 'sha1', 'sha3_384', 'mdc2', 'sha512', 'ripemd160', 'shake_256', 'md5', 'whirlpool', 'md5-sha1', 'blake2b', 'sha3_224', 'blake2s'}
```

## Examples
- Single guess, single hash
```powershell
PS G:\Other computers\Origin PC\DSU\Security Tool Development - CSC842\pashion\pashion> py -3 .\main.py -g hello -d 5d41402abc4b2a76b9719d911017c592 -a md5
[*] HASH CRACKED: b'hello'
```

- Single guess, multiple hashes
```powershell
PS G:\Other computers\Origin PC\DSU\Security Tool Development - CSC842\pashion\pashion> py -3 .\main.py -g 1 -D .\test_hashes.txt -a md5
[*] HASH CRACKED: 1
```

- Multiple guesses, single hash
```powershell
PS G:\Other computers\Origin PC\DSU\Security Tool Development - CSC842\pashion\pashion> py -3 .\main.py -G .\test_guesses.txt -d 5d41402abc4b2a76b9719d911017c592 -a md5
[*] HASH CRACKED: b'hello'
```

- Multiple guesses, multiple hashes (verbose)
```powershell
PS G:\Other computers\Origin PC\DSU\Security Tool Development - CSC842\pashion\pashion> py -3 .\main.py -G .\test_guesses.txt -D .\test_hashes.txt -a md5 -v
md5
[*] hash algorithm is <md5 _hashlib.HASH object @ 0x000001719D105AF0>

[*] guess file is .\test_guesses.txt

[*] hash file is .\test_hashes.txt

b'cfcd208495d565ef66e7dff9f98764da\r\n'
b'test \r\n'
Guess: b'test'
Hash Digest: b"\t\x8fk\xcdF!\xd3s\xca\xdeN\x83&'\xb4\xf6"
Hash Hexdigest: b'098f6bcd4621d373cade4e832627b4f6'
Hash: b'cfcd208495d565ef66e7dff9f98764da'
b'test1 \r\n'
Guess: b'test1'
Hash Digest: b'Z\x10^\x8b\x9d@\xe12\x97\x80\xd6.\xa2&]\x8a'
Hash Hexdigest: b'5a105e8b9d40e1329780d62ea2265d8a'
Hash: b'cfcd208495d565ef66e7dff9f98764da'
...
Hash: b'c4ca4238a0b923820dcc509a6f75849b'
b'1 \r\n'
Guess: b'1'
Hash Digest: b'\xc4\xcaB8\xa0\xb9#\x82\r\xccP\x9aou\x84\x9b'
Hash Hexdigest: b'c4ca4238a0b923820dcc509a6f75849b'
Hash: b'c4ca4238a0b923820dcc509a6f75849b'
[*] HASH CRACKED: b'1'
```

## Additional Resources
- [Argparse](https://docs.python.org/3/library/argparse.html)
  - I've used this a thousand times and still have to look it up every time.
- [hashlib](https://docs.python.org/3/library/hashlib.html)
