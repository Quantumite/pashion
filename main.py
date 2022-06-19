import hashlib
import argparse

#Error codes
NO_RESULT_ERROR = 1
NO_HASH_ERROR = 2
BAD_HASH_ALGORITHM_ERROR = 3
NO_GUESS_ERROR = 4
SUCCESS = 0

def single_guess_single_hash(hash_func, hash, guess, verbose=False):
    """Checks the computation of a guess with a hash_func against a supplied hash. Verbosity is optional."""
    if not isinstance(guess, bytes):
        guess = guess.encode()
    if not isinstance(hash, bytes):
        hash = hash.encode()

    hash_func.update(guess)
    hash_digest = hash_func.digest()
    hash_hexdigest = hash_func.hexdigest().encode()

    if verbose:
        print(f"Guess: {guess}")
        print(f"Hash Digest: {hash_digest}")
        print(f"Hash Hexdigest: {hash_hexdigest}")
        print(f"Hash: {hash}")

    if hash_digest == hash or hash_hexdigest == hash:
        return guess.strip()
    return None

def guess_file_single_hash(hash_func, hash, guess_file, verbose=False):
    """Iterates over many guesses in a file to check against a single, provided hash."""
    #Open and read lines from file
    with open(guess_file, 'rb') as f:
        for guess in f:
            tmp_hash_func = hash_func.copy()
            tmp_return_value = single_guess_single_hash(tmp_hash_func, hash.strip(), guess.strip(), verbose) 
            if tmp_return_value is not None:
                return guess.strip()
    return None

def single_guess_hash_file(hash_func, hash_file, guess, verbose=False):
    """Iterates over many hashes in a file to compare against a single, provided guess."""
    with open(hash_file, 'rb') as f:
        for hash in f:
            tmp_hash_func = hash_func.copy()
            tmp_return_value = single_guess_single_hash(tmp_hash_func, hash.strip(), guess.strip(), verbose) 
            if tmp_return_value is not None:
                return guess.strip()
    return None

def guess_file_hash_file(hash_func, hash_file, guess_file, verbose=False):
    """Iterates over guesses and hashes in two different files to find a match."""
    with open(hash_file, 'rb') as f1:
        for hash in f1:
            with open(guess_file, 'rb') as f2:
                for guess in f2:
                    tmp_hash_func = hash_func.copy()
                    tmp_return_value = single_guess_single_hash(tmp_hash_func, hash.strip(), guess.strip(), verbose) 
                    if tmp_return_value is not None:
                        return guess.strip()
    return None
     


def main():
    h = None
    return_value = None

    #Parse command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action="store_true", dest='verbose', help="Print extra information during execution. Useful for debugging.") 
    parser.add_argument('-g', '--guess', dest='guess', default=None, help="Supply a single guess to check against any provided hash(es).")
    parser.add_argument('-G', '--guess_file', dest='guess_file', default=None, help="Supply a file name that holds many guesses. Format: single guess per line.")
    parser.add_argument('-d', '--digest', dest='hash', default=None, help="Supply a single hash/digest to be checked against guess(es). Format: hexadecimal or binary.")
    parser.add_argument('-D', '--digest_file', dest='hash_file', default=None, help="Supply a file name that holds many hashes/digests. Format: single hash/digest per line.")
    parser.add_argument('-a', '--algorithm', dest='hash_name', default=None, help=f'Supply the hash algorithm you intended to use during execution. Algorithms available: {hashlib.algorithms_available}\n')
    args = parser.parse_args()

    if args.verbose:
        print(args.hash_name)

    #Create a hash object if hashlib is able
    if args.hash_name in hashlib.algorithms_available:
        h = hashlib.new(args.hash_name)
    else:
        print("[!] Missing or unknown hash algorithm.\n")
        return BAD_HASH_ALGORITHM_ERROR

    if args.verbose:
        print(f"[*] hash algorithm is {h}\n")
    if args.guess and args.verbose:
        print(f"[*] guess is {args.guess}\n")
    if args.guess_file and args.verbose:
        print(f"[*] guess file is {args.guess_file}\n")
    if args.hash and args.verbose:
        print(f"[*] hash is {args.hash}\n")
    if args.hash_file and args.verbose:
        print(f"[*] hash file is {args.hash_file}\n")
    


    #If we have a single hash...
    if args.hash:
        #...and a single guess...
        if args.guess:
            #...check if the hash_func(guess) == hash
            return_value = single_guess_single_hash(h, args.hash.strip(), args.guess.strip(), args.verbose)
        #...and multiple guesses...
        elif args.guess_file:
            #...check each guess to see if hash_func(guess) == hash 
            return_value = guess_file_single_hash(h, args.hash.strip(), args.guess_file.strip(), args.verbose)
        else:
            #...no guesses were given. Error.
            print("[!] No guess given.\n")
            return NO_GUESS_ERROR
    #If we have multiple hashes...
    elif args.hash_file:
        #...and a single guess...
        if args.guess:
            #...check each hash to see if hash_func(guess) == hash
            return_value = single_guess_hash_file(h, args.hash_file.strip(), args.guess.strip(), args.verbose)
        #...and multiple guesses...
        elif args.guess_file:
            #...check each guess and each hash in both files to see if hash_func(guess) == hash.
            return_value = guess_file_hash_file(h, args.hash_file.strip(), args.guess_file.strip(), args.verbose)
        #...no guesses were given. Error.
        else:
            print("[!] No guess given.\n")
            return NO_GUESS_ERROR
    #No hashes were given. Error.
    else:
        print("[!] No hashes given.")
        return NO_HASH_ERROR

    
    #Found a matach!
    if return_value is not None:
        print(f"[*] HASH CRACKED: {return_value}\n")
    #No match
    else:
        print("Failed to crack hash... :(")
    
    #Only return success if the hash was cracked
    return SUCCESS if return_value is not None else NO_RESULT_ERROR

if __name__ == "__main__":
    main()