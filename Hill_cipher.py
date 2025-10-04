#!/usr/bin/env python3
"""
Simple 2x2 Hill cipher implementation with brute-force recovery (known block size = 2).
- Supports encryption and decryption using a 2x2 key matrix (mod 26).
- Brute force tries all invertible 2x2 keys (mod 26) and ranks results by simple English-word scoring.

Usage:
    Run the script and follow prompts.
    Or use the functions defined below from another script.

Author: Ritvik
"""

import math
import itertools
import sys
from collections import Counter

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
M = 26

# ----------------------
# helpers: text <-> vectors
# ----------------------
def clean_text(s):
    s = "".join(ch for ch in s.upper() if ch.isalpha())
    return s

def pad_text(s, block=2, pad_char="X"):
    if len(s) % block != 0:
        s += pad_char * (block - (len(s) % block))
    return s

def text_to_blocks(s, block=2):
    s = clean_text(s)
    s = pad_text(s, block)
    blocks = []
    for i in range(0, len(s), block):
        blocks.append([ALPH.index(c) for c in s[i:i+block]])
    return blocks

def blocks_to_text(blocks):
    return "".join(ALPH[v % M] for block in blocks for v in block)

# ----------------------
# modular arithmetic utils
# ----------------------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

# ----------------------
# 2x2 matrix ops mod 26
# ----------------------
def mat_mul_2x2_vec(key, vec):
    # key: tuple/list (a,b,c,d) representing [[a,b],[c,d]]
    a,b,c,d = key
    x,y = vec
    return [ (a*x + b*y) % M, (c*x + d*y) % M ]

def det_2x2(key):
    a,b,c,d = key
    return (a*d - b*c) % M

def inverse_key_2x2(key):
    a,b,c,d = key
    det = (a*d - b*c) % M
    inv_det = modinv(det, M)
    if inv_det is None:
        return None
    # inverse of [[a,b],[c,d]] is inv_det * [[d,-b],[-c,a]] mod M
    return ( (d * inv_det) % M,
            ((-b) * inv_det) % M,
            ((-c) * inv_det) % M,
            (a * inv_det) % M )

# ----------------------
# encrypt / decrypt
# ----------------------
def encrypt(plaintext, key):
    blocks = text_to_blocks(plaintext, block=2)
    ciphertext_blocks = [ mat_mul_2x2_vec(key, vec) for vec in blocks ]
    return blocks_to_text(ciphertext_blocks)

def decrypt(ciphertext, key):
    inv = inverse_key_2x2(key)
    if inv is None:
        raise ValueError("Key is not invertible mod 26.")
    blocks = text_to_blocks(ciphertext, block=2)
    plain_blocks = [ mat_mul_2x2_vec(inv, vec) for vec in blocks ]
    return blocks_to_text(plain_blocks)

# ----------------------
# brute force (try all invertible 2x2 keys)
# ----------------------
COMMON_WORDS = ("THE", "AND", "TO", "OF", "IN", "IS", "IT", "YOU", "THAT", "HE")

def english_score(text):
    # Simple scoring: count occurrences of common words
    t = text.upper()
    sc = 0
    for w in COMMON_WORDS:
        sc += t.count(w)  # counts non-overlapping occurrences
    # bonus for letter frequency roughly matching English (rough heuristic):
    freq = Counter(t)
    sc += freq.get('E',0) * 0.1
    return sc

def brute_force_hill(ciphertext, top_n=10, show_all=False):
    ciphertext = clean_text(ciphertext)
    results = []
    # iterate keys a,b,c,d in 0..25
    for a,b,c,d in itertools.product(range(M), repeat=4):
        key = (a,b,c,d)
        det = det_2x2(key)
        if math.gcd(det, M) != 1:
            continue  # not invertible
        try:
            pt = decrypt(ciphertext, key)
        except Exception:
            continue
        sc = english_score(pt)
        results.append( (sc, key, pt) )
    results.sort(reverse=True, key=lambda x: x[0])
    if show_all:
        return results
    return results[:top_n]

# ----------------------
# small CLI
# ----------------------
def prompt_key():
    print("Enter 2x2 key matrix values (row-major) as four integers 0-25, separated by spaces.")
    print("Example: '3 3 2 5' means [[3,3],[2,5]]")
    vals = input("Key> ").strip().split()
    if len(vals) != 4:
        raise SystemExit("Need four integers for key.")
    key = tuple(int(v) % M for v in vals)
    if math.gcd(det_2x2(key), M) != 1:
        raise SystemExit("This key matrix is not invertible modulo 26. Choose another.")
    return key

def main():
    print("2x2 Hill Cipher - encrypt, decrypt, brute-force (block size = 2)")
    while True:
        print("\nOptions: (E)ncrypt  (D)ecrypt  (B)rute-force  (Q)uit")
        choice = input("> ").strip().upper()
        if not choice: continue
        if choice.startswith("Q"):
            break
        if choice.startswith("E"):
            pt = input("Plaintext> ").strip()
            key = prompt_key()
            ct = encrypt(pt, key)
            print("Ciphertext:", ct)
        elif choice.startswith("D"):
            ct = input("Ciphertext> ").strip()
            key = prompt_key()
            try:
                pt = decrypt(ct, key)
                print("Decrypted (raw):", pt)
            except Exception as e:
                print("Error:", e)
        elif choice.startswith("B"):
            ct = input("Ciphertext to brute-force> ").strip()
            print("Running brute-force... (this tries all invertible 2x2 keys)")
            results = brute_force_hill(ct, top_n=20)
            print("\nTop candidates (score, key, plaintext):")
            for sc, key, pt in results:
                print(f"{sc:.2f}\t{key}\t{pt}")
            print("\nTo inspect more results, call brute_force_hill(..., show_all=True) from code.")
        else:
            print("Unknown option. Choose E/D/B/Q.")

if __name__ == "__main__":
    main()
