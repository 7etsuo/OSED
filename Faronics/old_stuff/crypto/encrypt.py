# import hashlib
# 
# key = "ZdrastvujteJaV"
# message = "Zdrastvujte, ja vasha tetia!"
# 
# # MD5 hash
# md5_hash = hashlib.md5((key + message).encode()).hexdigest()
# print("MD5 hash:", md5_hash)
# 
# # SHA-1 hash
# sha1_hash = hashlib.sha1((key + message).encode()).hexdigest()
# print("SHA-1 hash:", sha1_hash)
# 
# # SHA-256 hash
# sha256_hash = hashlib.sha256((key + message).encode()).hexdigest()
# print("SHA-256 hash:", sha256_hash)
# 
# # Additional hash algorithms (SHA-512, SHA-3-256, and SHA-3-512)
# sha512_hash = hashlib.sha512((key + message).encode()).hexdigest()
# print("SHA-512 hash:", sha512_hash)
# 
# sha3_256_hash = hashlib.sha3_256((key + message).encode()).hexdigest()
# print("SHA-3-256 hash:", sha3_256_hash)
# 
# sha3_512_hash = hashlib.sha3_512((key + message).encode()).hexdigest()
# print("SHA-3-512 hash:", sha3_512_hash)
# 
# 
# key = "ZdrastvujteJaV"
# message = "Zdrastvujte, ja vasha tetia!"
# 
# # Convert key and message to bytes
# key_bytes = key.encode()
# message_bytes = message.encode()
# 
# # Perform XOR operation
# result = bytes(x ^ y for x, y in zip(key_bytes, message_bytes))
# 
# # Convert result back to string
# result_string = result.decode()
# 
# print("XOR result:", result_string)
# 
"""
This script attempts to brute-force XOR-encrypted text using a combination of letter frequency and common word analysis.

Letter frequencies are based on their commonness in the English language, and a set of common English words is used for additional scoring.

The script generates all possible keys (within given lengths of 1 to n) the user must set n, from a key space of all printable ASCII characters, and decrypts the given message using these keys. It scores the result of each decryption based on the presence of common English words and the overall letter frequency.

The 10 decryption results with the highest scores are kept and printed at the end, along with their corresponding keys and scores. 

This script is intended for educational purposes only, and should not be used for illegal activities.
"""

import string
import itertools
import heapq
import re

from transformers import GPT2LMHeadModel, GPT2Tokenizer

tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# English letter frequency
freq = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074, ' ': 0.13000
}

# Most common English words
common_words = {
    'the': 1.0, 'be': 0.8, 'to': 0.8, 'of': 0.8, 'and': 0.8, 'a': 0.8, 'in': 0.8, 'that': 0.6, 'have': 0.6,
    'i': 0.6, 'it': 0.6, 'for': 0.6, 'not': 0.6, 'on': 0.6, 'with': 0.6, 'he': 0.6, 'is': 0.6, 'you': 0.6, 
    'do': 0.6, 'at': 0.6, 'this': 0.6, 'but': 0.4, 'by': 0.4, 'from': 0.4, 'they': 0.4, 'we': 0.4, 'say': 0.4, 
    'her': 0.4, 'she': 0.4, 'or': 0.4, 'an': 0.4, 'will': 0.4, 'my': 0.4, 'one': 0.4, 'all': 0.4, 'would': 0.4, 
    'there': 0.4, 'their': 0.4, 'what': 0.4, 'so': 0.4, 'up': 0.4, 'out': 0.4, 'if': 0.4, 'about': 0.4, 
    'who': 0.4, 'get': 0.4, 'which': 0.4, 'go': 0.4, 'me': 0.4
}

common_trigrams = {
    'the': 1, 'and': 0.8, 'ing': 0.7, 'her': 0.6, 'hat': 0.5,
    # ... (add more common trigrams and their scores as needed)
}

def contextual_score(sentence):
    input_ids = tokenizer.encode(sentence, return_tensors='pt')
    output = model(input_ids, labels=input_ids)
    loss = output.loss
    return -loss.item()

# The key space to try
key_space = string.printable  # all printable ASCII characters

def xor_decrypt(ciphertext, key):
    key = key.encode()
    return bytes([b ^ key[i%len(key)] for i, b in enumerate(ciphertext)])


def score(text):
    text = text.lower()
    letter_score = sum(freq.get(c, 0) for c in text)
    word_score = sum(common_words.get(word, 0) for word in re.findall(r'\b\w+\b', text))
    trigram_score = sum(common_trigrams.get(text[i:i+3], 0) for i in range(len(text) - 2))
    unusual_chars_penalty = sum((1 if c not in freq else 0) for c in text)
    context_score = contextual_score(text)
    return letter_score + word_score + trigram_score + context_score - unusual_chars_penalty


def key_score(key):
    # Reward shorter keys
    return 1 / len(key)


def decrypt_message(encrypted_message):
    heap = []
    for key_length in range(1, 4):  # Trying keys of lengths 1, 2, and 3
        for key_tuple in itertools.product(key_space, repeat=key_length):
            key = "".join(key_tuple)
            decrypted_message = xor_decrypt(encrypted_message, key)
            decrypted_text = decrypted_message.decode(errors='ignore')
            decrypted_score = score(decrypted_text) + key_score(key)
            if len(heap) < 10:  # If less than 10 elements, just push onto the heap
                heapq.heappush(heap, (decrypted_score, key, decrypted_text))
            else:  # Otherwise, push onto the heap and then pop to maintain 10 elements
                heapq.heappushpop(heap, (decrypted_score, key, decrypted_text))

    # Show top 10 messages
    for decrypted_score, key, message in sorted(heap, reverse=True):
        print(f'Score: {decrypted_score}, Key: {key}, Message: {message}')

def main():
    message = b'\x45\x5A\x56\x14\x57\x5B\x5D\x55\x5D\x12\x47\x51\x42\x46\x13\x5D\x42\x12\x51\x51\x42\x46'

    # hello = b'\x59\x57\x5F\x5D\x5D'
    # encrypted_two = b'\x0C\x27\x3B\x2B\x6F\x3B\x2B\x6F\x33\x78\x3B\x37\x2B\x3B'
    decrypt_message(message)
# decrypt_message(encrypted_two)

if __name__ == "__main__":
    main()
