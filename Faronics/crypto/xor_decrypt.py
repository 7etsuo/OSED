import string
import itertools
import heapq
import re
import threading
import time
from queue import PriorityQueue

from transformers import GPT2LMHeadModel, GPT2Tokenizer
from colorama import Fore, Style

tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# The key space to try
# key_space = string.printable  # all printable ASCII characters
# Good enough for testing 
key_space = "1234567"
NUM_KEYS = 4

# (freq, common_words, and common_trigrams dictionaries here)
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

# Most common English trigrams
common_trigrams = {
    'the': 1, 'and': 0.8, 'ing': 0.7, 'her': 0.6, 'hat': 0.5,
    # ... (add more common trigrams and their scores as needed)
}

def contextual_score(sentence):
    input_ids = tokenizer.encode(sentence, return_tensors='pt')
    output = model(input_ids, labels=input_ids)
    loss = output.loss
    return -loss.item()  # Lower loss is better, so we negate

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

def worker(encrypted_message, heap, keys_queue):
    while not keys_queue.empty():
        key_tuple = keys_queue.get()
        key = "".join(key_tuple)
        decrypted_message = xor_decrypt(encrypted_message, key)
        decrypted_text = decrypted_message.decode(errors='ignore')
        decrypted_score = score(decrypted_text) + key_score(key)
        heap.put((-1 * decrypted_score, key, decrypted_text))  # Multiply score by -1 to sort in descending order

def print_top_10(heap):
    print(Fore.GREEN + "\nCurrent top 10 decrypted messages:" + Style.RESET_ALL)
    for _ in range(min(10, heap.qsize())):
        decrypted_score, key, message = heap.get()
        print(Fore.YELLOW + f'Score: {-1 * decrypted_score}, Key: {key}, Message: {message}' + Style.RESET_ALL)

def decrypt_message(encrypted_message, num_threads=8):
    heap = PriorityQueue()
    total_keys = len(key_space)**NUM_KEYS  # Total number of keys to try

    keys_queue = PriorityQueue()
    for key_length in range(1, NUM_KEYS+1):  # Trying keys of lengths 1, 2, and 3
        for key_tuple in itertools.product(key_space, repeat=key_length):
            keys_queue.put(key_tuple)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(encrypted_message, heap, keys_queue))
        thread.start()
        threads.append(thread)

    start_time = time.time()
    while True:
        time.sleep(10)
        progress = (total_keys - keys_queue.qsize()) / total_keys * 100
        print(Fore.BLUE + f"Progress: {progress:.2f}%   " + Style.RESET_ALL)
        print_top_10(heap)

        # Check if all threads have finished
        if all(not thread.is_alive() for thread in threads):
            break

    end_time = time.time()
    print(Fore.BLUE + f"Decryption completed in {end_time - start_time:.2f} seconds." + Style.RESET_ALL)

def main():
    print(Fore.BLUE + "Starting decryption..." + Style.RESET_ALL)
    ciphertext = b'\x45\x5A\x56\x14\x57\x5B\x5D\x55\x5D\x12\x47\x51\x42\x46\x13\x5D\x42\x12\x51\x51\x42\x46'
    decrypt_message(ciphertext)

if __name__ == "__main__":
    main()

