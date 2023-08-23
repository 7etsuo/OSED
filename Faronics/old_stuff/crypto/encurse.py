import itertools
import heapq
import re
import threading
import time
import curses
import string
from collections import deque

from queue import PriorityQueue
from transformers import GPT2LMHeadModel, GPT2Tokenizer

# Initialize the tokenizer and the model
tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# Key space to try
key_space = string.printable[:-5]  # Excluding few non-printable characters
key_space = '01234567'

NUM_KEYS = 3
NUM_THREADS = 8  # You should adjust this according to your hardware

# Create a mutex for thread-safe operations
mutex = threading.Lock()

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

common_words = {
    'the': 1.0, 'be': 0.8, 'to': 0.8, 'of': 0.8, 'and': 0.8, 'a': 0.8, 'in': 0.8, 'that': 0.6, 'have': 0.6,
    'i': 0.6, 'it': 0.6, 'for': 0.6, 'not': 0.6, 'on': 0.6, 'with': 0.6, 'he': 0.6, 'is': 0.6, 'you': 0.6, 
    'do': 0.6, 'at': 0.6, 'this': 0.6, 'but': 0.4, 'by': 0.4, 'from': 0.4, 'they': 0.4, 'we': 0.4, 'say': 0.4, 
    'her': 0.4, 'she': 0.4, 'or': 0.4, 'an': 0.4, 'will': 0.4, 'my': 0.4, 'one': 0.4, 'all': 0.4, 'would': 0.4, 
    'there': 0.4, 'their': 0.4, 'what': 0.4, 'so': 0.4, 'up': 0.4, 'out': 0.4, 'if': 0.4, 'about': 0.4, 
    'who': 0.4, 'get': 0.4, 'which': 0.4, 'go': 0.4, 'me': 0.4, 'when': 0.4, 'make': 0.4, 'can': 0.4,
    'hello': 1.0, 'like': 0.4, 'time': 0.4, 'no': 0.4, 'just': 0.4, 'him': 0.4, 'know': 0.4, 'take': 0.4, 'people': 0.4, 
    'into': 0.4, 'year': 0.4, 'your': 0.4, 'good': 0.4, 'some': 0.4, 'could': 0.4, 'them': 0.4, 'see': 0.4, 
    'other': 0.4, 'than': 0.4, 'then': 0.4, 'now': 0.4, 'look': 0.4, 'only': 0.4, 'come': 0.4, 'its': 0.4, 
    'over': 0.4, 'think': 0.4, 'also': 0.2, 'back': 0.2, 'after': 0.2, 'use': 0.2, 'two': 0.2, 'how': 0.2, 
    'our': 0.2, 'work': 0.2, 'first': 0.2, 'well': 0.2, 'way': 0.2, 'even': 0.2, 'new': 0.2, 'want': 0.2, 
    'because': 0.2, 'any': 0.2, 'these': 0.2, 'give': 0.2, 'day': 0.2, 'most': 0.2, 'us': 0.2
}

common_trigrams = {
    'the': 1.0, 'and': 0.8, 'ing': 0.8, 'her': 0.6, 'for': 0.6, 'hat': 0.6, 'tha': 0.6, 'nth': 0.6, 
    'ent': 0.6, 'ion': 0.6, 'tio': 0.6, 'ati': 0.6, 'ate': 0.6, 'all': 0.6, 'eth': 0.6, 'hes': 0.6, 
    'ver': 0.6, 'his': 0.6, 'oft': 0.4, 'ith': 0.4, 'fth': 0.4, 'sth': 0.4, 'oth': 0.4, 'res': 0.4, 
    'ont': 0.4, 'dth': 0.4, 'are': 0.4, 'rea': 0.4, 'ear': 0.4, 'was': 0.4, 'ere': 0.4, 'ers': 0.4, 
    'ter': 0.4, 'est': 0.4, 'ted': 0.4, 'ons': 0.4, 'con': 0.4, 'nce': 0.4, 'tis': 0.4, 'ell': 0.9,
}

def contextual_score(sentence):
    # Create tensors for input and labels
    input_ids = tokenizer.encode(sentence, return_tensors='pt')
    labels = input_ids.clone()

    # Shift the input to the right by 1 and remove the last token
    input_ids = input_ids[:, 1:]

    # Remove last token from labels
    labels = labels[:, :-1]

    # Run the model
    output = model(input_ids, labels=labels)

    loss = output.loss
    return -loss.item() if loss is not None else -float('inf')  # return negative infinity for None


def xor_decrypt(ciphertext, key):
    key_cycle = itertools.cycle(key)  # Create a repeating iterator of the key
    return bytes(b ^ next(key_cycle) for b in ciphertext).decode(errors='ignore')


def update_progress(stdscr, processed_keys, initial_queue_size, verbose_output, top_n):
    height, width = stdscr.getmaxyx()
    progress_ratio = processed_keys[0] / initial_queue_size

    progress_bar_width = width - 20
    filled_progress = int(progress_ratio * progress_bar_width)
    progress_bar = "█" * filled_progress + "-" * (progress_bar_width - filled_progress)

    stdscr.clear()
    stdscr.border()

    # Update the progress bar
    stdscr.addstr(1, 1, "Progress: [{0}] {1:.1f}%".format(progress_bar, progress_ratio * 100))

    # Display top scores
    if verbose_output:
        stdscr.addstr(3, 1, "Top Scores:")
        for i, (score, plaintext, key) in enumerate(top_n):
            if i < 10:
                key_str = str(key).replace('\0', '')
                score_str = str(score).replace('\0', '')
                plaintext_str = str(plaintext[:width-20]).replace('\0', '')
                
                stdscr.addstr(4 + i, 1, "Key: {0}, Score: {1}, Text: {2}".format(key_str, score_str, plaintext_str))

    stdscr.refresh()

readable_chars = set(string.ascii_letters + string.digits + string.whitespace)

def score(text):
    text = text.lower()
    if text.strip() == "":
        return float('inf')

    letter_score = sum(freq.get(c, 0) for c in text if c in readable_chars)
    word_score = sum(common_words.get(word, 0) for word in re.findall(r'\b\w+\b', text))
    trigram_score = sum(common_trigrams.get(text[i:i + 3], 0) for i in range(len(text) - 2))
    unusual_chars_penalty = sum((1 if c not in freq else 0) for c in text if c in readable_chars)
    context_score = contextual_score(text)
    non_printable_penalty = sum((1 if c not in readable_chars else 0) for c in text)

    return (
        letter_score
            + 4 * word_score
            + 4 * trigram_score
            + 2 * context_score
            - 10 * unusual_chars_penalty
            - 10 * non_printable_penalty
    )


def worker(queue, ciphertext, top_n, verbose_output, processed_keys):
    while queue:
        with mutex:
            try:
                key = queue.popleft()
            except IndexError:
                break
        plaintext = xor_decrypt(ciphertext, key)
        plaintext_score = score(plaintext)

        with mutex:
            if len(top_n) < 10 or plaintext_score > top_n[0][0]:
                if len(top_n) == 10:
                    heapq.heappop(top_n)
                heapq.heappush(top_n, (plaintext_score, plaintext, key))
                verbose_output.append(f"New top {len(top_n)} plaintext: {plaintext[:100]}... score: {plaintext_score}")
                verbose_output = verbose_output[-1000:]
            processed_keys[0] += 1


def main(stdscr, ciphertext, verbose):
    top_n = []
    queue = deque(key for key in itertools.product(range(256), repeat=NUM_KEYS))  # Generate keys as byte sequences
    verbose_output = []
    processed_keys = [0]
    initial_queue_size = len(queue)

    # Convert ciphertext to byte array
    ciphertext = bytes(ciphertext)

    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(queue, ciphertext, top_n, verbose_output, processed_keys))
        thread.start()
        threads.append(thread)

    while any(thread.is_alive() for thread in threads):
        with mutex:
            update_progress(stdscr, processed_keys, initial_queue_size, verbose_output, top_n)
        time.sleep(0.1)

    for thread in threads:
        thread.join()

    return top_n


def start(stdscr):
    stdscr.nodelay(True)  # Make getch() non-blocking
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)

    # Initialize color scheme for the progress bar window
    stdscr.bkgd(' ', curses.color_pair(1))
    stdscr.clear()

    # Print the cool ASCII graphic
    ciphertext = b'\x45\x5A\x56\x14\x57\x5B\x5D\x55\x5D\x12\x47\x51\x42\x46\x13\x5D\x42\x12\x51\x51\x42\x46'
    verbose = True
    top_n = main(stdscr, ciphertext, verbose)
    for score, plaintext, key in top_n:
        key_str = str(key).replace('\0', '')
        score_str = str(score).replace('\0', '')
        plaintext_str = str(plaintext[:width-20]).replace('\0', '')
        
        stdscr.addstr(4 + i, 1, "Key: {0}, Score: {1}, Text: {2}".format(key_str, score_str, plaintext_str))


    stdscr.addstr("\nPress any key to exit...")
    stdscr.nodelay(False)  # Make getch() blocking
    stdscr.getch()

if __name__ == "__main__":
    curses.wrapper(start)
