import binascii
import json

with open("ciphertexts.json", "r") as file:
    ciphertexts = json.load(file)

with open("target.json", "r") as file:
    target_data = json.load(file)

target = target_data["target"]
ciphertexts.append(target)


# turning cipher texts into bye forms
captures = []
for i in range(0,len(ciphertexts)):
    converted = []
    converted += binascii.unhexlify(ciphertexts[i])
    captures.append(converted)

target_bytes = captures[-1]


# sees if the byte is a letter or zero through ASCII
def is_letter_or_zero(value):
    if value > 0x60 and value < 0x7b or value > 0x40 and value < 0x5b or value == 0:
        return True
    return False

# scores how likely a character is to be a zero, by XOR'ing with the other characters in the same position and giving a score for each successful find
def space_score(chr_target,chrs_other):
    score = 0
    for current in chrs_other:
        result = chr_target ^ current
        if is_letter_or_zero(result):
            score += 1
    return score


keys = [None] * len(target_bytes)
space_votes = [0] * len(target_bytes)
THRESHOLD = 7 # without this false positives can make the parsed message have incorrect letters


# grabbing keys
for i in range(0, len(captures)):
    excluded_list = captures[:i] + captures[i+1:] # excludes the current list we are looking at
    for j in range(len(min(captures, key=len))):
        # getting the score for the current position
        current_score = space_score(captures[i][j],[cipher[j] for cipher in excluded_list])
        if current_score > space_votes[j] and current_score >= THRESHOLD:
            # if the score is higher than the votes and threshold, we will be grabbing the key for the position from it
            space_votes[j] = current_score
            keys[j] = captures[i][j] ^ 0x20

plaintext = ""

for i in range(0,len(target_bytes)):
    if keys[i] is not None:
        plaintext += chr(target_bytes[i] ^ keys[i])
    else:
        plaintext += "_"

print(plaintext)