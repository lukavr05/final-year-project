from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def getNGrams(code: bytes, n):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []

    for i in md.disasm(code, 0x1000):
        instructions.append(i.mnemonic)

    ngrams = []

    for i in range(len(instructions) - n + 1):
        ngram = tuple(instructions[i:i+n])
        ngrams.append(ngram)
    
    return ngrams


def getNGramCounts(ngrams):
    ngram_counts = {}

    for n in ngrams:
        if n in ngram_counts:
            ngram_counts[n] += 1
        else:
            ngram_counts[n] = 1

    return ngram_counts