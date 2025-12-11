import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import numpy as np

def getTextfromBinary(path):
    binary = lief.parse(path)

    text_section = binary.get_section(".text")

    return bytes(text_section.content)

def getInstructionCounts(code: bytes):
 
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instruction_counts = {}

    for i in md.disasm(code, 0x1000):
        mnemonic = i.mnemonic
        if mnemonic in instruction_counts:
            instruction_counts[mnemonic] += 1
        else:
            instruction_counts[mnemonic] = 1

    for instr, count in instruction_counts.items():
        print(f"{instr}: {count}")

    return instruction_counts

def getInstructionFrequencies(counts):

    relevant_instructions = ["jmp", "call", "ret", "cmp", "mov", "push", "pop", "add", "sub"]
    freqs = np.zeros(len(relevant_instructions), dtype=float)
    total_instructions = 0

    for count in counts.values():
        total_instructions += count

    for i in range(0, len(relevant_instructions)):
        current_instr = relevant_instructions[i]
        if current_instr in counts:
            c = counts.get(current_instr)
            freqs[i] = c / total_instructions
        else:
            freqs[i] = 0

    print(freqs)

text = getTextfromBinary("../examples/example1")
getInstructionFrequencies(getInstructionCounts(text))