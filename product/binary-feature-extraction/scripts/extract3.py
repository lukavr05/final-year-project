import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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


text = getTextfromBinary("../examples/example1")
getInstructionCounts(text)