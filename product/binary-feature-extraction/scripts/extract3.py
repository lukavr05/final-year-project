from capstone import *

def getInstructionCounts(path):
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    with open(path, "rb") as file:
        code = file.read()

    instruction_counts = {}

    for i in md.disasm(code, 0x1000):
        mnemonic = i.mnemonic
        if mnemonic in instruction_counts:
            instruction_counts[mnemonic] += 1
        else:
            instruction_counts[mnemonic] = 1

    for instr, count in instruction_counts.items():
        print(f"{instr}: {count}")

getInstructionCounts("../examples/example2.exe")