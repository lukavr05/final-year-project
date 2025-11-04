import pefile
from capstone import *

pe = pefile.PE("../examples/example1.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)


text_section = next(s for s in pe.sections if b'.text' in s.Name)
code = text_section.get_data()
base_addr = text_section.VirtualAddress

instruction_counts = {}
for insn in md.disasm(code, base_addr):
    instruction_counts[insn.mnemonic] = instruction_counts.get(insn.mnemonic, 0) + 1

for instr, count in sorted(instruction_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{instr}: {count}")