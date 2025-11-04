from capstone import *

def dissassemble(path):
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    with open(path, "rb") as file:
        code = file.read()

    for i in md.disasm(code, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

dissassemble("../examples/example1.exe")
