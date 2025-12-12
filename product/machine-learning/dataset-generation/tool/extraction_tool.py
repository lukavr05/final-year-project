import lief
import numpy as np
import angr
import networkx as nx
from capstone import *
import networkx as nx


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

    return instruction_counts


def getInstructionFrequencies(code: bytes):

    counts = getInstructionCounts(code)

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

    return freqs


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


def getCFG(path):
    binary = angr.Project(path, load_options={"auto_load_libs": False})

    cfg = binary.analyses.CFGFast()
    
    return cfg

def getCFGFeatures(path):
    cfg = getCFG(path)
    g = cfg.model.graph

    num_nodes = len(g.nodes())
    num_edges = len(g.edges())

    density = nx.density(g)
    cyclomatic = num_edges - num_nodes + 2 * nx.number_weakly_connected_components(g)
    num_functions = len(cfg.kb.functions)
    num_branches = 0
    for _, d in g.out_degree():
        if d > 1:
            num_branches += 1
            
    if num_nodes > 0:
        branch_ratio = num_branches / num_nodes
    else:
        branch_ratio = 0
    
    return np.array([num_nodes, num_edges, density, cyclomatic, num_functions, num_branches, branch_ratio], dtype=float)

def extractBinaryFeatures(path):
    text = getTextfromBinary(path)

    instr_freqs = getInstructionFrequencies(text)
    cfg_feats = getCFGFeatures(path)

    return np.concatenate((instr_freqs, cfg_feats))

