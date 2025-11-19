import angr
import numpy as np
import networkx as nx

def getControlFlowGraph(path):
    binary = angr.Project(path, load_options={"auto_load_libs": False})

    cfg = binary.analyses.CFGFast()
    
    return cfg

def getCFGFeatures(cfg):
    g = cfg.model.graph

    num_nodes = len(g.nodes())
    num_edges = len(g.edges())

    density = nx.density(cfg.model)
    cycles = nx.cycle_basis(cfg.model)
    cyclomatic = len(cycles)

    return np.array([num_edges, num_nodes, density, cyclomatic])

cfg = getControlFlowGraph("../examples/example1")

print(getCFGFeatures(cfg))