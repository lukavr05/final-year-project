import angr
import numpy as np
import networkx as nx

def getCFG(path):
    binary = angr.Project(path, load_options={"auto_load_libs": False})

    cfg = binary.analyses.CFGFast()
    
    return cfg

def getCFGFeatures(path):
    cfg = getCFG(path)
    g = cfg.model.graph

    print("Graph Type:", cfg.model.graph)
    print("\nNodes:")
    for node in cfg.model.graph.nodes():
        print(f"Node address: {hex(node.addr)}\tNode size: {node.size}")

    print("\nEdges:")

    for src, dest in cfg.model.graph.edges():
        print(f"{hex(src.addr)} -> {hex(dest.addr)}")

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


print(getCFGFeatures("../examples/example1"))