import angr

def getControlFlowGraph(path):
    binary = angr.Project(path, load_options={"auto_load_libs": False})

    cfg = binary.analyses.CFGFast()
    
    return cfg


cfg = getControlFlowGraph("../examples/example1")

print("Graph Type:", cfg.model.graph)
print("\nNodes:")
for node in cfg.model.graph.nodes():
    print(f"Node address: {hex(node.addr)}\tNode size: {node.size}")

print("\nEdges:")
for src, dest, data in cfg.model.graph.edges(data=True):
    print(f"{hex(src.addr)} -> {hex(dest.addr)} ({data})")