import networkx as nx
from colorama import Fore, Style

def generate_event_graph(miner):
    """Uses NetworkX to map log templates into a graph to identify key variables."""
    print(f"\n{Fore.YELLOW}--- Starting NetworkX Graphing ---{Style.RESET_ALL}")
    
    G = nx.Graph()
    clusters = miner.drain.clusters
    
    if not clusters:
        print(f"{Fore.RED}No log clusters found to graph.{Style.RESET_ALL}")
        return None

    print(f"Mapping {len(clusters)} log templates into graph nodes...")
    
    # Add nodes for each cluster, storing its size (frequency) and template string
    for cluster in clusters:
        G.add_node(cluster.cluster_id, size=cluster.size, template=cluster.get_template())
        
    print(f"{Fore.GREEN}Graph generated successfully with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.{Style.RESET_ALL}")
    
    # Identify key variables by finding the most frequent events
    sorted_nodes = sorted(G.nodes(data=True), key=lambda x: x[1].get('size', 0), reverse=True)
    
    print(f"\n{Fore.CYAN}Top 3 Key Variables (Most Frequent Patterns) Identified:{Style.RESET_ALL}")
    for node_id, data in sorted_nodes[:3]:
        print(f"  [Node {node_id}] Count: {data['size']} | Pattern: {data['template']}")
        
    return G