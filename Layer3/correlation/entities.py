"""
Layer 3 — Entity Extraction & Relationship Graph.

Extracts entities (users, IPs, hosts, processes) from correlated events
and builds a NetworkX relationship graph for investigation analysis.
"""

from typing import Optional

import networkx as nx

from Layer3.schemas.events import SuspiciousEvent
from Layer3.schemas.incident import IncidentEntities


def extract_entities(events: list[SuspiciousEvent]) -> IncidentEntities:
    """
    Extract all unique entities from a list of suspicious events.

    Args:
        events: List of correlated suspicious events.

    Returns:
        IncidentEntities with deduplicated entity lists.
    """
    users: set[str] = set()
    source_ips: set[str] = set()
    destination_ips: set[str] = set()
    hosts: set[str] = set()
    processes: set[str] = set()

    for event in events:
        if event.user:
            users.add(event.user)
        if event.source_ip:
            source_ips.add(event.source_ip)
        if event.destination_ip:
            destination_ips.add(event.destination_ip)
        if event.hostname:
            hosts.add(event.hostname)
        if event.process:
            processes.add(event.process)

    return IncidentEntities(
        users=sorted(users),
        source_ips=sorted(source_ips),
        destination_ips=sorted(destination_ips),
        hosts=sorted(hosts),
        processes=sorted(processes),
    )


def build_entity_graph(events: list[SuspiciousEvent]) -> nx.Graph:
    """
    Build a NetworkX graph of entity relationships from correlated events.

    Nodes represent entities (users, IPs, hosts, processes).
    Edges represent relationships observed in the events.

    The graph can be used for:
    - Visualizing entity connections
    - Querying related entities
    - Identifying central entities (high degree nodes)

    Args:
        events: List of correlated suspicious events.

    Returns:
        NetworkX undirected graph of entity relationships.
    """
    graph = nx.Graph()

    for event in events:
        # Add nodes with type attribute
        if event.user:
            graph.add_node(
                f"user:{event.user}",
                entity_type="user",
                label=event.user,
            )
        if event.source_ip:
            graph.add_node(
                f"ip:{event.source_ip}",
                entity_type="source_ip",
                label=event.source_ip,
            )
        if event.destination_ip:
            graph.add_node(
                f"ip:{event.destination_ip}",
                entity_type="destination_ip",
                label=event.destination_ip,
            )
        if event.hostname:
            graph.add_node(
                f"host:{event.hostname}",
                entity_type="host",
                label=event.hostname,
            )
        if event.process:
            graph.add_node(
                f"process:{event.process}",
                entity_type="process",
                label=event.process,
            )

        # Add edges between related entities in this event
        entities_in_event: list[str] = []
        if event.user:
            entities_in_event.append(f"user:{event.user}")
        if event.source_ip:
            entities_in_event.append(f"ip:{event.source_ip}")
        if event.hostname:
            entities_in_event.append(f"host:{event.hostname}")
        if event.process:
            entities_in_event.append(f"process:{event.process}")
        if event.destination_ip:
            entities_in_event.append(f"ip:{event.destination_ip}")

        # Connect all entities that appear in the same event
        for i, entity_a in enumerate(entities_in_event):
            for entity_b in entities_in_event[i + 1:]:
                if graph.has_edge(entity_a, entity_b):
                    # Increment weight for repeated co-occurrence
                    graph[entity_a][entity_b]["weight"] += 1
                    graph[entity_a][entity_b]["event_ids"].append(event.event_id)
                else:
                    graph.add_edge(
                        entity_a,
                        entity_b,
                        weight=1,
                        event_ids=[event.event_id],
                    )

    return graph


def get_related_entities(
    graph: nx.Graph,
    entity_key: str,
) -> list[dict[str, str]]:
    """
    Get all entities related to a given entity in the graph.

    Args:
        graph: The entity relationship graph.
        entity_key: The entity key (e.g., "user:admin", "ip:185.10.20.50").

    Returns:
        List of dicts with 'key', 'type', 'label', and 'weight'.
    """
    if entity_key not in graph:
        return []

    related: list[dict[str, str]] = []
    for neighbor in graph.neighbors(entity_key):
        node_data = graph.nodes[neighbor]
        edge_data = graph[entity_key][neighbor]
        related.append({
            "key": neighbor,
            "type": node_data.get("entity_type", "unknown"),
            "label": node_data.get("label", neighbor),
            "weight": str(edge_data.get("weight", 1)),
        })

    return related


def get_entity_context(
    graph: nx.Graph,
    entity_key: str,
) -> Optional[dict]:
    """
    Get full context for an entity including its relationships and centrality.

    Args:
        graph: The entity relationship graph.
        entity_key: The entity key.

    Returns:
        Dict with entity info, relationships, and degree centrality, or None.
    """
    if entity_key not in graph:
        return None

    node_data = graph.nodes[entity_key]
    related = get_related_entities(graph, entity_key)

    # Calculate degree centrality for this node
    centrality = nx.degree_centrality(graph).get(entity_key, 0.0)

    return {
        "entity_key": entity_key,
        "entity_type": node_data.get("entity_type", "unknown"),
        "label": node_data.get("label", entity_key),
        "degree": graph.degree(entity_key),
        "centrality": round(centrality, 4),
        "relationships": related,
    }
