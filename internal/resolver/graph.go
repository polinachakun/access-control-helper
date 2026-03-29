// Package resolver handles reference resolution and dependency tracking.
package resolver

import (
	"fmt"
	"sort"
)

// DependencyGraph tracks dependencies between resources.
type DependencyGraph struct {
	nodes    map[string]*Node
	edges    map[string][]string // node -> nodes it depends on
	revEdges map[string][]string // node -> nodes that depend on it
}

// Node represents a resource in the dependency graph.
type Node struct {
	ID       string // e.g., "aws_s3_bucket.my_bucket"
	Type     string // e.g., "aws_s3_bucket"
	Name     string // e.g., "my_bucket"
	Resolved bool
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes:    make(map[string]*Node),
		edges:    make(map[string][]string),
		revEdges: make(map[string][]string),
	}
}

// AddNode adds a node to the graph.
func (g *DependencyGraph) AddNode(id, resourceType, name string) {
	if _, exists := g.nodes[id]; !exists {
		g.nodes[id] = &Node{
			ID:   id,
			Type: resourceType,
			Name: name,
		}
	}
}

// AddEdge adds a dependency edge (from depends on to).
func (g *DependencyGraph) AddEdge(from, to string) {
	// Ensure both nodes exist
	if _, exists := g.nodes[from]; !exists {
		return
	}

	// Add edge
	g.edges[from] = appendUnique(g.edges[from], to)
	g.revEdges[to] = appendUnique(g.revEdges[to], from)
}

// GetDependencies returns direct dependencies of a node.
func (g *DependencyGraph) GetDependencies(id string) []string {
	return g.edges[id]
}

// GetDependents returns nodes that depend on a given node.
func (g *DependencyGraph) GetDependents(id string) []string {
	return g.revEdges[id]
}

// TopologicalSort returns nodes in dependency order (dependencies first).
// Returns an error if there are cycles.
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	var sorted []string
	visited := make(map[string]bool)
	inStack := make(map[string]bool)

	var visit func(id string) error
	visit = func(id string) error {
		if inStack[id] {
			return fmt.Errorf("cycle detected involving %s", id)
		}
		if visited[id] {
			return nil
		}

		inStack[id] = true

		// Visit dependencies first
		for _, dep := range g.edges[id] {
			if _, exists := g.nodes[dep]; exists {
				if err := visit(dep); err != nil {
					return err
				}
			}
		}

		inStack[id] = false
		visited[id] = true
		sorted = append(sorted, id)

		return nil
	}

	// Sort node IDs for deterministic output
	nodeIDs := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		if err := visit(id); err != nil {
			return nil, err
		}
	}

	return sorted, nil
}

// GetAllNodes returns all node IDs.
func (g *DependencyGraph) GetAllNodes() []string {
	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// GetNode returns a node by ID.
func (g *DependencyGraph) GetNode(id string) *Node {
	return g.nodes[id]
}

// HasNode returns true if the node exists.
func (g *DependencyGraph) HasNode(id string) bool {
	_, exists := g.nodes[id]
	return exists
}

// Size returns the number of nodes.
func (g *DependencyGraph) Size() int {
	return len(g.nodes)
}

// GetNodesByType returns all nodes of a given type.
func (g *DependencyGraph) GetNodesByType(resourceType string) []*Node {
	var nodes []*Node
	for _, node := range g.nodes {
		if node.Type == resourceType {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// appendUnique appends to a slice only if the value doesn't exist.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// FindRelatedResources finds all resources related to a given resource.
// This includes both direct dependencies and dependents.
func (g *DependencyGraph) FindRelatedResources(id string) []string {
	visited := make(map[string]bool)
	var result []string

	var traverse func(nodeID string)
	traverse = func(nodeID string) {
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true
		result = append(result, nodeID)

		// Traverse dependencies
		for _, dep := range g.edges[nodeID] {
			traverse(dep)
		}

		// Traverse dependents
		for _, dep := range g.revEdges[nodeID] {
			traverse(dep)
		}
	}

	traverse(id)

	// Remove the starting node from results
	filtered := make([]string, 0, len(result)-1)
	for _, r := range result {
		if r != id {
			filtered = append(filtered, r)
		}
	}

	sort.Strings(filtered)
	return filtered
}

// Clone creates a deep copy of the graph.
func (g *DependencyGraph) Clone() *DependencyGraph {
	clone := NewDependencyGraph()

	for id, node := range g.nodes {
		clone.nodes[id] = &Node{
			ID:       node.ID,
			Type:     node.Type,
			Name:     node.Name,
			Resolved: node.Resolved,
		}
	}

	for from, tos := range g.edges {
		clone.edges[from] = append([]string{}, tos...)
	}

	for to, froms := range g.revEdges {
		clone.revEdges[to] = append([]string{}, froms...)
	}

	return clone
}
