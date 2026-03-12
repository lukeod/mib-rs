use std::collections::HashMap;
use std::fmt;

use petgraph::graph::DiGraph;
pub use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

/// A symbol in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol {
    pub module: String,
    pub name: String,
}

impl Symbol {
    #[cfg(test)]
    pub fn new(module: impl Into<String>, name: impl Into<String>) -> Self {
        Symbol {
            module: module.into(),
            name: name.into(),
        }
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.module, self.name)
    }
}

/// Result of computing the resolution order.
pub struct ResolutionResult {
    /// Symbols in topological (dependency) order (used by tests for validation).
    #[cfg_attr(not(test), allow(dead_code))]
    pub order: Vec<Symbol>,
    /// Node indices in topological (dependency) order (parallel to `order`).
    pub order_indices: Vec<NodeIndex>,
    /// Cycles detected as strongly connected components.
    pub cycles: Vec<Vec<Symbol>>,
}

/// Dependency graph for topological ordering with cycle detection.
pub struct Graph {
    inner: DiGraph<Symbol, ()>,
    node_index: HashMap<Symbol, NodeIndex>,
}

impl Graph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node to the graph. Returns the node index.
    pub fn add_node(&mut self, sym: Symbol) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(&sym) {
            return idx;
        }
        let idx = self.inner.add_node(sym.clone());
        self.node_index.insert(sym, idx);
        idx
    }

    /// Add a directed edge from -> to.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex) {
        if !self.inner.edges(from).any(|e| e.target() == to) {
            self.inner.add_edge(from, to, ());
        }
    }

    /// Compute resolution order using Tarjan's SCC algorithm.
    pub fn resolution_order(&self) -> ResolutionResult {
        if self.inner.node_count() == 0 {
            return ResolutionResult {
                order: Vec::new(),
                order_indices: Vec::new(),
                cycles: Vec::new(),
            };
        }

        let sccs = petgraph::algo::tarjan_scc(&self.inner);

        let mut order = Vec::with_capacity(self.inner.node_count());
        let mut order_indices = Vec::with_capacity(self.inner.node_count());
        let mut cycles = Vec::new();

        // petgraph returns SCCs in reverse topological order.
        for scc in &sccs {
            let is_cycle = scc.len() > 1 || (scc.len() == 1 && self.has_self_loop(scc[0]));

            if is_cycle {
                let mut cycle: Vec<Symbol> =
                    scc.iter().map(|&idx| self.inner[idx].clone()).collect();
                cycle.sort();
                cycles.push(cycle);
            }

            // Add nodes from this SCC to the ordered output (sorted for determinism).
            let mut scc_syms: Vec<(NodeIndex, &Symbol)> =
                scc.iter().map(|&idx| (idx, &self.inner[idx])).collect();
            scc_syms.sort_by(|a, b| a.1.cmp(b.1));
            for (idx, sym) in scc_syms {
                order.push(sym.clone());
                order_indices.push(idx);
            }
        }

        ResolutionResult {
            order,
            order_indices,
            cycles,
        }
    }

    fn has_self_loop(&self, node: NodeIndex) -> bool {
        self.inner.edges(node).any(|e| e.target() == node)
    }
}

impl Default for Graph {
    fn default() -> Self {
        Graph {
            inner: DiGraph::new(),
            node_index: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph() {
        let g = Graph::new();
        let result = g.resolution_order();
        assert!(result.order.is_empty());
        assert!(result.cycles.is_empty());
    }

    #[test]
    fn acyclic_graph() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        let b = g.add_node(Symbol::new("M", "B"));
        let c = g.add_node(Symbol::new("M", "C"));
        g.add_edge(a, b);
        g.add_edge(b, c);

        let result = g.resolution_order();
        assert!(result.cycles.is_empty());
        assert_eq!(result.order.len(), 3);
        // C should come before B, B before A (reverse dependency order)
        let pos_a = result.order.iter().position(|s| s.name == "A").unwrap();
        let pos_b = result.order.iter().position(|s| s.name == "B").unwrap();
        let pos_c = result.order.iter().position(|s| s.name == "C").unwrap();
        assert!(pos_c < pos_b);
        assert!(pos_b < pos_a);
    }

    #[test]
    fn cycle_detection() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        let b = g.add_node(Symbol::new("M", "B"));
        g.add_edge(a, b);
        g.add_edge(b, a);

        let result = g.resolution_order();
        assert_eq!(result.cycles.len(), 1);
        assert_eq!(result.cycles[0].len(), 2);
    }

    #[test]
    fn self_loop() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        g.add_edge(a, a);

        let result = g.resolution_order();
        assert_eq!(result.cycles.len(), 1);
        assert_eq!(result.cycles[0].len(), 1);
    }

    #[test]
    fn mixed_acyclic_and_cyclic() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        let b = g.add_node(Symbol::new("M", "B"));
        let c = g.add_node(Symbol::new("M", "C"));
        let d = g.add_node(Symbol::new("M", "D"));

        // A -> B -> C -> B (cycle), A -> D (no cycle)
        g.add_edge(a, b);
        g.add_edge(b, c);
        g.add_edge(c, b);
        g.add_edge(a, d);

        let result = g.resolution_order();
        assert_eq!(result.cycles.len(), 1);
        assert_eq!(result.order.len(), 4);
    }

    #[test]
    fn symbol_display() {
        let s = Symbol::new("IF-MIB", "ifIndex");
        assert_eq!(s.to_string(), "IF-MIB::ifIndex");
    }
}
