use std::collections::HashMap;

/// A symbol in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol {
    pub module: String,
    pub name: String,
}

impl Symbol {
    pub fn new(module: impl Into<String>, name: impl Into<String>) -> Self {
        Symbol {
            module: module.into(),
            name: name.into(),
        }
    }
}

/// Dependency graph for topological ordering with cycle detection.
pub struct Graph {
    nodes: Vec<Symbol>,
    node_index: HashMap<Symbol, usize>,
    edges: Vec<Vec<usize>>,
}

impl Graph {
    pub fn new() -> Self {
        Graph {
            nodes: Vec::new(),
            node_index: HashMap::new(),
            edges: Vec::new(),
        }
    }

    /// Add a node to the graph. Returns the node index.
    pub fn add_node(&mut self, sym: Symbol) -> usize {
        if let Some(&idx) = self.node_index.get(&sym) {
            return idx;
        }
        let idx = self.nodes.len();
        self.node_index.insert(sym.clone(), idx);
        self.nodes.push(sym);
        self.edges.push(Vec::new());
        idx
    }

    /// Add a directed edge from -> to.
    pub fn add_edge(&mut self, from: usize, to: usize) {
        if !self.edges[from].contains(&to) {
            self.edges[from].push(to);
        }
    }

    /// Compute resolution order using Tarjan's SCC algorithm.
    /// Returns (ordered symbols, cycles) where cycles is a list of SCCs with size > 1.
    pub fn resolution_order(&self) -> (Vec<Symbol>, Vec<Vec<Symbol>>) {
        let n = self.nodes.len();
        if n == 0 {
            return (Vec::new(), Vec::new());
        }

        let sccs = tarjan_scc(&self.edges, n);

        let mut ordered = Vec::with_capacity(n);
        let mut cycles = Vec::new();

        // Tarjan's returns SCCs in reverse topological order.
        for scc in &sccs {
            if scc.len() > 1 {
                let mut cycle: Vec<Symbol> = scc.iter().map(|&i| self.nodes[i].clone()).collect();
                cycle.sort();
                cycles.push(cycle);
            }
            // Add nodes from this SCC to the ordered output (sorted for determinism).
            let mut scc_syms: Vec<(usize, &Symbol)> =
                scc.iter().map(|&i| (i, &self.nodes[i])).collect();
            scc_syms.sort_by(|a, b| a.1.cmp(b.1));
            for (_, sym) in scc_syms {
                ordered.push(sym.clone());
            }
        }

        (ordered, cycles)
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

/// Tarjan's SCC algorithm. Returns SCCs in reverse topological order.
fn tarjan_scc(edges: &[Vec<usize>], n: usize) -> Vec<Vec<usize>> {
    struct State {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlinks: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        result: Vec<Vec<usize>>,
    }

    let mut state = State {
        index: 0,
        indices: vec![None; n],
        lowlinks: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        result: Vec::new(),
    };

    fn strongconnect(v: usize, edges: &[Vec<usize>], s: &mut State) {
        s.indices[v] = Some(s.index);
        s.lowlinks[v] = s.index;
        s.index += 1;
        s.stack.push(v);
        s.on_stack[v] = true;

        for &w in &edges[v] {
            if s.indices[w].is_none() {
                strongconnect(w, edges, s);
                s.lowlinks[v] = s.lowlinks[v].min(s.lowlinks[w]);
            } else if s.on_stack[w] {
                s.lowlinks[v] = s.lowlinks[v].min(s.indices[w].unwrap());
            }
        }

        if s.lowlinks[v] == s.indices[v].unwrap() {
            let mut scc = Vec::new();
            loop {
                let w = s.stack.pop().unwrap();
                s.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            s.result.push(scc);
        }
    }

    // Process nodes in sorted order for determinism.
    let mut sorted_indices: Vec<usize> = (0..n).collect();
    sorted_indices.sort_by(|&a, &b| {
        // Sort by (module, name) would be ideal but we just use the indices
        // since Graph already stores symbols. The caller should add nodes in sorted order
        // or we sort the SCCs later.
        a.cmp(&b)
    });

    for v in sorted_indices {
        if state.indices[v].is_none() {
            strongconnect(v, edges, &mut state);
        }
    }

    state.result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph() {
        let g = Graph::new();
        let (ordered, cycles) = g.resolution_order();
        assert!(ordered.is_empty());
        assert!(cycles.is_empty());
    }

    #[test]
    fn acyclic_graph() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        let b = g.add_node(Symbol::new("M", "B"));
        let c = g.add_node(Symbol::new("M", "C"));
        g.add_edge(a, b);
        g.add_edge(b, c);

        let (ordered, cycles) = g.resolution_order();
        assert!(cycles.is_empty());
        assert_eq!(ordered.len(), 3);
        // C should come before B, B before A (reverse dependency order)
        let pos_a = ordered.iter().position(|s| s.name == "A").unwrap();
        let pos_b = ordered.iter().position(|s| s.name == "B").unwrap();
        let pos_c = ordered.iter().position(|s| s.name == "C").unwrap();
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

        let (_, cycles) = g.resolution_order();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
    }

    #[test]
    fn self_loop() {
        let mut g = Graph::new();
        let a = g.add_node(Symbol::new("M", "A"));
        g.add_edge(a, a);

        let (_, cycles) = g.resolution_order();
        // Self-loop is an SCC of size 1 with an edge to itself.
        // Tarjan treats it as SCC size 1, but we only report size > 1 as cycles.
        // However, a self-loop creates an SCC where the node has itself as a successor,
        // so Tarjan will still put it in a size-1 SCC. We don't report size-1 SCCs as cycles.
        // This matches Go behavior where self-loops are handled differently.
        assert!(cycles.is_empty() || cycles[0].len() == 1);
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

        let (ordered, cycles) = g.resolution_order();
        assert_eq!(cycles.len(), 1);
        assert_eq!(ordered.len(), 4);
    }
}
