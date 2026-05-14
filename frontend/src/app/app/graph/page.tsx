"use client";

import { useEffect, useState } from "react";
import dagre from "dagre";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";

import { useSafeOps } from "@/components/safeops-data-provider";
import { safeopsApi } from "@/lib/api";

type GraphNode = {
  id: string;
  label: string;
  type: string;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
};

const NODE_WIDTH = 240;
const NODE_HEIGHT = 100;

function nodeStyle(type: string) {
  const base = {
    color: "#f8fafc",
    borderRadius: 18,
    padding: 14,
    width: NODE_WIDTH,
    minHeight: NODE_HEIGHT,
    fontSize: 16,
    fontWeight: 700,
    border: "1px solid rgba(103,232,249,.25)",
    background: "#07101a",
  };

  if (type === "iam_role") {
    return {
      ...base,
      border: "1px solid rgba(196,181,253,.45)",
      background: "linear-gradient(135deg, rgba(88,28,135,.35), rgba(15,23,42,.9))",
    };
  }

  if (type === "s3_bucket") {
    return {
      ...base,
      border: "1px solid rgba(103,232,249,.45)",
      background: "linear-gradient(135deg, rgba(8,145,178,.28), rgba(15,23,42,.9))",
    };
  }

  if (type === "security_group") {
    return {
      ...base,
      border: "1px solid rgba(248,113,113,.45)",
      background: "linear-gradient(135deg, rgba(127,29,29,.35), rgba(15,23,42,.9))",
    };
  }

  if (type === "rds_instance") {
    return {
      ...base,
      border: "1px solid rgba(251,146,60,.45)",
      background: "linear-gradient(135deg, rgba(154,52,18,.35), rgba(15,23,42,.9))",
    };
  }

  return base;
}

function layoutGraph(nodes: GraphNode[], edges: GraphEdge[]) {
  const dagreGraph = new dagre.graphlib.Graph();

  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({
    rankdir: "LR",
    nodesep: 80,
    ranksep: 120,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, {
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const flowNodes = nodes.map((node) => {
    const position = dagreGraph.node(node.id);

    return {
      id: node.id,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        label: (
          <div>
            <div>{node.label}</div>
            <div style={{ opacity: 0.65, fontSize: 12, marginTop: 8 }}>
              {node.type}
            </div>
          </div>
        ),
      },
      position: {
        x: position.x - NODE_WIDTH / 2,
        y: position.y - NODE_HEIGHT / 2,
      },
      style: nodeStyle(node.type),
    };
  });

  const flowEdges = edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.type,
    markerEnd: {
      type: MarkerType.ArrowClosed,
    },
    animated: true,
    style: {
      stroke: "#67e8f9",
      strokeWidth: 2,
    },
    labelStyle: {
      fill: "#bae6fd",
      fontWeight: 700,
    },
  }));

  return { flowNodes, flowEdges };
}

export default function GraphPage() {
  const { activeAccountId } = useSafeOps();

  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);

  useEffect(() => {
    if (!activeAccountId) return;

    async function loadGraph() {
      const graph = await safeopsApi.graph(activeAccountId as number);

      const { flowNodes, flowEdges } = layoutGraph(
        graph.nodes as GraphNode[],
        graph.edges as GraphEdge[]
      );

      setNodes(flowNodes);
      setEdges(flowEdges);
    }

    loadGraph();
  }, [activeAccountId]);

  return (
    <main style={{ height: "100vh", background: "#05070b" }}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </main>
  );
}