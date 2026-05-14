"use client";

import { useEffect, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
} from "reactflow";
import "reactflow/dist/style.css";

import { useSafeOps } from "@/components/safeops-data-provider";
import { safeopsApi } from "@/lib/api";

export default function GraphPage() {
  const { activeAccountId } = useSafeOps();

  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);

  useEffect(() => {
    if (!activeAccountId) return;

    async function loadGraph() {
      const graph = await safeopsApi.graph(activeAccountId as number);

      const flowNodes = graph.nodes.map((node: any, index: number) => ({
        id: node.id,
        data: {
          label: `${node.label}\n(${node.type})`,
        },
        position: {
          x: index * 220,
          y: 120,
        },
        style: {
          background: "#07101a",
          color: "#fff",
          border: "1px solid rgba(103,232,249,.25)",
          borderRadius: 14,
          padding: 10,
          width: 180,
        },
      }));

      const flowEdges = graph.edges.map((edge: any) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.type,
        markerEnd: {
          type: MarkerType.ArrowClosed,
        },
        style: {
          stroke: "#67e8f9",
        },
      }));

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