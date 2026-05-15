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
    severity: string;
    criticality_score?: number;
    crown_jewel?: boolean;
};

type AttackPath = {
    path: string[];
    score: number;
    crown_jewel_reached: boolean;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
};

const NODE_WIDTH = 240;
const NODE_HEIGHT = 100;

function nodeIcon(type: string) {
    if (type === "internet") return "🌐";
    if (type === "s3_bucket") return "🪣";
    if (type === "iam_role") return "🔑";
    if (type === "rds_instance") return "🗄️";
    if (type === "security_group") return "🛡️";

    return "☁️";
}

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

    if (type === "internet") {
        return {
            ...base,
            border: "1px solid rgba(248,113,113,.55)",
            background:
            "linear-gradient(135deg, rgba(127,29,29,.65), rgba(15,23,42,.95))",
        };
    }
    

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

function edgeColor(type: string) {
    if (type === "public_access") {
        return "#f87171";
    }

    if (type === "can_access") {
        return "#67e8f9";
    }

    if (type === "can_assume") {
        return "#c4b5fd";
    }

    return "rgba(148,163,184,.35)";
}

function severityGlow(severity: string) {
    if (severity === "critical") {
        return "0 0 40px rgba(248,113,113,.35)";
    }

    if (severity === "high") {
        return "0 0 30px rgba(251,191,36,.25)";
    }

    if (severity === "medium") {
        return "0 0 24px rgba(96,165,250,.18)";
    }

    return "none";
}

function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], activePath: string[]) {
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
                <div
                    style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 10,
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 10,
                            fontSize: 18,
                            fontWeight: 800,
                        }}
                    >
                        <span>{nodeIcon(node.type)}</span>
                        <span>{node.label}</span>
                    </div>

                    <div
                    style={{
                        fontSize: 11,
                        padding: "4px 8px",
                        borderRadius: 999,
                        background:
                        node.severity === "critical"
                            ? "rgba(127,29,29,.8)"
                            : node.severity === "high"
                            ? "rgba(120,53,15,.8)"
                            : "rgba(15,23,42,.8)",
                        border:
                        node.severity === "critical"
                            ? "1px solid rgba(248,113,113,.45)"
                            : node.severity === "high"
                            ? "1px solid rgba(251,191,36,.45)"
                            : "1px solid rgba(148,163,184,.25)",
                        textTransform: "uppercase",
                        fontWeight: 700,
                    }}
                    >
                    {node.severity}
                    {node.crown_jewel ? (
                        <div
                            style={{
                            fontSize: 10,
                            padding: "4px 8px",
                            borderRadius: 999,
                            background: "rgba(251,191,36,.18)",
                            border: "1px solid rgba(251,191,36,.45)",
                            textTransform: "uppercase",
                            fontWeight: 800,
                            marginTop: 6,
                            color: "#fde68a",
                            }}
                        >
                            Crown jewel
                        </div>
                        ) : null}
                    </div>
                </div>

                <div
                    style={{
                    opacity: 0.65,
                    fontSize: 13,
                    }}
                >
                    {node.type}
                </div>
                </div>
            ),
        },
        position: {
            x: position.x - NODE_WIDTH / 2,
            y: position.y - NODE_HEIGHT / 2,
        },
        style: {
        ...nodeStyle(node.type),
        opacity: activePath.length === 0 || activePath.includes(node.id) ? 1 : 0.22,
        filter: activePath.length === 0 || activePath.includes(node.id) ? "none" : "grayscale(80%)",
        boxShadow: activePath.includes(node.id)
            ? "0 0 50px rgba(103,232,249,.45)"
            : severityGlow(node.severity),
        },
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
    animated:
        activePath.includes(edge.source) &&
        activePath.includes(edge.target),
    style: {
        stroke:
            activePath.includes(edge.source) &&
            activePath.includes(edge.target)
            ? edgeColor(edge.type)
            : "rgba(148,163,184,.18)",
        strokeWidth:
            activePath.includes(edge.source) &&
            activePath.includes(edge.target)
            ? 3
            : 1.5,
        opacity:
            activePath.length === 0 ||
            (activePath.includes(edge.source) && activePath.includes(edge.target))
            ? 1
            : 0.25,
    },
    labelStyle: {
        fill: edgeColor(edge.type),
        fontWeight: 800,
    },
  }));

  return { flowNodes, flowEdges };
}

export default function GraphPage() {
    const { activeAccountId } = useSafeOps();

    const [nodes, setNodes] = useState<any[]>([]);
    const [edges, setEdges] = useState<any[]>([]);
    const [selectedAsset, setSelectedAsset] = useState<any | null>(null);
    const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
    const [activePath, setActivePath] = useState<string[]>([]);
    const [graphData, setGraphData] = useState<{
        nodes: GraphNode[];
        edges: GraphEdge[];
    }   | null>(null);

    useEffect(() => {
        if (!activeAccountId) return;

        async function loadGraph() {
            const graph = await safeopsApi.graph(activeAccountId as number);

            const paths = (graph.attack_paths || []) as AttackPath[];
            const firstPath = paths[0]?.path || [];

            setAttackPaths(paths);
            setActivePath(firstPath);

            setGraphData({
            nodes: graph.nodes as GraphNode[],
            edges: graph.edges as GraphEdge[],
            });
        }

        loadGraph();
    }, [activeAccountId]);

    useEffect(() => {
        if (!graphData) return;

        const { flowNodes, flowEdges } = layoutGraph(
            graphData.nodes,
            graphData.edges,
            activePath
        );

        setNodes(flowNodes);
        setEdges(flowEdges);
    }, [graphData, activePath]);

    return (
        <main style={{ height: "100vh", background: "#05070b", position: "relative" }}>
            <div
                style={{
                    position: "absolute",
                    top: 20,
                    left: 20,
                    zIndex: 20,
                    display: "flex",
                    gap: 10,
                }}
                >
                {attackPaths.map((path, index) => (
                    <button
                    key={index}
                    onClick={() => setActivePath(path.path)}
                    style={{
                        padding: "8px 14px",
                        borderRadius: 999,
                        border: "1px solid rgba(103,232,249,.25)",
                        background:
                        activePath.join(",") === path.path.join(",")
                            ? "rgba(8,145,178,.3)"
                            : "rgba(15,23,42,.8)",
                        color: "#f8fafc",
                        cursor: "pointer",
                    }}
                    >
                    Path {index + 1} · {path.score}
                    </button>
                ))}
                </div>
            <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            onNodeClick={async (_, node) => {
                const details = await safeopsApi.assetDetails(Number(node.id));
                setSelectedAsset(details);
            }}
            >
            <Background />
            <Controls />
            </ReactFlow>

            {selectedAsset ? (
            <div
                style={{
                position: "absolute",
                top: 0,
                right: 0,
                width: 380,
                height: "100%",
                background: "#07101a",
                borderLeft: "1px solid rgba(103,232,249,.18)",
                padding: 24,
                overflowY: "auto",
                color: "#f8fafc",
                zIndex: 10,
                }}
            >
                <button
                onClick={() => setSelectedAsset(null)}
                style={{
                    marginBottom: 20,
                    background: "transparent",
                    color: "#67e8f9",
                    border: "none",
                    cursor: "pointer",
                }}
                >
                Close
                </button>

                <h2>{selectedAsset.asset.name}</h2>
                <p style={{ opacity: 0.7, marginBottom: 24 }}>
                {selectedAsset.asset.type}
                </p>

                <h3>Findings</h3>

                {selectedAsset.findings.length ? (
                selectedAsset.findings.map((finding: any) => (
                    <div
                    key={finding.id}
                    style={{
                        marginBottom: 16,
                        padding: 14,
                        borderRadius: 14,
                        background: "rgba(255,255,255,.04)",
                    }}
                    >
                    <div style={{ fontWeight: 700, marginBottom: 8 }}>
                        {finding.title}
                    </div>

                    <div style={{ opacity: 0.7, fontSize: 14 }}>
                        {finding.severity}
                    </div>
                    </div>
                ))
                ) : (
                <p>No findings</p>
                )}
            </div>
            ) : null}
        </main>
    );
}