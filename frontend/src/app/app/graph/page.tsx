"use client";

import { useEffect, useState } from "react";
import dagre from "dagre";
import ReactFlow, {
    Background,
    Controls,
    MarkerType,
    MiniMap,
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
    effective_severity?: string;
    risk_propagated?: boolean;
    propagation_reason?: {
        rank: number;
        source_id: string;
        source_label: string;
        source_type: string;
        source_severity: string;
        via_relation: string;
        path: string[];
    } | null;
    criticality_score?: number;
    crown_jewel?: boolean;
};

type AttackPath = {
    path: string[];
    score: number;
    hop_count: number;
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

function edgeDescription(type: string) {
    if (type === "public_access") {
        return "Asset reachable from Internet";
    }

    if (type === "can_access") {
        return "Asset can access downstream resource";
    }

    if (type === "can_assume") {
        return "IAM trust / role assumption possible";
    }

    return "Relationship detected";
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

function layoutGraph(
    nodes: GraphNode[],
    edges: GraphEdge[],
    activePath: string[],
    blastMode: boolean,
    blastReachable: string[],
    searchQuery: string
) {
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

    const matchesSearch =
        !searchQuery ||
        node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        node.type.toLowerCase().includes(searchQuery.toLowerCase());

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
                    {node.effective_severity || node.severity}
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

                {node.risk_propagated ? (
                    <div
                        style={{
                        fontSize: 10,
                        padding: "4px 8px",
                        borderRadius: 999,
                        background: "rgba(248,113,113,.18)",
                        border: "1px solid rgba(248,113,113,.45)",
                        textTransform: "uppercase",
                        fontWeight: 800,
                        marginTop: 6,
                        color: "#fecaca",
                        }}
                    >
                        Risk elevated
                    </div>
                ) : null}

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
        opacity:
            !matchesSearch
                ? 0.08
                : blastMode
                ? blastReachable.includes(node.id)
                ? 1
                : 0.12
                : activePath.length === 0 || activePath.includes(node.id)
                ? 1
                : 0.22,
        filter:
            !matchesSearch
                ? "grayscale(100%) blur(1px)"
                : blastMode
                ? blastReachable.includes(node.id)
                ? "none"
                : "grayscale(100%)"
                : activePath.length === 0 || activePath.includes(node.id)
                ? "none"
                : "grayscale(80%)",
        boxShadow:
            blastMode && blastReachable.includes(node.id)
                ? "0 0 60px rgba(248,113,113,.35)"
                : activePath.includes(node.id)
                ? "0 0 50px rgba(103,232,249,.45)"
                : severityGlow(node.effective_severity || node.severity),
        },
    };
  });

  const flowEdges = edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.type,

    data: {
        description: edgeDescription(edge.type),
    },
    
    markerEnd: {
      type: MarkerType.ArrowClosed,
    },
    animated:
        activePath.includes(edge.source) &&
        activePath.includes(edge.target),
    style: {
        stroke:
            blastMode
                ? blastReachable.includes(edge.source) &&
                blastReachable.includes(edge.target)
                ? edgeColor(edge.type)
                : "rgba(148,163,184,.12)"
                : activePath.includes(edge.source) &&
                activePath.includes(edge.target)
            ? edgeColor(edge.type)
            : "rgba(148,163,184,.18)",
        strokeWidth:
            activePath.includes(edge.source) &&
            activePath.includes(edge.target)
            ? 3
            : 1.5,
        opacity:
            blastMode
                ? blastReachable.includes(edge.source) &&
                blastReachable.includes(edge.target)
                ? 1
                : 0.08
                : activePath.length === 0 ||
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

function summarizeAttackPath(
  activePath: string[],
  graphData: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  } | null
) {
  if (!graphData || !activePath.length) {
    return [];
  }

  const nodeLookup = Object.fromEntries(
    graphData.nodes.map((node) => [node.id, node])
  );

  const summaries: string[] = [];

  if (activePath.includes("internet")) {
    summaries.push("Internet reachable");
  }

  for (const nodeId of activePath) {
    const node = nodeLookup[nodeId];

    if (!node) continue;

    if (node.type === "iam_role") {
      summaries.push("IAM privilege escalation path");
    }

    if (node.crown_jewel) {
      summaries.push("Crown jewel exposed");
    }

    if (node.severity === "critical") {
      summaries.push("Critical asset in attack chain");
    }
  }

  return [...new Set(summaries)];
}

function describePathStep(
  node: GraphNode,
  previousNode?: GraphNode
) {
  if (node.type === "internet") {
    return "Internet exposure detected";
  }

  if (node.type === "iam_role") {
    return `Privilege escalation through ${node.label}`;
  }

  if (node.type === "s3_bucket") {
    if (node.crown_jewel) {
      return `Crown jewel bucket exposed: ${node.label}`;
    }

    return `S3 bucket reachable: ${node.label}`;
  }

  if (node.type === "rds_instance") {
    return `Database reachable: ${node.label}`;
  }

  return `Asset reachable: ${node.label}`;
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
    const [blastRadius, setBlastRadius] = useState<any | null>(null);
    const [blastMode, setBlastMode] = useState(false);
    const [blastReachable, setBlastReachable] = useState<string[]>([]);
    const attackSummary = summarizeAttackPath(
        activePath,
        graphData
    );
    const attackTimeline =
        graphData && activePath.length
            ? activePath
                .map((nodeId) =>
                graphData.nodes.find((node) => node.id === nodeId)
                )
                .filter(Boolean)
                .map((node, index, arr) =>
                describePathStep(
                    node as GraphNode,
                    arr[index - 1] as GraphNode | undefined
                )
                )
            : [];
    const [analysisCollapsed, setAnalysisCollapsed] = useState(false);
    const [hoveredEdge, setHoveredEdge] = useState<any | null>(null);
    const [searchQuery, setSearchQuery] = useState("");

    function resetWorkspace() {
        setBlastMode(false);
        setBlastReachable([]);
        setBlastRadius(null);
        setSelectedAsset(null);

        if (attackPaths.length) {
            setActivePath(attackPaths[0].path);
        } else {
            setActivePath([]);
        }
    }

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
            activePath,
            blastMode,
            blastReachable,
            searchQuery
        );

        setNodes(flowNodes);
        setEdges(flowEdges);
    }, [graphData, activePath, blastMode, blastReachable, searchQuery]);

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
                onClick={() => {
                    setBlastMode(false);
                    setBlastReachable([]);
                    setActivePath(path.path);
                }}
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
                Path {index + 1} · {path.score} · {path.hop_count} hops
                </button>
            ))}
            </div>

            <button
            onClick={resetWorkspace}
            style={{
                position: "absolute",
                top: 20,
                right: 20,
                zIndex: 30,
                padding: "10px 16px",
                borderRadius: 14,
                border: "1px solid rgba(248,113,113,.25)",
                background: "rgba(127,29,29,.18)",
                color: "#f8fafc",
                fontWeight: 700,
                cursor: "pointer",
                backdropFilter: "blur(10px)",
            }}
            >
            Reset Workspace
            </button>

            <input
                value={searchQuery}
                onChange={(event) => {
                    setSearchQuery(event.target.value);
                }}
                placeholder="Search assets, IAM roles, buckets..."
                style={{
                    position: "absolute",
                    top: 70,
                    right: 20,
                    zIndex: 30,
                    width: 320,
                    padding: "12px 14px",
                    borderRadius: 14,
                    border: "1px solid rgba(103,232,249,.18)",
                    background: "rgba(7,16,26,.92)",
                    color: "#f8fafc",
                    outline: "none",
                    backdropFilter: "blur(10px)",
                }}
            />

            {attackSummary.length ? (
            <div
                style={{
                position: "absolute",
                top: 90,
                left: 20,
                zIndex: 20,
                width: 340,
                padding: 18,
                borderRadius: 18,
                background: "rgba(7,16,26,.92)",
                border: "1px solid rgba(103,232,249,.18)",
                color: "#f8fafc",
                backdropFilter: "blur(10px)",
                height: analysisCollapsed ? 64 : "auto",
                overflow: "hidden",
                transition: "all 0.25s ease",
                }}
            >
                <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 14,
                }}
                >
                <div
                    style={{
                    fontSize: 12,
                    letterSpacing: "0.14em",
                    textTransform: "uppercase",
                    color: "#67e8f9",
                    fontWeight: 800,
                    }}
                >
                    Analysis Panel
                </div>

                <button
                    onClick={() => setAnalysisCollapsed((current) => !current)}
                    style={{
                    background: "transparent",
                    border: "none",
                    color: "#94a3b8",
                    cursor: "pointer",
                    fontWeight: 700,
                    }}
                >
                    {analysisCollapsed ? "Expand" : "Collapse"}
                </button>
                </div>

                <div style={{ marginBottom: 22 }}>
                <div
                    style={{
                    fontSize: 12,
                    opacity: 0.75,
                    marginBottom: 10,
                    textTransform: "uppercase",
                    letterSpacing: "0.12em",
                    fontWeight: 800,
                    }}
                >
                    Attack Summary
                </div>

                <ul
                    style={{
                    margin: 0,
                    paddingLeft: 18,
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                    }}
                >
                    {attackSummary.map((item) => (
                    <li key={item}>{item}</li>
                    ))}
                </ul>
                </div>

                <div style={{ marginBottom: 22 }}>
                <div
                    style={{
                    fontSize: 12,
                    opacity: 0.75,
                    marginBottom: 10,
                    textTransform: "uppercase",
                    letterSpacing: "0.12em",
                    fontWeight: 800,
                    }}
                >
                    Attack Timeline
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    {attackTimeline.map((step, index) => (
                    <div
                        key={`${index}-${step}`}
                        style={{ display: "flex", gap: 12, alignItems: "flex-start" }}
                    >
                        <div
                        style={{
                            minWidth: 26,
                            height: 26,
                            borderRadius: 999,
                            background: "rgba(103,232,249,.18)",
                            border: "1px solid rgba(103,232,249,.35)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: 12,
                            fontWeight: 800,
                            color: "#67e8f9",
                        }}
                        >
                        {index + 1}
                        </div>

                        <div style={{ lineHeight: 1.5, opacity: 0.92 }}>{step}</div>
                    </div>
                    ))}
                </div>
                </div>

                <div>
                <div
                    style={{
                    fontSize: 12,
                    opacity: 0.75,
                    marginBottom: 10,
                    textTransform: "uppercase",
                    letterSpacing: "0.12em",
                    fontWeight: 800,
                    }}
                >
                    Relationship Types
                </div>

                <div
                    style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 10,
                    fontSize: 14,
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 28, height: 4, borderRadius: 999, background: "#f87171" }} />
                    <span>Public access</span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 28, height: 4, borderRadius: 999, background: "#67e8f9" }} />
                    <span>Can access</span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 28, height: 4, borderRadius: 999, background: "#c4b5fd" }} />
                    <span>Can assume</span>
                    </div>
                </div>
                </div>
            </div>
            ) : null}

            {hoveredEdge ? (
            <div
                style={{
                position: "absolute",
                bottom: 24,
                left: 24,
                zIndex: 30,
                width: 320,
                padding: 16,
                borderRadius: 16,
                background: "rgba(7,16,26,.96)",
                border: "1px solid rgba(103,232,249,.18)",
                color: "#f8fafc",
                backdropFilter: "blur(10px)",
                }}
            >
                <div
                style={{
                    fontSize: 12,
                    letterSpacing: "0.14em",
                    textTransform: "uppercase",
                    color: edgeColor(String(hoveredEdge.label)),
                    marginBottom: 10,
                    fontWeight: 800,
                }}
                >
                {hoveredEdge.label}
                </div>

                <div style={{ lineHeight: 1.5, opacity: 0.9 }}>
                {hoveredEdge.data?.description}
                </div>
            </div>
            ) : null}

            <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            onNodeClick={async (_, node) => {
                const details = await safeopsApi.assetDetails(Number(node.id));
                setSelectedAsset(details);
            }}
            onEdgeMouseEnter={(_, edge) => setHoveredEdge(edge)}
            onEdgeMouseLeave={() => setHoveredEdge(null)}
            >
            <Background />
            <Controls />
            <MiniMap
                pannable
                zoomable
                nodeStrokeColor="#67e8f9"
                nodeColor="#07101a"
                nodeBorderRadius={8}
                maskColor="rgba(5,7,11,.72)"
            />
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

                {(() => {
                const selectedNode = graphData?.nodes.find(
                    (node) => node.id === String(selectedAsset.asset.id)
                );

                if (!selectedNode?.risk_propagated || !selectedNode.propagation_reason) {
                    return null;
                }

                return (
                    <div
                    style={{
                        marginBottom: 24,
                        padding: 14,
                        borderRadius: 14,
                        background: "rgba(248,113,113,.10)",
                        border: "1px solid rgba(248,113,113,.25)",
                        color: "#fecaca",
                    }}
                    >
                    <div
                        style={{
                        fontSize: 12,
                        textTransform: "uppercase",
                        letterSpacing: "0.12em",
                        fontWeight: 800,
                        marginBottom: 8,
                        }}
                    >
                        Why risk is elevated
                    </div>

                    <div style={{ lineHeight: 1.5 }}>
                        Reachable from{" "}
                        <strong>{selectedNode.propagation_reason.source_label}</strong>{" "}
                        via <strong>{selectedNode.propagation_reason.via_relation}</strong>.
                    </div>
                    </div>
                );
                })()}

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

                <button
                onClick={async () => {
                    const result = await safeopsApi.blastRadius(
                    Number(selectedAsset.asset.id)
                    );

                    setBlastRadius(result);
                    setBlastMode(true);
                    setBlastReachable([
                    String(selectedAsset.asset.id),
                    ...result.reachable_assets.map((asset) => String(asset.id)),
                    ]);
                }}
                style={{
                    marginTop: 20,
                    padding: "10px 14px",
                    borderRadius: 12,
                    border: "1px solid rgba(103,232,249,.25)",
                    background: "rgba(8,145,178,.2)",
                    color: "#f8fafc",
                    cursor: "pointer",
                    fontWeight: 700,
                }}
                >
                Analyze Blast Radius
                </button>

                <button
                onClick={() => {
                    setBlastMode(false);
                    setBlastReachable([]);

                    if (attackPaths.length) {
                    setActivePath(attackPaths[0].path);
                    }
                }}
                style={{
                    marginTop: 10,
                    padding: "10px 14px",
                    borderRadius: 12,
                    border: "1px solid rgba(248,113,113,.25)",
                    background: "rgba(127,29,29,.2)",
                    color: "#f8fafc",
                    cursor: "pointer",
                    fontWeight: 700,
                }}
                >
                Exit Blast Mode
                </button>

                {blastRadius ? (
                <div
                    style={{
                    marginTop: 24,
                    padding: 16,
                    borderRadius: 14,
                    background: "rgba(255,255,255,.04)",
                    }}
                >
                    <h3>Blast Radius</h3>

                    <p>Reachable assets: {blastRadius.reachable_asset_count}</p>
                    <p>Crown jewels exposed: {blastRadius.crown_jewel_count}</p>
                    <p>Impact score: {blastRadius.impact_score}</p>

                    {blastRadius.crown_jewels.length ? (
                    <div style={{ marginTop: 12 }}>
                        <strong>Crown jewels reachable:</strong>

                        <ul>
                        {blastRadius.crown_jewels.map((name: string) => (
                            <li key={name}>{name}</li>
                        ))}
                        </ul>
                    </div>
                    ) : null}
                </div>
                ) : null}
            </div>
            ) : null}
        </main>
    );
}