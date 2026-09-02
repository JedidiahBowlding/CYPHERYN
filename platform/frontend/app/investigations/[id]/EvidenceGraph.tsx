"use client";

import { PointerEvent, WheelEvent, useMemo, useRef, useState } from "react";

export type GraphEntity = {
  id: string;
  entity_type: string;
  canonical_value: string;
  confidence: number;
  provider: string;
  attributes: Record<string, unknown>;
};
export type GraphRelationship = {
  id: string;
  subject_entity_id: string;
  predicate: string;
  object_entity_id: string;
  confidence: number;
  provider: string;
  claim_class: string;
};
export type EvidenceSource = {
  id: string;
  job_id: string;
  provider: string;
  query: string;
  raw_response_hash: string | null;
  redacted_payload: Record<string, unknown>;
  redaction_policy: string;
  retrieved_at: string;
  retain_until: string;
};
export type ClaimObservation = {
  id: string;
  source_id: string;
  entity_id: string | null;
  relationship_id: string | null;
  claim_class: string;
  confidence: number;
  observed_at: string;
};

const palette: Record<string, string> = {
  domain: "#25d9ff",
  subdomain: "#6f8cff",
  ip_address: "#f5b94c",
  certificate: "#b58af5",
};

const paletteClasses: Record<string, string> = {
  domain: "entity-dot-domain",
  subdomain: "entity-dot-subdomain",
  ip_address: "entity-dot-ip-address",
  certificate: "entity-dot-certificate",
};

export default function EvidenceGraph({
  entities,
  relationships,
  sources = [],
  observations = [],
}: {
  entities: GraphEntity[];
  relationships: GraphRelationship[];
  sources?: EvidenceSource[];
  observations?: ClaimObservation[];
}) {
  const types = useMemo(
    () =>
      Array.from(new Set(entities.map((entity) => entity.entity_type))).sort(),
    [entities],
  );
  const [visibleTypes, setVisibleTypes] = useState<Set<string>>(
    () => new Set(types),
  );
  const [selectedId, setSelectedId] = useState<string | null>(
    entities[0]?.id ?? null,
  );
  const [selectedSourceId, setSelectedSourceId] = useState("latest");
  const [view, setView] = useState({ x: 0, y: 0, scale: 1 });
  const drag = useRef<{
    x: number;
    y: number;
    originX: number;
    originY: number;
  } | null>(null);
  const touchPoints = useRef(new Map<number, { x: number; y: number }>());
  const pinch = useRef<{
    distance: number;
    anchorX: number;
    anchorY: number;
    originScale: number;
  } | null>(null);
  const selectedSource = sources.find(
    (source) => source.id === selectedSourceId,
  );
  const eligibleSourceIds = new Set(
    selectedSource
      ? sources
          .filter(
            (source) =>
              new Date(source.retrieved_at) <=
              new Date(selectedSource.retrieved_at),
          )
          .map((source) => source.id)
      : sources.map((source) => source.id),
  );
  const eligibleObservations = observations.filter((observation) =>
    eligibleSourceIds.has(observation.source_id),
  );
  const historicalEntityIds = new Set(
    eligibleObservations.flatMap((observation) =>
      observation.entity_id ? [observation.entity_id] : [],
    ),
  );
  const historicalRelationshipIds = new Set(
    eligibleObservations.flatMap((observation) =>
      observation.relationship_id ? [observation.relationship_id] : [],
    ),
  );
  const historyEnabled = sources.length > 0 && selectedSourceId !== "latest";
  const visible = entities.filter(
    (entity) =>
      visibleTypes.has(entity.entity_type) &&
      (!historyEnabled || historicalEntityIds.has(entity.id)),
  );
  const visibleIds = new Set(visible.map((entity) => entity.id));
  const edges = relationships.filter(
    (edge) =>
      visibleIds.has(edge.subject_entity_id) &&
      visibleIds.has(edge.object_entity_id) &&
      (!historyEnabled || historicalRelationshipIds.has(edge.id)),
  );
  const positions = useMemo(() => {
    const center = { x: 450, y: 325 };
    let ring = 0;
    let ringStart = 0;
    let ringCapacity = 8;
    return new Map(
      entities.map((entity, index) => {
        while (index >= ringStart + ringCapacity) {
          ringStart += ringCapacity;
          ring += 1;
          ringCapacity = 8 + ring * 6;
        }
        const positionInRing = index - ringStart;
        const angle =
          (positionInRing /
            Math.min(ringCapacity, entities.length - ringStart)) *
            Math.PI *
            2 -
          Math.PI / 2;
        const radius = entities.length < 3 ? 120 : 125 + ring * 105;
        return [
          entity.id,
          {
            x: center.x + Math.cos(angle) * radius,
            y: center.y + Math.sin(angle) * radius,
          },
        ];
      }),
    );
  }, [entities]);
  const selected = visible.find((entity) => entity.id === selectedId) ?? null;
  const connected = selected
    ? relationships.filter(
        (edge) =>
          edge.subject_entity_id === selected.id ||
          edge.object_entity_id === selected.id,
      ).length
    : 0;
  const selectedObservations = selected
    ? observations.filter(
        (observation) => observation.entity_id === selected.id,
      )
    : [];
  const latestObservation = selectedObservations[0];
  const latestSource = sources.find(
    (source) => source.id === latestObservation?.source_id,
  );
  function toggleType(type: string) {
    setVisibleTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }
  function wheel(event: WheelEvent<SVGSVGElement>) {
    event.preventDefault();
    const focus = svgPoint(event.currentTarget, event.clientX, event.clientY);
    setView((current) => {
      const nextScale = Math.min(
        2.2,
        Math.max(0.55, current.scale * (event.deltaY > 0 ? 0.9 : 1.1)),
      );
      const anchorX = (focus.x - current.x) / current.scale;
      const anchorY = (focus.y - current.y) / current.scale;
      return {
        x: focus.x - anchorX * nextScale,
        y: focus.y - anchorY * nextScale,
        scale: nextScale,
      };
    });
  }
  function svgPoint(svg: SVGSVGElement, clientX: number, clientY: number) {
    const point = svg.createSVGPoint();
    point.x = clientX;
    point.y = clientY;
    const matrix = svg.getScreenCTM();
    return matrix ? point.matrixTransform(matrix.inverse()) : point;
  }
  function pointerDown(event: PointerEvent<SVGSVGElement>) {
    if (event.pointerType === "touch") {
      event.preventDefault();
      event.currentTarget.setPointerCapture(event.pointerId);
      touchPoints.current.set(event.pointerId, {
        x: event.clientX,
        y: event.clientY,
      });
      const points = Array.from(touchPoints.current.values());
      if (points.length === 2) {
        const [first, second] = points;
        const center = svgPoint(
          event.currentTarget,
          (first.x + second.x) / 2,
          (first.y + second.y) / 2,
        );
        pinch.current = {
          distance: Math.max(
            1,
            Math.hypot(second.x - first.x, second.y - first.y),
          ),
          anchorX: (center.x - view.x) / view.scale,
          anchorY: (center.y - view.y) / view.scale,
          originScale: view.scale,
        };
        drag.current = null;
      } else if (
        points.length === 1 &&
        !(event.target as Element).closest("[data-node]")
      ) {
        const point = svgPoint(event.currentTarget, event.clientX, event.clientY);
        drag.current = {
          x: point.x,
          y: point.y,
          originX: view.x,
          originY: view.y,
        };
      }
      return;
    }
    if ((event.target as Element).closest("[data-node]")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    const point = svgPoint(event.currentTarget, event.clientX, event.clientY);
    drag.current = {
      x: point.x,
      y: point.y,
      originX: view.x,
      originY: view.y,
    };
  }
  function pointerMove(event: PointerEvent<SVGSVGElement>) {
    if (event.pointerType === "touch" && touchPoints.current.has(event.pointerId)) {
      event.preventDefault();
      touchPoints.current.set(event.pointerId, {
        x: event.clientX,
        y: event.clientY,
      });
      const points = Array.from(touchPoints.current.values());
      const activePinch = pinch.current;
      if (points.length >= 2 && activePinch) {
        const [first, second] = points;
        const distance = Math.hypot(second.x - first.x, second.y - first.y);
        const center = svgPoint(
          event.currentTarget,
          (first.x + second.x) / 2,
          (first.y + second.y) / 2,
        );
        const nextScale = Math.min(
          2.2,
          Math.max(0.55, activePinch.originScale * (distance / activePinch.distance)),
        );
        setView({
          x: center.x - activePinch.anchorX * nextScale,
          y: center.y - activePinch.anchorY * nextScale,
          scale: nextScale,
        });
        return;
      }
    }
    const activeDrag = drag.current;
    if (!activeDrag) return;
    const point = svgPoint(event.currentTarget, event.clientX, event.clientY);
    const nextX = activeDrag.originX + (point.x - activeDrag.x);
    const nextY = activeDrag.originY + (point.y - activeDrag.y);
    setView((current) => ({
      ...current,
      x: nextX,
      y: nextY,
    }));
  }
  function pointerUp(event: PointerEvent<SVGSVGElement>) {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    touchPoints.current.delete(event.pointerId);
    if (touchPoints.current.size < 2) pinch.current = null;
    drag.current = null;
  }
  return (
    <section className="detail-panel graph-workspace" id="graph">
      <header>
        <div>
          <h2>Interactive evidence graph</h2>
          <p>Drag or use one finger to pan; scroll or pinch with two fingers to zoom</p>
        </div>
        <div className="graph-actions">
          {sources.length > 0 && (
            <label>
              Evidence time
              <select
                aria-label="Evidence time"
                value={selectedSourceId}
                onChange={(event) => setSelectedSourceId(event.target.value)}
              >
                <option value="latest">Latest</option>
                {sources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {new Date(source.retrieved_at).toLocaleString()}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button onClick={() => setView({ x: 0, y: 0, scale: 1 })}>
            Fit graph
          </button>
          <span>
            {visible.length} nodes · {edges.length} edges
          </span>
        </div>
      </header>
      <div className="graph-filter" aria-label="Entity type filters">
        {types.map((type) => (
          <button
            key={type}
            aria-pressed={visibleTypes.has(type)}
            onClick={() => toggleType(type)}
          >
            <i className={paletteClasses[type] ?? "entity-dot-default"} />
            {type.replaceAll("_", " ")}
          </button>
        ))}
      </div>
      <div className="evidence-graph-layout">
        <svg
          className="evidence-graph"
          viewBox="0 0 900 650"
          role="img"
          aria-label="Evidence relationship graph"
          onWheel={wheel}
          onPointerDown={pointerDown}
          onPointerMove={pointerMove}
          onPointerUp={pointerUp}
          onPointerCancel={pointerUp}
        >
          <defs>
            <marker
              id="graph-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#40536a" />
            </marker>
          </defs>
          <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
            {edges.map((edge) => {
              const a = positions.get(edge.subject_entity_id)!;
              const b = positions.get(edge.object_entity_id)!;
              return (
                <g key={edge.id}>
                  <line
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    markerEnd="url(#graph-arrow)"
                  />
                  <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 7}>
                    {edge.predicate.replaceAll("_", " ")}
                  </text>
                </g>
              );
            })}
            {visible.map((entity) => {
              const position = positions.get(entity.id)!;
              const active = selectedId === entity.id;
              return (
                <g
                  key={entity.id}
                  data-node
                  className={active ? "selected" : ""}
                  transform={`translate(${position.x} ${position.y})`}
                  role="button"
                  tabIndex={0}
                  aria-label={`${entity.entity_type} ${entity.canonical_value}`}
                  onClick={() => setSelectedId(entity.id)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ")
                      setSelectedId(entity.id);
                  }}
                >
                  <title>{entity.canonical_value}</title>
                  <circle
                    r={active ? 29 : 24}
                    fill={palette[entity.entity_type] ?? "#91a0b2"}
                  />
                  <text className="node-type" y="4">
                    {entity.entity_type.slice(0, 3).toUpperCase()}
                  </text>
                  <text className="node-label" y="44">
                    {shortGraphLabel(entity.canonical_value)}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
        <aside className="graph-inspector">
          {selected ? (
            <>
              <span className="inspector-type">
                {selected.entity_type.replaceAll("_", " ")}
              </span>
              <h3>{selected.canonical_value}</h3>
              <dl>
                <div>
                  <dt>Confidence</dt>
                  <dd>{selected.confidence}%</dd>
                </div>
                <div>
                  <dt>Provider</dt>
                  <dd>{selected.provider.replaceAll("_", " ")}</dd>
                </div>
                <div>
                  <dt>Connections</dt>
                  <dd>{connected}</dd>
                </div>
                <div>
                  <dt>Observations</dt>
                  <dd>{selectedObservations.length}</dd>
                </div>
                <div>
                  <dt>Claim</dt>
                  <dd>
                    {String(
                      selected.attributes.classification ?? "OBSERVED_FACT",
                    ).replaceAll("_", " ")}
                  </dd>
                </div>
                {latestSource && (
                  <>
                    <div>
                      <dt>Source hash</dt>
                      <dd>
                        {latestSource.raw_response_hash?.slice(0, 12) ??
                          "pending"}
                      </dd>
                    </div>
                    <div>
                      <dt>Retained until</dt>
                      <dd>
                        {new Date(
                          latestSource.retain_until,
                        ).toLocaleDateString()}
                      </dd>
                    </div>
                  </>
                )}
              </dl>
              <p>
                {selected.attributes.synthetic
                  ? "Synthetic validation evidence. No external provider was contacted."
                  : "Provider-derived evidence."}
              </p>
            </>
          ) : (
            <p>Select a visible node to inspect its evidence.</p>
          )}
        </aside>
      </div>
    </section>
  );
}

function shortGraphLabel(value: string) {
  return value.length > 24 ? `${value.slice(0, 21)}…` : value;
}
