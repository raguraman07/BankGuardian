"""
FinSpark Security AI — FastAPI Backend
Wraps the existing ML modules and exposes REST endpoints for the HTML/CSS/JS frontend.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import random
import os

# ── Import existing ML modules ──────────────────────────────────────────────
from data_generator import generate_encryption_inventory, generate_users, generate_known_entities
from stream_simulator import StreamSimulator
from correlation_engine import CorrelationEngine
from fraud_model import correlated_score, raw_score
from quantum_scanner import scan_encryption_inventory, detect_hndl_risk, detect_sequence_threat
from explainability import explain_threat

# ── App State ──────────────────────────────────────────────────────────────
class AppState:
    def __init__(self):
        print("[API] Initializing ML components...")
        self.simulator = StreamSimulator()
        self.engine = CorrelationEngine()
        self.events_history = []
        self.scored_transactions = []
        self.alerts = []
        self.false_positives_avoided = 0
        self.alerts_count = 0
        self.hndl_alerts = []
        self.sequence_alerts = []
        self.encryption_inventory = scan_encryption_inventory(generate_encryption_inventory())

        # Pre-populate with 30 historical events
        print("[API] Pre-populating historical events...")
        for _ in range(30):
            evt = self.simulator.get_next_event()
            if evt:
                self._process(evt)

        # Inject a demo HNDL event
        hndl_evt = {
            "event_type": "data_transfer",
            "system_name": "Core Banking Ledger",
            "bytes_transferred": int(5.6 * 1024 * 1024 * 1024),
            "destination_ip": "104.244.42.1",
            "timestamp": datetime.now()
        }
        self._process(hndl_evt)
        print(f"[API] Ready. {len(self.events_history)} events loaded.")

    def _process(self, evt):
        self.events_history.append(evt)
        self.engine.add_event(evt)

        if evt.get("event_type") == "transaction":
            user = evt.get("user")
            score_res = correlated_score(evt, self.engine, user)
            scored_txn = {
                "transaction_id": evt["transaction_id"],
                "user": user,
                "amount": evt["amount"],
                "timestamp": evt["timestamp"].isoformat() if isinstance(evt["timestamp"], datetime) else str(evt["timestamp"]),
                "is_new_beneficiary": evt["is_new_beneficiary"],
                "raw_score": score_res["raw_score"],
                "correlated_score": score_res["correlated_score"],
                "adjustment_reason": score_res["adjustment_reason"],
                "status": score_res["status"]
            }
            if score_res["raw_score"] >= 0.60 and score_res["correlated_score"] < 0.60:
                self.false_positives_avoided += 1
            if score_res["status"] == "high":
                self.alerts_count += 1
                self.alerts.append({
                    "id": f"ALT-{len(self.alerts)+1:04d}",
                    "transaction_id": evt["transaction_id"],
                    "user": user,
                    "amount": evt["amount"],
                    "risk_score": score_res["correlated_score"],
                    "reason": score_res["adjustment_reason"],
                    "status": "open",
                    "timestamp": scored_txn["timestamp"]
                })
            self.scored_transactions.append(scored_txn)

            seq_res = detect_sequence_threat(self.events_history, user)
            if seq_res["threat_detected"]:
                self.sequence_alerts.append({
                    "user": user,
                    "timestamp": evt["timestamp"].isoformat() if isinstance(evt["timestamp"], datetime) else str(evt["timestamp"]),
                    "reason": seq_res["reason"],
                    "transaction_id": seq_res.get("transaction_id",""),
                    "amount": seq_res.get("amount",0)
                })

        if evt.get("event_type") == "data_transfer":
            hndl_res = detect_hndl_risk([evt], self.encryption_inventory)
            if hndl_res:
                self.hndl_alerts.extend(hndl_res)

    def tick(self):
        """Pull next event from simulator and process it."""
        evt = self.simulator.get_next_event()
        if evt:
            self._process(evt)
            return evt
        return None

    def inject(self, scenario_name, user=None):
        if not user:
            user = random.choice(self.simulator.users)
        chosen_user, events = self.simulator.inject_scenario(scenario_name, user)
        for e in events:
            self._process(e)
        return chosen_user, events


# Singleton state
state = AppState()

# ── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(title="FinSpark Security AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
web_dir = os.path.join(os.path.dirname(__file__), "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")


# ── Helper to serialize events ───────────────────────────────────────────────
def serialize_event(evt):
    d = dict(evt)
    if isinstance(d.get("timestamp"), datetime):
        d["timestamp"] = d["timestamp"].isoformat()
    return d


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "FinSpark Security AI API"}


@app.get("/api/kpis")
def get_kpis():
    total_tx = len([e for e in state.events_history if e.get("event_type") == "transaction"])
    total_cyber = len([e for e in state.events_history if e.get("event_type") in ["login", "sim_swap", "data_transfer"]])
    return {
        "total_transactions": total_tx,
        "cyber_events": total_cyber,
        "high_risk_alerts": state.alerts_count,
        "false_positives_avoided": state.false_positives_avoided,
        "sequence_threats_blocked": len(state.sequence_alerts),
        "hndl_risks": len(state.hndl_alerts),
        "quantum_risk_score": 62,
    }


@app.get("/api/live-feed")
def get_live_feed(limit: int = 40):
    """Returns the most recent N events as a live feed."""
    recent = list(reversed(state.events_history[-limit:]))
    return [serialize_event(e) for e in recent]


@app.post("/api/tick")
def tick_event():
    """Advance the stream by one event."""
    evt = state.tick()
    if evt:
        return {"status": "ok", "event": serialize_event(evt)}
    return {"status": "empty"}


class ScenarioRequest(BaseModel):
    scenario: str  # "safe_transaction" | "attack_chain" | "legitimate_large"
    user: Optional[str] = None

@app.post("/api/inject-scenario")
def inject_scenario(req: ScenarioRequest):
    user, events = state.inject(req.scenario, req.user)
    return {
        "status": "ok",
        "user": user,
        "events_injected": len(events),
        "events": [serialize_event(e) for e in events]
    }


class ScoreRequest(BaseModel):
    user: str
    scenario: str  # "safe" | "sim_swap_fraud" | "large_legit"

@app.post("/api/score-transaction")
def score_transaction(req: ScoreRequest):
    """Score a transaction directly from a scenario name (used by Phase 7 interception UI)."""
    scenario_map = {
        "safe": "safe_transaction",
        "sim_swap_fraud": "attack_chain",
        "large_legit": "legitimate_large"
    }
    sim_scenario = scenario_map.get(req.scenario, "safe_transaction")
    user, events = state.inject(sim_scenario, req.user)

    tx_event = next((e for e in events if e.get("event_type") == "transaction"), None)
    if not tx_event:
        return {"error": "No transaction in scenario"}

    score_res = correlated_score(tx_event, state.engine, user)
    _, _, rules = state.engine.find_suspicious_paths(user)
    explanation = explain_threat(tx_event, score_res, rules)

    recent_events = [serialize_event(e) for e in events if e.get("event_type") != "transaction"]

    return {
        "transaction": {
            "id": tx_event.get("transaction_id"),
            "user": user,
            "amount": tx_event.get("amount"),
            "destination": tx_event.get("destination_account"),
            "timestamp": tx_event["timestamp"].isoformat()
        },
        "raw_score": score_res["raw_score"],
        "correlated_score": score_res["correlated_score"],
        "status": score_res["status"],
        "adjustment_reason": score_res["adjustment_reason"],
        "explanation": explanation["narrative"],
        "contributing_factors": explanation["contributing_factors"],
        "recent_events": recent_events
    }


@app.get("/api/fraud-transactions")
def get_fraud_transactions(limit: int = 30):
    return list(reversed(state.scored_transactions[-limit:]))


@app.get("/api/alerts")
def get_alerts(limit: int = 20):
    return list(reversed(state.alerts[-limit:]))


@app.get("/api/sequence-alerts")
def get_sequence_alerts():
    return state.sequence_alerts[-10:]


@app.get("/api/hndl-alerts")
def get_hndl_alerts():
    alerts = []
    for a in state.hndl_alerts:
        d = dict(a)
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        alerts.append(d)
    return alerts


@app.get("/api/quantum-inventory")
def get_quantum_inventory():
    return state.encryption_inventory.to_dict(orient="records")


@app.get("/api/graph/{user}")
def get_graph(user: str):
    """Return graph nodes/edges for a specific user (or 'all')."""
    import networkx as nx

    graph = state.engine.graph

    if user != "all":
        user_node = f"User: {user}"
        if graph.has_node(user_node):
            node_keys = list(nx.single_source_shortest_path_length(graph, user_node, cutoff=2).keys())
            subgraph = graph.subgraph(node_keys)
        else:
            subgraph = nx.Graph()
        susp_nodes, susp_edges, rules = state.engine.find_suspicious_paths(user)
    else:
        subgraph = graph
        susp_nodes = set()
        susp_edges = []
        rules = []
        for u in state.simulator.users:
            sn, se, _ = state.engine.find_suspicious_paths(u)
            susp_nodes.update(sn)
            susp_edges.extend(se)

    nodes = []
    for n in subgraph.nodes():
        node_data = dict(subgraph.nodes[n])
        nodes.append({
            "id": n,
            "label": node_data.get("label", n.split(": ")[-1] if ": " in n else n),
            "type": node_data.get("type", "Unknown"),
            "suspicious": n in susp_nodes
        })

    edges = []
    seen = set()
    for u, v in subgraph.edges():
        key = tuple(sorted([u, v]))
        if key not in seen:
            seen.add(key)
            is_susp = (u, v) in susp_edges or (v, u) in susp_edges
            edges.append({"from": u, "to": v, "suspicious": is_susp})

    return {"nodes": nodes, "edges": edges, "rules": rules}


@app.get("/api/users")
def get_users():
    return {"users": list(state.simulator.users)}


@app.get("/api/ai-models")
def get_ai_models():
    import random
    return [
        {"name": "Isolation Forest", "type": "Anomaly Detection", "status": "running", "accuracy": 94.7, "latency_ms": random.randint(8, 18)},
        {"name": "Sequence Detector", "type": "Behavioural Analysis", "status": "running", "accuracy": 91.2, "latency_ms": random.randint(15, 28)},
        {"name": "Quantum Risk Scanner", "type": "Crypto Vulnerability", "status": "running", "accuracy": 88.5, "latency_ms": random.randint(40, 60)},
        {"name": "Correlation Engine", "type": "Graph-Based Fusion", "status": "running", "accuracy": 96.3, "latency_ms": random.randint(6, 14)},
        {"name": "Explainability Engine", "type": "SHAP Attribution", "status": "running", "accuracy": 99.1, "latency_ms": random.randint(3, 8)},
    ]


@app.delete("/api/reset")
def reset_state():
    global state
    state = AppState()
    return {"status": "reset", "message": "Dashboard state cleared and reloaded."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
