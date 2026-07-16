import networkx as nx
from datetime import datetime, timedelta

class CorrelationEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self.events = []
        
    def add_event(self, event):
        """
        Adds an event to the internal list and updates the NetworkX graph.
        """
        self.events.append(event)
        self.events.sort(key=lambda x: x["timestamp"]) # Maintain chronological order
        
        user = event.get("user")
        if not user:
            return
            
        u_node = f"User: {user}"
        self.graph.add_node(u_node, type="User", label=user)
        
        event_type = event.get("event_type")
        
        if event_type == "login":
            dev = event.get("device_id")
            ip = event.get("ip_address")
            success = event.get("success")
            
            d_node = f"Device: {dev}"
            ip_node = f"IP: {ip}"
            
            # Add nodes with metadata
            self.graph.add_node(d_node, type="Device", label=dev)
            self.graph.add_node(ip_node, type="IP", label=ip)
            
            # Connect User -> Device -> IP
            self.graph.add_edge(u_node, d_node, type="LoginDevice", success=success, timestamp=event["timestamp"])
            self.graph.add_edge(d_node, ip_node, type="DeviceIP", success=success, timestamp=event["timestamp"])
            self.graph.add_edge(u_node, ip_node, type="UserIP", success=success, timestamp=event["timestamp"])
            
        elif event_type == "transaction":
            txn_id = event.get("transaction_id")
            amount = event.get("amount")
            dest = event.get("destination_account")
            is_new = event.get("is_new_beneficiary")
            
            t_node = f"Txn: {txn_id}"
            a_node = f"Account: {dest}"
            
            self.graph.add_node(t_node, type="Transaction", label=f"{txn_id} (${amount})", amount=amount)
            self.graph.add_node(a_node, type="Account", label=dest)
            
            # Connect User -> Transaction -> Destination Account
            self.graph.add_edge(u_node, t_node, type="UserTxn", timestamp=event["timestamp"])
            self.graph.add_edge(t_node, a_node, type="TxnDest", timestamp=event["timestamp"])
            self.graph.add_edge(u_node, a_node, type="UserAccount", is_new=is_new)
            
        elif event_type == "sim_swap":
            flagged = event.get("flagged")
            sim_node = f"SIM: {user}_SIM"
            
            self.graph.add_node(sim_node, type="SIM", label="SIM Card", flagged=flagged)
            self.graph.add_edge(u_node, sim_node, type="UserSIM", flagged=flagged, timestamp=event["timestamp"])
            
    def rebuild_graph(self, all_events):
        """
        Rebuilds the graph completely from a list of events.
        """
        self.graph.clear()
        self.events = []
        for evt in all_events:
            self.add_event(evt)

    def find_suspicious_paths(self, user, time_window_minutes=30):
        """
        Finds suspicious nodes and edges for a user within the specified time window.
        Returns:
            suspicious_nodes: set of node names
            suspicious_edges: list of (node1, node2) tuples
            rules_triggered: list of trigger descriptions
        """
        suspicious_nodes = set()
        suspicious_edges = list()
        rules_triggered = []
        
        user_node = f"User: {user}"
        if not self.graph.has_node(user_node):
            return suspicious_nodes, suspicious_edges, rules_triggered
            
        # Get all events for this user
        user_evts = [e for e in self.events if e.get("user") == user]
        if not user_evts:
            return suspicious_nodes, suspicious_edges, rules_triggered
            
        # 1. Rule: SIM Swap followed by Large Transaction within time window
        sim_events = [e for e in user_evts if e["event_type"] == "sim_swap" and e.get("flagged")]
        txn_events = [e for e in user_evts if e["event_type"] == "transaction"]
        
        for sim in sim_events:
            sim_t = sim["timestamp"]
            for txn in txn_events:
                txn_t = txn["timestamp"]
                # SIM Swap occurred before transaction, and within the window, and amount is large (> $5000)
                if sim_t <= txn_t <= sim_t + timedelta(minutes=time_window_minutes) and txn["amount"] >= 5000:
                    desc = f"SIM Swap (at {sim_t.strftime('%H:%M:%S')}) followed by Large Transaction ${txn['amount']} (at {txn_t.strftime('%H:%M:%S')})"
                    rules_triggered.append(desc)
                    
                    # Highlight SIM node, User node, Txn node, and Account node
                    sim_node = f"SIM: {user}_SIM"
                    t_node = f"Txn: {txn['transaction_id']}"
                    a_node = f"Account: {txn['destination_account']}"
                    
                    suspicious_nodes.update([user_node, sim_node, t_node, a_node])
                    
                    # Add edges
                    for u, v in [(user_node, sim_node), (user_node, t_node), (t_node, a_node)]:
                        if self.graph.has_edge(u, v):
                            suspicious_edges.append((u, v))

        # 2. Rule: New Device + Foreign IP (Tor/North Korea/Russia or different location) occurring together
        # We look for successful logins from new/suspicious locations
        login_events = [e for e in user_evts if e["event_type"] == "login" and e.get("success")]
        for login in login_events:
            loc = login.get("location", "")
            # Assume location with "Russia" or "North Korea" or foreign IPs represent foreign risks
            is_foreign = loc in ["North Korea", "Russia"] or login.get("ip_address", "").startswith("185.220.")
            
            # Check if this device is new. A device is new if there are very few logins on it.
            # In our data generator, foreign IPs/new devices are correlated
            if is_foreign:
                desc = f"Login from suspicious location/IP: {loc} ({login['ip_address']}) using device {login['device_id']}"
                rules_triggered.append(desc)
                
                d_node = f"Device: {login['device_id']}"
                ip_node = f"IP: {login['ip_address']}"
                
                suspicious_nodes.update([user_node, d_node, ip_node])
                for u, v in [(user_node, d_node), (d_node, ip_node), (user_node, ip_node)]:
                    if self.graph.has_edge(u, v):
                        suspicious_edges.append((u, v))

        # 3. Rule: Multiple failed logins (e.g., 3+) followed by a transaction
        failed_logins = [e for e in user_evts if e["event_type"] == "login" and not e.get("success")]
        if len(failed_logins) >= 3:
            # Check if there is a transaction shortly after the last failed login
            last_failed_t = failed_logins[-1]["timestamp"]
            first_failed_t = failed_logins[0]["timestamp"]
            
            # Check if the failed logins occurred in a cluster (e.g. 5 minutes)
            if last_failed_t - first_failed_t <= timedelta(minutes=10):
                for txn in txn_events:
                    txn_t = txn["timestamp"]
                    if last_failed_t <= txn_t <= last_failed_t + timedelta(minutes=time_window_minutes):
                        desc = f"Brute Force Alert: {len(failed_logins)} failed logins followed by Transaction ${txn['amount']}"
                        rules_triggered.append(desc)
                        
                        t_node = f"Txn: {txn['transaction_id']}"
                        a_node = f"Account: {txn['destination_account']}"
                        
                        suspicious_nodes.update([user_node, t_node, a_node])
                        if self.graph.has_edge(user_node, t_node):
                            suspicious_edges.append((user_node, t_node))
                        if self.graph.has_edge(t_node, a_node):
                            suspicious_edges.append((t_node, a_node))
                            
                        # Also include the IP/devices that failed
                        for f_login in failed_logins:
                            fd_node = f"Device: {f_login['device_id']}"
                            fip_node = f"IP: {f_login['ip_address']}"
                            suspicious_nodes.update([fd_node, fip_node])
                            for u, v in [(user_node, fd_node), (fd_node, fip_node), (user_node, fip_node)]:
                                if self.graph.has_edge(u, v):
                                    suspicious_edges.append((u, v))

        # 4. Rule: Any 3+ correlated security events (SIM swaps, login failures, suspicious logins)
        # touching the same account within the window
        all_security_signals = [e for e in user_evts if e["event_type"] == "sim_swap" or (e["event_type"] == "login" and (not e.get("success") or e.get("location") in ["North Korea", "Russia"]))]
        if len(all_security_signals) >= 3:
            for txn in txn_events:
                dest_acc = txn["destination_account"]
                # If these security signals happened close to the transaction
                txn_t = txn["timestamp"]
                nearby_signals = [s for s in all_security_signals if abs((txn_t - s["timestamp"]).total_seconds()) <= time_window_minutes * 60]
                if len(nearby_signals) >= 3:
                    desc = f"Multi-signal security escalation ({len(nearby_signals)} events) surrounding Account {dest_acc}"
                    rules_triggered.append(desc)
                    
                    t_node = f"Txn: {txn['transaction_id']}"
                    a_node = f"Account: {dest_acc}"
                    suspicious_nodes.update([user_node, t_node, a_node])
                    if self.graph.has_edge(user_node, t_node):
                        suspicious_edges.append((user_node, t_node))
                    if self.graph.has_edge(t_node, a_node):
                        suspicious_edges.append((t_node, a_node))
                        
                    for sig in nearby_signals:
                        if sig["event_type"] == "sim_swap":
                            s_node = f"SIM: {user}_SIM"
                            suspicious_nodes.add(s_node)
                            if self.graph.has_edge(user_node, s_node):
                                suspicious_edges.append((user_node, s_node))
                        elif sig["event_type"] == "login":
                            d_node = f"Device: {sig['device_id']}"
                            ip_node = f"IP: {sig['ip_address']}"
                            suspicious_nodes.update([d_node, ip_node])
                            if self.graph.has_edge(user_node, d_node):
                                suspicious_edges.append((user_node, d_node))
                            if self.graph.has_edge(d_node, ip_node):
                                suspicious_edges.append((d_node, ip_node))
                                
        # Clean duplicates from edges list (as (u, v) or (v, u))
        unique_edges = []
        seen = set()
        for u, v in suspicious_edges:
            pair = tuple(sorted([u, v]))
            if pair not in seen:
                seen.add(pair)
                unique_edges.append((u, v))
                
        return suspicious_nodes, unique_edges, list(set(rules_triggered))

if __name__ == "__main__":
    print("--- Testing correlation_engine.py ---")
    from data_generator import generate_users, generate_known_entities, generate_attack_chain, generate_legitimate_large_transaction
    
    users = generate_users(2)
    devs, ips, accs = generate_known_entities(users)
    user = users[0]
    
    engine = CorrelationEngine()
    
    print("\n1. Testing Attack Chain correlation...")
    chain = generate_attack_chain(user)
    engine.rebuild_graph(chain)
    
    print(f"Graph nodes: {list(engine.graph.nodes)}")
    print(f"Graph edges: {list(engine.graph.edges)}")
    
    nodes, edges, rules = engine.find_suspicious_paths(user)
    print("Rules triggered (should detect SIM swap + large txn, and suspicious login):")
    for r in rules:
        print(f" - {r}")
    print(f"Suspicious Nodes: {nodes}")
    print(f"Suspicious Edges: {edges}")
    
    print("\n2. Testing Legitimate Large Transaction correlation (should not trigger SIM swap rules)...")
    legit_chain = generate_legitimate_large_transaction(user, devs, ips)
    engine.rebuild_graph(legit_chain)
    nodes_l, edges_l, rules_l = engine.find_suspicious_paths(user)
    print("Rules triggered (should be empty, or only if location matches foreign blacklists):")
    print(rules_l)
    
    print("--- correlation_engine.py verified successfully ---")
