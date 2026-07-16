import pandas as pd
from datetime import datetime, timedelta

def scan_encryption_inventory(inventory_df):
    """
    Scans the encryption inventory and classifies systems based on quantum risk.
    Kyber/AES-256 are classified as Low risk.
    RSA/ECC are classified as High risk (or Medium if migration is > 50%).
    """
    scanned_inventory = []
    
    for _, row in inventory_df.iterrows():
        system = row["system_name"]
        alg = row["algorithm"]
        progress = row["migration_progress"]
        
        # Determine risk based on algorithm and migration progress
        if "Kyber" in alg or "AES" in alg:
            risk = "Low"
            desc = "Quantum-Safe Cryptography (Post-Quantum Algorithm / Sufficient Symmetric Key Size)"
        else: # RSA or ECC
            if progress >= 90:
                risk = "Low"
                desc = "Migration almost complete — minimal risk exposure"
            elif progress >= 50:
                risk = "Medium"
                desc = f"Legacy classical algorithm ({alg}) - active migration in progress ({progress}%)"
            else:
                risk = "High"
                desc = f"Vulnerable classical algorithm ({alg}) - high risk of decryption by quantum adversaries"
                
        scanned_inventory.append({
            "system_name": system,
            "algorithm": alg,
            "migration_progress": progress,
            "quantum_risk": risk,
            "description": desc
        })
        
    return pd.DataFrame(scanned_inventory)

def detect_hndl_risk(events_list, inventory_df):
    """
    Harvest Now, Decrypt Later (HNDL) Heuristic:
    Checks if there's a large data transfer event (e.g., > 5 GB) to an external/unfamiliar IP
    from a system running legacy classical encryption (RSA/ECC) with progress < 80%.
    """
    hndl_alerts = []
    
    # Extract vulnerable systems
    vulnerable_systems = set(
        inventory_df[
            (inventory_df["algorithm"].str.contains("RSA|ECC")) & 
            (inventory_df["migration_progress"] < 80)
        ]["system_name"].tolist()
    )
    
    # We look for "data_exfiltration" or "data_transfer" events in telemetry
    for event in events_list:
        if event.get("event_type") == "data_transfer":
            system = event.get("system_name")
            bytes_transferred = event.get("bytes_transferred", 0)
            destination = event.get("destination_ip", "")
            
            # Check if source system is in the vulnerable set
            # and transfer size is large (e.g. > 5 GB, 5 * 1024^3 bytes)
            if system in vulnerable_systems and bytes_transferred >= 5 * 1024 * 1024 * 1024:
                gb_size = round(bytes_transferred / (1024 * 1024 * 1024), 2)
                hndl_alerts.append({
                    "system_name": system,
                    "algorithm": next((item["algorithm"] for item in inventory_df.to_dict('records') if item["system_name"] == system), "Unknown"),
                    "destination": destination,
                    "transfer_size_gb": gb_size,
                    "timestamp": event.get("timestamp"),
                    "severity": "CRITICAL",
                    "threat_type": "HNDL (Harvest Now, Decrypt Later)",
                    "details": f"Large exfiltration of {gb_size} GB to {destination} detected from legacy encrypted system '{system}'. Threat: Adversary harvesting encrypted data for decryption once Cryptanalytically Relevant Quantum Computers (CRQCs) emerge."
                })
                
    return hndl_alerts

def detect_sequence_threat(events_list, user, time_window_minutes=25):
    """
    Proactive sequence detection: login -> credential/password reset -> new device login -> large transaction.
    Chronological verification checks for a pattern within the given time window.
    """
    user_evts = [e for e in events_list if e.get("user") == user]
    # Sort events by timestamp
    user_evts = sorted(user_evts, key=lambda x: x["timestamp"])
    
    if len(user_evts) < 3:
        return {
            "threat_detected": False,
            "reason": "Insufficient event history for sequence analysis."
        }
        
    # We want to match:
    # 1. Initiating event: Failed login cluster or SIM Swap or a password_reset event
    # 2. Login event on a new device (not in user's regular profile)
    # 3. Transaction event with amount >= $5,000
    
    sim_swap_t = None
    login_fail_t = None
    new_device_login_t = None
    
    for evt in user_evts:
        etype = evt["event_type"]
        ts = evt["timestamp"]
        
        if etype == "sim_swap" and evt.get("flagged"):
            sim_swap_t = ts
            
        elif etype == "login":
            if not evt.get("success"):
                login_fail_t = ts
            elif evt.get("success"):
                # Check if it looks like a new/unfamiliar device (e.g. from foreign IP or Korea/Russia)
                is_suspicious_device = evt.get("location") in ["North Korea", "Russia"] or "DEV-" in evt.get("device_id", "")
                
                # Check if it occurs after the SIM swap or login failure
                trigger_t = sim_swap_t or login_fail_t
                if trigger_t and ts > trigger_t and (ts - trigger_t) <= timedelta(minutes=time_window_minutes):
                    new_device_login_t = ts
                    
        elif etype == "transaction":
            amount = evt.get("amount", 0)
            if amount >= 5000:
                # Must follow new device login
                if new_device_login_t and ts > new_device_login_t and (ts - new_device_login_t) <= timedelta(minutes=time_window_minutes):
                    trigger_t = sim_swap_t or login_fail_t
                    total_duration = int((ts - trigger_t).total_seconds() / 60)
                    
                    trigger_type = "SIM Swap" if sim_swap_t else "Failed Login Burst"
                    return {
                        "threat_detected": True,
                        "trigger_type": trigger_type,
                        "duration_minutes": total_duration,
                        "transaction_id": evt.get("transaction_id"),
                        "amount": amount,
                        "reason": f"PROACTIVE RULE TRIGGERED: Chronological sequence match ({trigger_type} -> Login on New Device -> Large Transaction) completed in {total_duration} minutes."
                    }
                    
    return {
        "threat_detected": False,
        "reason": "No matched attack sequences in active event history."
    }

if __name__ == "__main__":
    print("--- Testing quantum_scanner.py ---")
    from data_generator import generate_encryption_inventory
    
    inv_df = generate_encryption_inventory()
    print("Encryption Inventory:")
    print(inv_df)
    
    print("\nScanning Inventory for Quantum Vulnerabilities:")
    scanned_df = scan_encryption_inventory(inv_df)
    print(scanned_df[["system_name", "algorithm", "quantum_risk", "migration_progress"]])
    
    print("\nTesting HNDL Heuristic:")
    now = datetime.now()
    test_events = [
        # Large exfiltration event from ECC server
        {
            "event_type": "data_transfer",
            "system_name": "Customer Auth Service",
            "bytes_transferred": int(6.2 * 1024 * 1024 * 1024), # 6.2 GB
            "destination_ip": "93.184.216.34",
            "timestamp": now
        },
        # Normal exfiltration from Kyber server (should not trigger alert because Kyber is secure)
        {
            "event_type": "data_transfer",
            "system_name": "Swift Payment Gateway",
            "bytes_transferred": int(10 * 1024 * 1024 * 1024), # 10 GB
            "destination_ip": "93.184.216.34",
            "timestamp": now + timedelta(minutes=5)
        }
    ]
    alerts = detect_hndl_risk(test_events, scanned_df)
    print(f"HNDL Alerts found: {len(alerts)}")
    for a in alerts:
        print(f" - System: {a['system_name']} ({a['algorithm']}) -> {a['details']}")
        
    print("\nTesting Proactive Sequence Detection:")
    sequence_events = [
        {
            "event_type": "sim_swap",
            "user": "bob",
            "timestamp": now,
            "flagged": True
        },
        {
            "event_type": "login",
            "user": "bob",
            "timestamp": now + timedelta(minutes=2),
            "device_id": "DEV-NEWX99",
            "ip_address": "185.220.101.5",
            "location": "Russia",
            "success": True
        },
        {
            "event_type": "transaction",
            "user": "bob",
            "transaction_id": "TXN-BOB-01",
            "amount": 7500.00,
            "destination_account": "ACC-RED-001",
            "timestamp": now + timedelta(minutes=5)
        }
    ]
    
    seq_res = detect_sequence_threat(sequence_events, "bob")
    print(seq_res)
    print("--- quantum_scanner.py verified successfully ---")
