import random
import uuid
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)
np.random.seed(42)

# System list for encryption inventory
SYSTEMS = [
    {"system_name": "Core Banking Ledger", "algorithm": "RSA-2048", "risk_level": "High", "migration_progress": 15},
    {"system_name": "Customer Auth Service", "algorithm": "ECC-256", "risk_level": "High", "migration_progress": 40},
    {"system_name": "Swift Payment Gateway", "algorithm": "Kyber-768", "risk_level": "Low", "migration_progress": 100},
    {"system_name": "Mobile API Endpoint", "algorithm": "RSA-4096", "risk_level": "High", "migration_progress": 5},
    {"system_name": "Card Processing Engine", "algorithm": "ECC-384", "risk_level": "High", "migration_progress": 60},
    {"system_name": "Internal HR Portal", "algorithm": "AES-256", "risk_level": "Low", "migration_progress": 100},
    {"system_name": "Data Analytics Lake", "algorithm": "RSA-2048", "risk_level": "High", "migration_progress": 10},
    {"system_name": "Wealth Management API", "algorithm": "Kyber-1024", "risk_level": "Low", "migration_progress": 100}
]

def generate_users(num_users=30):
    return [fake.user_name() for _ in range(num_users)]

def generate_known_entities(users):
    user_devices = {}
    user_ips = {}
    user_accounts = {}
    
    for u in users:
        user_devices[u] = [f"DEV-{uuid.uuid4().hex[:8].upper()}" for _ in range(random.randint(1, 2))]
        user_ips[u] = [fake.ipv4_public() for _ in range(random.randint(1, 2))]
        user_accounts[u] = [f"ACC-{random.randint(100000, 999999)}" for _ in range(random.randint(1, 2))]
        
    return user_devices, user_ips, user_accounts

def generate_background_logins(users, user_devices, user_ips, n=200, start_time=None):
    if not start_time:
        start_time = datetime.now() - timedelta(days=1)
        
    events = []
    for _ in range(n):
        u = random.choice(users)
        # 95% chance of using a known device, 5% new device
        is_known_dev = random.random() < 0.95
        dev = random.choice(user_devices[u]) if is_known_dev else f"DEV-{uuid.uuid4().hex[:8].upper()}"
        
        # 95% chance of using a known IP, 5% foreign IP
        is_known_ip = random.random() < 0.95
        ip = random.choice(user_ips[u]) if is_known_ip else fake.ipv4_public()
        
        loc = fake.city() if is_known_ip else fake.country()
        
        # 92% success rate, 8% fail
        success = random.random() < 0.92
        
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        
        events.append({
            "event_type": "login",
            "user": u,
            "timestamp": timestamp,
            "device_id": dev,
            "ip_address": ip,
            "location": loc,
            "success": success
        })
        
    # Generate some failed login bursts to simulate brute force
    brute_users = random.sample(users, min(5, len(users)))
    for u in brute_users:
        burst_time = start_time + timedelta(seconds=random.randint(0, 86400))
        dev = f"DEV-{uuid.uuid4().hex[:8].upper()}"
        ip = fake.ipv4_public()
        loc = fake.country()
        for i in range(random.randint(4, 7)):
            events.append({
                "event_type": "login",
                "user": u,
                "timestamp": burst_time + timedelta(seconds=i * 15),
                "device_id": dev,
                "ip_address": ip,
                "location": loc,
                "success": False
            })
            
    return pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)

def generate_background_transactions(users, user_accounts, n=300, start_time=None):
    if not start_time:
        start_time = datetime.now() - timedelta(days=1)
        
    events = []
    for _ in range(n):
        u = random.choice(users)
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        
        # Regular transaction amounts (usually small to moderate)
        # Log-normal distribution to simulate real-world transaction distribution
        amount = round(float(np.random.lognormal(mean=4.5, sigma=1.0)), 2)
        amount = max(5.0, min(amount, 15000.0))  # Clamp between $5 and $15,000
        
        dest = f"ACC-{random.randint(100000, 999999)}"
        
        events.append({
            "event_type": "transaction",
            "transaction_id": f"TXN-{uuid.uuid4().hex[:10].upper()}",
            "user": u,
            "amount": amount,
            "destination_account": dest,
            "timestamp": timestamp,
            "is_new_beneficiary": random.random() < 0.3
        })
        
    return pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)

def generate_sim_swaps(users, n=15, start_time=None):
    if not start_time:
        start_time = datetime.now() - timedelta(days=1)
        
    events = []
    for _ in range(n):
        u = random.choice(users)
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        # 80% false alarms (flagged no/yes), 20% flagged yes
        flagged = random.random() < 0.20
        events.append({
            "event_type": "sim_swap",
            "user": u,
            "timestamp": timestamp,
            "flagged": flagged
        })
    return pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)

def generate_encryption_inventory():
    return pd.DataFrame(SYSTEMS)

# Scenario Generators
def generate_attack_chain(user, base_time=None):
    """
    SIM Swap -> Login from New Device/Foreign IP -> Large Transaction to New Beneficiary
    """
    if not base_time:
        base_time = datetime.now()
        
    # 1. SIM Swap Event
    sim_time = base_time
    sim_event = {
        "event_type": "sim_swap",
        "user": user,
        "timestamp": sim_time,
        "flagged": True
    }
    
    # 2. Login Event (new device, foreign IP, success)
    login_time = sim_time + timedelta(minutes=random.randint(2, 4))
    new_dev = f"DEV-{uuid.uuid4().hex[:8].upper()}"
    foreign_ip = "185.220.101.5"  # Typical Tor exit node style
    login_event = {
        "event_type": "login",
        "user": user,
        "timestamp": login_time,
        "device_id": new_dev,
        "ip_address": foreign_ip,
        "location": "North Korea" if random.random() < 0.5 else "Russia",
        "success": True
    }
    
    # 3. Large Transaction (e.g. $18,500) to new destination
    txn_time = login_time + timedelta(minutes=random.randint(2, 5))
    dest_acc = f"ACC-{random.randint(900000, 999999)}"
    txn_event = {
        "event_type": "transaction",
        "transaction_id": f"TXN-{uuid.uuid4().hex[:10].upper()}",
        "user": user,
        "amount": round(random.uniform(9000.0, 25000.0), 2),
        "destination_account": dest_acc,
        "timestamp": txn_time,
        "is_new_beneficiary": True
    }
    
    return [sim_event, login_event, txn_event]

def generate_legitimate_large_transaction(user, user_devices, user_ips, base_time=None):
    """
    Known device + Known IP -> Large transaction (no SIM swap)
    This is designed to test false-positive downweighting!
    """
    if not base_time:
        base_time = datetime.now()
        
    # Login event (normal device, normal IP, success)
    login_time = base_time
    dev = random.choice(user_devices[user])
    ip = random.choice(user_ips[user])
    login_event = {
        "event_type": "login",
        "user": user,
        "timestamp": login_time,
        "device_id": dev,
        "ip_address": ip,
        "location": "Local",
        "success": True
    }
    
    # Large transaction to regular or new destination (e.g., $15,000 for a car or transfer)
    txn_time = login_time + timedelta(minutes=random.randint(1, 3))
    dest_acc = f"ACC-{random.randint(100000, 999999)}"
    txn_event = {
        "event_type": "transaction",
        "transaction_id": f"TXN-{uuid.uuid4().hex[:10].upper()}",
        "user": user,
        "amount": round(random.uniform(8500.0, 20000.0), 2),
        "destination_account": dest_acc,
        "timestamp": txn_time,
        "is_new_beneficiary": random.random() < 0.5
    }
    
    return [login_event, txn_event]

def generate_safe_transaction(user, user_devices, user_ips, base_time=None):
    """
    Standard low-amount normal transaction.
    """
    if not base_time:
        base_time = datetime.now()
        
    login_time = base_time
    dev = random.choice(user_devices[user])
    ip = random.choice(user_ips[user])
    login_event = {
        "event_type": "login",
        "user": user,
        "timestamp": login_time,
        "device_id": dev,
        "ip_address": ip,
        "location": "Local",
        "success": True
    }
    
    txn_time = login_time + timedelta(minutes=random.randint(1, 3))
    dest_acc = f"ACC-{random.randint(100000, 999999)}"
    txn_event = {
        "event_type": "transaction",
        "transaction_id": f"TXN-{uuid.uuid4().hex[:10].upper()}",
        "user": user,
        "amount": round(random.uniform(10.0, 500.0), 2),
        "destination_account": dest_acc,
        "timestamp": txn_time,
        "is_new_beneficiary": False
    }
    
    return [login_event, txn_event]

if __name__ == "__main__":
    print("--- Testing data_generator.py ---")
    users = generate_users(5)
    devs, ips, accs = generate_known_entities(users)
    
    print("Users generated:", users)
    print("\nSample Known Entities (First User):")
    first_user = users[0]
    print(f"Devices for {first_user}: {devs[first_user]}")
    print(f"IPs for {first_user}: {ips[first_user]}")
    print(f"Accounts for {first_user}: {accs[first_user]}")
    
    print("\nGenerating background log data...")
    logins_df = generate_background_logins(users, devs, ips, n=20)
    print(f"Logins (First 3 events):\n{logins_df.head(3)}")
    
    print("\nGenerating background transaction data...")
    txns_df = generate_background_transactions(users, accs, n=30)
    print(f"Transactions (First 3 events):\n{txns_df.head(3)}")
    
    print("\nGenerating SIM Swaps...")
    sims_df = generate_sim_swaps(users, n=5)
    print(f"SIM Swaps (First 3 events):\n{sims_df.head(3)}")
    
    print("\nGenerating Attack Chain for user:", first_user)
    chain = generate_attack_chain(first_user)
    for event in chain:
        print(f"  Event: {event['event_type']} at {event['timestamp']} details: { {k:v for k,v in event.items() if k not in ['event_type', 'timestamp']} }")
        
    print("\nGenerating Legitimate Large Transaction for user:", first_user)
    legit_chain = generate_legitimate_large_transaction(first_user, devs, ips)
    for event in legit_chain:
        print(f"  Event: {event['event_type']} at {event['timestamp']} details: { {k:v for k,v in event.items() if k not in ['event_type', 'timestamp']} }")
        
    print("\nGenerating Encryption Inventory:")
    enc_df = generate_encryption_inventory()
    print(enc_df)
    print("--- data_generator.py verified successfully! ---")
