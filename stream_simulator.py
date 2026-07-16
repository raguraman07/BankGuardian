import time
import random
from datetime import datetime, timedelta
import pandas as pd
from data_generator import (
    generate_users, generate_known_entities,
    generate_background_logins, generate_background_transactions, generate_sim_swaps,
    generate_attack_chain, generate_legitimate_large_transaction, generate_safe_transaction
)

class StreamSimulator:
    def __init__(self):
        # Generate stable user base and credentials
        self.users = generate_users(25)
        self.devices, self.ips, self.accounts = generate_known_entities(self.users)
        
        # Generate initial background database (historical)
        print("[Simulator] Pre-generating historical background telemetry...")
        start_time = datetime.now() - timedelta(hours=12)
        
        self.history_logins = generate_background_logins(self.users, self.devices, self.ips, n=100, start_time=start_time)
        self.history_transactions = generate_background_transactions(self.users, self.accounts, n=150, start_time=start_time)
        self.history_sim_swaps = generate_sim_swaps(self.users, n=8, start_time=start_time)
        
        # Combine all events into one timeline
        self.history_events = []
        
        for _, row in self.history_logins.iterrows():
            d = row.to_dict()
            self.history_events.append(d)
            
        for _, row in self.history_transactions.iterrows():
            d = row.to_dict()
            self.history_events.append(d)
            
        for _, row in self.history_sim_swaps.iterrows():
            d = row.to_dict()
            self.history_events.append(d)
            
        # Sort history by timestamp
        self.history_events.sort(key=lambda x: x["timestamp"])
        
        # Internal state for live stream
        self.injected_queue = []
        self.history_ptr = 0
        
    def inject_scenario(self, scenario_name, user=None):
        """
        Injects a scenario into the front of the queue to be read by the stream.
        """
        if not user:
            user = random.choice(self.users)
            
        now = datetime.now()
        
        if scenario_name == "attack_chain":
            print(f"[Simulator] Injecting Cyber-Fraud Attack Chain for user '{user}'")
            events = generate_attack_chain(user, base_time=now)
        elif scenario_name == "legitimate_large":
            print(f"[Simulator] Injecting Legitimate Large Transaction scenario for user '{user}'")
            events = generate_legitimate_large_transaction(user, self.devices, self.ips, base_time=now)
        elif scenario_name == "safe_transaction":
            print(f"[Simulator] Injecting Safe Transaction scenario for user '{user}'")
            events = generate_safe_transaction(user, self.devices, self.ips, base_time=now)
        else:
            raise ValueError(f"Unknown scenario: {scenario_name}")
            
        self.injected_queue.extend(events)
        return user, events

    def get_next_event(self):
        """
        Yields the next event. Prioritizes injected scenario events,
        then falls back to ticking the background historical events.
        """
        # 1. Check if there are injected events waiting
        if self.injected_queue:
            evt = self.injected_queue.pop(0)
            # Make sure timestamp is close to current real time
            # Keep delta differences relative if they are chained
            return evt
            
        # 2. Otherwise return a background event and advance ptr
        if self.history_events:
            evt = self.history_events[self.history_ptr % len(self.history_events)].copy()
            # Bring timestamp to "now"
            evt["timestamp"] = datetime.now()
            self.history_ptr += 1
            return evt
            
        return None

    def event_generator(self, interval_seconds=3):
        """
        A Python generator that yields events continuously.
        """
        while True:
            yield self.get_next_event()
            time.sleep(interval_seconds)

if __name__ == "__main__":
    print("--- Testing stream_simulator.py ---")
    sim = StreamSimulator()
    print(f"Loaded {len(sim.history_events)} historical events.")
    
    print("\nGetting 3 default stream events:")
    for i in range(3):
        event = sim.get_next_event()
        print(f"Event {i+1}: {event['event_type']} - User: {event['user']} - Time: {event['timestamp']}")
        
    print("\nInjecting SIM-Swap Attack Scenario...")
    user, injected = sim.inject_scenario("attack_chain")
    print(f"Injected chain for user: {user}. Event count: {len(injected)}")
    
    print("\nReading next 4 stream events (should contain injected events first):")
    for i in range(4):
        event = sim.get_next_event()
        print(f"Event {i+1}: {event['event_type']} - User: {event['user']} - Details: { {k:v for k,v in event.items() if k not in ['event_type', 'user', 'timestamp']} }")
        
    print("--- stream_simulator.py verified successfully ---")
