import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text
import sys
import os

def verify_model():
    if not os.path.isfile('training_data.csv'):
        print("[-] Error: training_data.csv not found. Please complete data collection first.")
        sys.exit(1)

    try:
        print("[*] Loading training_data.csv...")
        df = pd.read_csv('training_data.csv')
        
        # The 6 comprehensive features matching your collector and agent
        features = ['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio']
        X = df[features].values
        y = df['label']
        
        # Using the exact same model parameters as agent.py
        clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
        clf.fit(X, y)
        
        print(f"\n[+] Model trained successfully on {len(df)} records.")
        
        # Calculate dataset balance
        normal_count = len(df[df['label'] == 0])
        attack_count = len(df[df['label'] == 1])
        print(f"[*] Dataset Balance: {normal_count} Normal | {attack_count} Attack")
        
        print("\n[+] --- DECISION TREE LOGIC RULES ---")
        # This exports the actual mathematical thresholds the agent will enforce
        feature_names = ['Packets/Sec (PPS)', 'Bytes/Sec (BPS)', 'Avg Size', 'TCP Ratio', 'UDP Ratio', 'ICMP Ratio']
        tree_rules = export_text(clf, feature_names=feature_names)
        print(tree_rules)
        
    except Exception as e:
        print(f"[-] Evaluation Error: {e}")

if __name__ == "__main__":
    verify_model()