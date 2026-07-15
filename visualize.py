import pandas as pd
from sklearn.tree import DecisionTreeClassifier, plot_tree
import matplotlib.pyplot as plt

# 1. Load the newly generated dataset
data_file = 'training_data.csv'
print(f"Loading dataset from {data_file}...")
df = pd.read_csv(data_file)

# 2. Define features and target labels (matching your agent.py)
features = ['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio']
X = df[features]
y = df['label']

# 3. Initialize and fit the exact same model used in your SDN agent
clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
clf.fit(X.values, y)

# 4. Configure the visual plot parameters
plt.figure(figsize=(20, 10))
plot_tree(
    clf, 
    feature_names=features, 
    class_names=['Normal (0)', 'Attack (1)'], 
    filled=True, 
    rounded=True, 
    fontsize=10,
    proportion=False
)

# 5. Render and save the image
plt.title("SDN Anomaly Detection Decision Tree (Cryptographic NFC Payload Rules)", fontsize=16)
plt.tight_layout()

output_image = "decision_tree_visual.png"
plt.savefig(output_image, dpi=300)
print(f"Decision tree visualization saved successfully as '{output_image}'.")

# Show the plot window interactively
plt.show()