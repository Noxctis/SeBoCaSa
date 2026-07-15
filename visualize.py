import pandas as pd
from sklearn.tree import DecisionTreeClassifier, plot_tree, export_text
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt

# 1. Load the dataset
data_file = 'training_data.csv'
print(f"Loading dataset from {data_file}...")
df = pd.read_csv(data_file)

features = ['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio']
X = df[features]
y = df['label']

# 2. Initialize and fit the model
clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
clf.fit(X.values, y)

# 3. Generate predictions for metric evaluation
y_pred = clf.predict(X.values)

# 4. Generate Visual Tree
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
plt.title("SDN Anomaly Detection Decision Tree (Cryptographic NFC Payload Rules)", fontsize=16)
plt.tight_layout()

output_image = "decision_tree_visual.png"
plt.savefig(output_image, dpi=300)
print(f"[*] Visual tree saved as '{output_image}'.")
plt.close()

# 5. Generate Formal Textual Documentation Report
report_file = "model_documentation_report.txt"
with open(report_file, "w") as f:
    f.write("====================================================\n")
    f.write("      DECISION TREE MODEL EVALUATION REPORT         \n")
    f.write("====================================================\n\n")
    
    f.write(f"Total Flow Records Analyzed: {len(df)}\n")
    f.write(f"Overall Accuracy: {accuracy_score(y, y_pred):.4f}\n\n")
    
    f.write("--- CONFUSION MATRIX ---\n")
    f.write("[True Negatives   False Positives]\n")
    f.write("[False Negatives  True Positives ]\n\n")
    f.write(f"{confusion_matrix(y, y_pred)}\n\n")
    
    f.write("--- CLASSIFICATION REPORT ---\n")
    f.write(f"{classification_report(y, y_pred, target_names=['Normal (0)', 'Attack (1)'])}\n\n")
    
    f.write("--- FEATURE IMPORTANCES (Weight of each metric) ---\n")
    importances = clf.feature_importances_
    for feat, imp in zip(features, importances):
        f.write(f"{feat.ljust(15)}: {imp:.4f}\n")
        
    f.write("\n--- EXTRACTED TEXTUAL RULES (For System Implementation) ---\n")
    f.write(export_text(clf, feature_names=features))

print(f"[*] Statistical evaluation saved as '{report_file}'.")