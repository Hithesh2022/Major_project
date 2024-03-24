import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler  # Assuming standard scaling was used
import warnings

warnings.filterwarnings("ignore")

# Load the trained model (replace with your actual model filename)
model = joblib.load('newtrainedModel.joblib')

# Define sample data (replace with your actual data)
sample_data ={
    'Duration': [20],
    'Wrong Fragment': [1],
    'Hot': [1],
    'Logged In': [0],
    'Num Compromised': [0],
    'Root Shell': [0],
    'Num Root': [0],
    'Num File Creations': [50],
    'Num Access Files': [10],
    'Same Service Rate': [0.9],
    'Srv Diff Host Rate': [0.1],
    'Dst Host Count': [1000000],
    'Dst Host Same Src Port Rate': [0.8],
    'Dst Host Rerror Rate': [0.05],
    'Dst Host Serror Rate': [0.1],
    'Protocol Type_icmp': [0],
    'Protocol Type_tcp': [1],
    'Protocol Type_udp': [0],
    'Service_domain': [0],
    'Service_http': [1],
    'Service_telnet': [0],
    'Flag_OTH': [1],
    'Flag_REJ': [1],
    'Flag_RSTO': [1],
    'Flag_RSTOS0': [1],
    'Flag_RSTR': [1],
    'Flag_S0': [1],
    'Flag_S1': [0],
    'Flag_SF': [1]
}







# Create DataFrame from sample data
sample_df = pd.DataFrame(sample_data)

# Handle missing values (if any) based on your training data
# ... (e.g., fill with mean/median for numerical features, special category for categorical)

# One-hot encode categorical features (assuming this was done during training)
sample_df_encoded = pd.get_dummies(sample_df)

# Apply feature scaling if used during training (assuming StandardScaler)
scaler = StandardScaler()  # Assuming the same scaler object used for training
sample_df_scaled = scaler.fit_transform(sample_df_encoded)

# Assuming features were arranged in a specific order during training
# Rearrange features in sample_df_scaled to match that order (if necessary)
# ...

# Make predictions using the loaded model
predictions = model.predict(sample_df_scaled)
print(predictions)

# Decode predictions based on your class encoding scheme (e.g., dictionary mapping numerical labels to attack types)
class_names = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
predicted_class = class_names[predictions[0]]

# Print the predicted attack type
print("Predicted Attack Type:", predicted_class)

# Interpretation:
# Based on the sample data with hot connection, high file creations, high destination host