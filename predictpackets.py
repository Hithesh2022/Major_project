import pandas as pd
import pickle
# from sklearn.preprocessing import StandardScaler  # Assuming standard scaling was used
# import warnings
from sklearn.preprocessing import StandardScaler
def predict_attack():
    with open('voting_classifier.pkl', 'rb') as f:
        model = pickle.load(f)


    sample_data ={
        'duration': '00:00:05',  # Short duration
        'wrong_fragment': 0,  # No wrong fragment
        'hot': '0x00',  # No hot indicators
        'logged_in': 0,  # Not logged in
        'num_compromised': '0',  # No compromised accounts
        'root_shell': '0',  # No root shell access
        'num_root': '0',  # No root accesses
        'num_file_creations': '0',  # No file creations
        'num_access_files': '0',  # No access files
        'same_srv_rate': '1',  # High same service rate
        'srv_diff_host_rate': '0',  # No difference in host rate
        'dst_host_count': '1',  # Low destination host count
        'Dst Host Same Src Port Rate': '1',  # Same source port rate
        'Dst Host Rerror Rate': '0',  # No RST error rate
        'Dst Host Serror Rate': '0',  # No SYN error rate
        'Protocol Type ICMP': '0',  # Not ICMP
        'Protocol Type TCP': '1',  # TCP protocol
        'Protocol Type UDP': '0',  # Not UDP
        'Service Domain': '0',  # Not domain service
        'Service HTTP': '0',  # Not HTTP service
        'Service Telnet': '0',  # Not Telnet service
        'Flag OTH': '0',  # No other flag
        'Flag REJ': '0',  # No reject flag
        'Flag RSTO': '0',  # No RSTO flag
        'Flag RSTOS0': '0',  # No RSTOS0 flag
        'Flag RSTR': '0',  # No RSTR flag
        'Flag S0': '0',  # No S0 flag
        'Flag S1': '0',  # No S1 flag
        'Flag SF': '0'  # SF flag indicating a potential DoS attack
    }

    sample_df =pd.DataFrame([sample_data])

    sample_df_encoded = pd.get_dummies(sample_df)

    scalar=StandardScaler()
    sample_df_scaled = scalar.fit_transform(sample_df_encoded)

    # Make predictions using the loaded model
    predictions = model.predict(sample_df_encoded)

    class_encoding = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
    predicted_class = class_encoding[predictions[0]]


    # Print the predicted attack type
    print(sample_df)
    print(sample_df_encoded)
    # print(sample_df_scaled)
    print(predictions)
    print("Predicted Attack Type:", predicted_class)
    with open('predicted_attack.txt', 'a') as file:
        file.write(predicted_class)

predict_attack()