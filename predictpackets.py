import pandas as pd
import pickle
# from sklearn.preprocessing import StandardScaler  # Assuming standard scaling was used
# import warnings
from sklearn.preprocessing import StandardScaler
def predict_attack():
    with open('voting_classifier.pkl', 'rb') as f:
        model = pickle.load(f)


    with open('extracted_data.txt', 'r') as file:
    # Read the first line
     first_line = file.readline()

# Convert the string to a dictionary using eval()
    sample_data = eval(first_line)
    print(sample_data)
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
    with open('predicted_attack.txt', 'w') as file:
        file.write(predicted_class)

predict_attack()