import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical
import joblib  # To save the Random Forest model
from tensorflow.keras.models import load_model  # To save and load Keras models

# 1. Load the dataset
data_path = "/Users/avinash/Documents/capstone Project/datasets/clean/all_data.feather"  # Replace with actual file path
df = pd.read_feather(data_path)

# 2. Encode the multiclass `Label` column into integers
label_mapping = {label: idx for idx, label in enumerate(df['Label'].unique())}  # Map each unique label to an integer
df['Label_Encoded'] = df['Label'].map(label_mapping)  # Add encoded labels to the DataFrame

# Print the label encoding for reference
print("Label Encoding Mapping:")
for label, encoded_value in label_mapping.items():
    print(f"Attack Type: {label}, Encoded Value: {encoded_value}")

# 3. Prepare the feature matrix (X) and target vector (y)
X = df.drop(columns=['Label', 'Label_Encoded'], errors='ignore')  # Drop unused columns
y = df['Label_Encoded']  # Target vector (encoded multiclass labels)

# 4. Normalize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler
scaler_path = "/Users/avinash/Documents/capstone Project/models/scaler.joblib"
joblib.dump(scaler, scaler_path)
print(f"Scaler saved to: {scaler_path}")


# 5. Train-Test Split for Multiclass Classification
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Check the class distribution in the training set
unique, counts = np.unique(y_train, return_counts=True)
print("\nClass distribution in y_train (Multiclass Labels):")
print(dict(zip(unique, counts)))

# 6. Train a Random Forest for Multiclass Classification
print("\nTraining Random Forest for Multiclass Attack Classification...")
rf_clf = RandomForestClassifier(n_estimators=100, random_state=42, verbose=1,
                                class_weight='balanced')  # Adjust `n_estimators` as needed
rf_clf.fit(X_train, y_train)

# Save the trained Random Forest model
rf_model_path = "/Users/avinash/Documents/capstone Project/models/random_forest_multiclass.joblib"
joblib.dump(rf_clf, rf_model_path)
print(f"Random Forest model saved to: {rf_model_path}")

# 7. Evaluate the Random Forest model
y_pred_rf = rf_clf.predict(X_test)
print("\nRandom Forest Classification Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_rf))
print("Classification Report:\n", classification_report(y_test, y_pred_rf))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

# 8. Train a Neural Network for Multiclass Classification
print("\nTraining Neural Network for Multiclass Attack Classification...")

# One-hot encode the target labels for the neural network
y_train_encoded = to_categorical(y_train)  # One-hot encoding for training labels
y_test_encoded = to_categorical(y_test)  # One-hot encoding for testing labels

# Build the neural network model
model = Sequential([
    Dense(128, activation='relu', input_shape=(X_train.shape[1],)),  # Input layer
    Dropout(0.3),  # Dropout for regularization
    Dense(64, activation='relu'),  # Hidden layer
    Dropout(0.3),  # Dropout for regularization
    Dense(len(y_train_encoded[0]), activation='softmax')  # Output layer (one node per class)
])

# Compile the model
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Train the model
history = model.fit(X_train, y_train_encoded, epochs=30, batch_size=32, validation_split=0.2, verbose=2)

# Save the trained neural network model
nn_model_path = "/Users/avinash/Documents/capstone Project/models/neural_network_multiclass.h5"
model.save(nn_model_path)
print(f"Neural Network model saved to: {nn_model_path}")

# 9. Evaluate the Neural Network
y_pred_nn = model.predict(X_test)
y_pred_nn_classes = np.argmax(y_pred_nn, axis=1)  # Convert one-hot predictions to class labels

print("\nNeural Network Classification Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_nn_classes))
print("Classification Report:\n", classification_report(y_test, y_pred_nn_classes))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_nn_classes))

# Done!
print("\nTraining and evaluation complete. Models are saved.")
