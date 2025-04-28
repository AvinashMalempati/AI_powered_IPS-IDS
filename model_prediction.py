import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model


def load_models(rf_model_path, nn_model_path):
    """
    Load the trained Random Forest and Neural Network models.
    :param rf_model_path: Path to the saved Random Forest model file.
    :param nn_model_path: Path to the saved Neural Network model file.
    :return: Loaded RF and NN models.
    """
    try:
        rf_model = joblib.load(rf_model_path)
        print(f"Random Forest model loaded successfully from: {rf_model_path}")

        nn_model = load_model(nn_model_path)
        print(f"Neural Network model loaded successfully from: {nn_model_path}")

        return rf_model, nn_model
    except Exception as e:
        print("Error loading models:")
        print(str(e))
        return None, None


def preprocess_data(file_path, scaler_path):
    """
    Load and preprocess features for prediction, using the saved scaler.
    :param file_path: Path to the CSV file with extracted features.
    :param scaler_path: Path to the saved scaler.
    :return: Preprocessed feature data (numpy array) and original DataFrame.
    """
    try:
        # Load the feature data
        df = pd.read_csv(file_path)
        print(f"CSV file loaded successfully from: {file_path}")

        # Replace any `inf` or `-inf` values with 0
        df.replace([np.inf, -np.inf], 0, inplace=True)

        # Handle missing values
        if df.isnull().values.any():
            df.fillna(0, inplace=True)

        # Load the saved scaler
        scaler = joblib.load(scaler_path)
        print(f"Scaler loaded successfully from: {scaler_path}")

        model_data = df.drop(['src_ip', 'dst_ip', 'protocol'], axis=1, errors='ignore')
        # Transform the features using the loaded scaler
        features_transformed = scaler.transform(model_data)

        return features_transformed, df
    except Exception as e:
        print("Error loading or preprocessing data:")
        print(str(e))
        return None, None


def hybrid_prediction(rf_model, nn_model, features):
    """
    Perform predictions using both Random Forest and Neural Network models
    and combine their outputs using a hybrid approach.
    :param rf_model: Trained Random Forest model.
    :param nn_model: Trained Neural Network model.
    :param features: Input features for prediction.
    :return: Final hybrid predictions as a numpy array.
    """
    try:
        # Predict using the Random Forest model
        rf_predictions = rf_model.predict(features)
        print("Random Forest predictions completed.")

        # Predict using the Neural Network model
        nn_probabilities = nn_model.predict(features)
        nn_predictions = np.argmax(nn_probabilities, axis=1)
        print("Neural Network predictions completed.")

        # Combine predictions (example: simple majority voting)
        final_predictions = []
        for rf_pred, nn_pred in zip(rf_predictions, nn_predictions):
            if rf_pred == nn_pred:  # If both models agree, take that prediction
                final_predictions.append(rf_pred)
            else:
                # If there's disagreement, choose NN's prediction (can be adjusted)
                final_predictions.append(nn_pred)

        return np.array(final_predictions)
    except Exception as e:
        print("Error during prediction:")
        print(str(e))
        return None


def main():
    # Paths for the models and scaler
    rf_model_path = "models/random_forest_multiclass.joblib"
    nn_model_path = "models/neural_network_multiclass.h5"
    scaler_path = "models/scaler.joblib"

    # Path to the CSV file with extracted features
    feature_csv_path = "extracted_features.csv"

    # Output path for the final predictions
    prediction_output_path = "final_hybrid_predictions.csv"

    # Step 1: Load trained models
    rf_model, nn_model = load_models(rf_model_path, nn_model_path)
    if rf_model is None or nn_model is None:
        print("Failed to load the models. Exiting...")
        return

    # Step 2: Load and preprocess feature data
    features, original_data = preprocess_data(feature_csv_path, scaler_path)
    print(features)
    if features is None:
        print("Failed to preprocess feature data. Exiting...")
        return

    # Step 3: Perform hybrid prediction
    final_predictions = hybrid_prediction(rf_model, nn_model, features)
    if final_predictions is None:
        print("Prediction failed. Exiting...")
        return

    # Step 4: Save predictions to a CSV file
    try:
        prediction_df = original_data.copy()
        prediction_df["Hybrid_Prediction"] = final_predictions  # Add predictions to the original data
        prediction_df.to_csv(prediction_output_path, index=False)
        print(f"Hybrid predictions saved successfully to: {prediction_output_path}")
    except Exception as e:
        print("Error saving predictions to CSV:")
        print(str(e))


if __name__ == "__main__":
    main()
