#!/usr/bin/env python3
"""
=== Prediction Phase for MITRE Techniques ===

This script performs the following steps:
1. Loads a saved model, target encoder, and optionally feature encoders.
2. Defines the list of training features (42 features) used during training.
3. Loads the input CSV file (preprocessed reinforced alert data).
4. Processes the 'timestamp' column (if present) to extract an 'hour' feature,
   then drops the original 'timestamp'.
5. Drops the target column ('mitretechniques') if it exists.
6. Transforms categorical features using saved feature encoders (or fits new ones if not available).
7. Reindexes the DataFrame to exactly match the training features (missing features filled with 0).
8. Converts all data to 32-bit floats.
9. Uses the loaded model and target encoder to make predictions.
10. Appends the predicted MITRE technique (human-readable) as a new column and saves the result.

Usage:
    python mitre_prediction.py --input <input_csv> --output <output_csv> --model <model_pkl> --label <label_pkl> [--feature_encoders <feature_encoders_pkl>]
"""

import argparse
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder

def parse_args():
    parser = argparse.ArgumentParser(description="MITRE Prediction Phase using CSV files")
    parser.add_argument("--input", required=True,
                        help="Path to the input CSV file (e.g., reinforced_alert_data.csv)")
    parser.add_argument("--output", required=True,
                        help="Path to save the updated CSV file with predictions")
    parser.add_argument("--model", required=True,
                        help="Path to the saved MITRE model pickle file (e.g., mitre_model.pkl)")
    parser.add_argument("--label", required=True,
                        help="Path to the saved LabelEncoder pickle file (e.g., mitre_label.pkl)")
    parser.add_argument("--feature_encoders", required=False,
                        help="Path to the saved feature encoders pickle file (e.g., feature_encoders.pkl)")
    return parser.parse_args()

def main():
    args = parse_args()
    
    print("=== Prediction Phase for MITRE Techniques ===")
    
    # -------------------------------
    # 1. Load the Saved Model and Target Encoder
    # -------------------------------
    try:
        model = joblib.load(args.model)
        target_le = joblib.load(args.label)
        print("Loaded model and target encoder.")
    except Exception as e:
        print("Error loading model or label encoder:", e)
        return

    try:
        if args.feature_encoders:
            feature_encoders = joblib.load(args.feature_encoders)
            print("Loaded feature encoders.")
        else:
            print("No feature encoders file provided; proceeding without saved encoders.")
            feature_encoders = {}
    except Exception as e:
        print("Error loading feature_encoders.pkl:", e)
        feature_encoders = {}

    # -------------------------------
    # 2. Define the List of Training Feature Names (42 features)
    # -------------------------------
    training_features = [
        'incidentid', 'alertid', 'detectorid', 'alerttitle', 'category', 
        'incidentgrade', 'actiongrouped', 'actiongranular', 'entitytype', 
        'evidencerole', 'deviceid', 'sha256', 'ipaddress', 'url', 
        'accountsid', 'accountupn', 'accountobjectid', 'accountname', 'devicename', 
        'networkmessageid', 'emailclusterid', 'registrykey', 'registryvaluename', 
        'registryvaluedata', 'applicationid', 'applicationname', 'oauthapplicationid', 
        'threatfamily', 'filename', 'folderpath', 'resourceidname', 'resourcetype', 
        'roles', 'osfamily', 'osversion', 'antispamdirection', 'suspicionlevel', 
        'lastverdict', 'countrycode', 'state', 'city', 'hour'
    ]
    print("Training features used (expected):", len(training_features))  # Should print 42

    # -------------------------------
    # 3. Load the CSV File
    # -------------------------------
    try:
        df_sample = pd.read_csv(args.input)
    except Exception as e:
        print(f"Error reading input file {args.input}: {e}")
        return

    # Standardize column names: strip and convert to lowercase
    df_sample.columns = df_sample.columns.str.strip().str.lower()
    print("Loaded sample data with shape:", df_sample.shape)
    print("Columns in sample data:", df_sample.columns.tolist())

    # -------------------------------
    # 4. Preprocess the Sample Data
    # -------------------------------
    # Process the 'timestamp' column: convert to datetime, extract 'hour', then drop 'timestamp'
    if 'timestamp' in df_sample.columns:
        df_sample['timestamp'] = pd.to_datetime(df_sample['timestamp'], errors='coerce')
        df_sample['hour'] = df_sample['timestamp'].dt.hour
        df_sample.drop(columns=['timestamp'], inplace=True)
        print("Processed 'timestamp'; 'hour' feature created.")
    else:
        print("Warning: 'timestamp' column not found in sample data.")

    # Drop the target column (if present) because we want to predict it.
    if 'mitretechniques' in df_sample.columns:
        df_sample = df_sample.drop(columns=['mitretechniques'])
    
    # -------------------------------
    # 5. Transform Categorical Features Using Saved Encoders
    # -------------------------------
    for col in training_features:
        if col in df_sample.columns:
            if df_sample[col].dtype == 'object':
                if col in feature_encoders:
                    try:
                        df_sample[col] = feature_encoders[col].transform(df_sample[col].astype(str))
                        print(f"Transformed column '{col}' using saved encoder.")
                    except Exception as e:
                        print(f"Error transforming column '{col}' using saved encoder: {e}")
                else:
                    print(f"Warning: No saved encoder for '{col}'. Fitting new encoder.")
                    le = LabelEncoder()
                    df_sample[col] = le.fit_transform(df_sample[col].astype(str))
            else:
                print(f"Column '{col}' is numeric.")
        else:
            print(f"Column '{col}' not found in sample data; will be added as default 0.")

    # -------------------------------
    # 6. Align Sample Data to Training Features
    # -------------------------------
    # Ensure all training features are present (missing ones filled with 0)
    df_sample = df_sample.reindex(columns=training_features, fill_value=0)
    print("Sample data after reindexing to training features:")
    print(df_sample.head())
    print("Shape after reindexing:", df_sample.shape)

    # -------------------------------
    # 7. Convert Data to 32-bit Floats
    # -------------------------------
    try:
        df_sample = df_sample.astype(np.float32)
        print("Converted sample data to np.float32.")
    except Exception as e:
        print("Error converting sample data to np.float32:", e)
        for col in df_sample.columns:
            try:
                df_sample[col] = df_sample[col].astype(np.float32)
            except Exception as e_col:
                print(f"Column '{col}' could not be converted: {e_col}")

    # -------------------------------
    # 8. Predict Using the Loaded Model and Target Encoder
    # -------------------------------
    pred_numeric = model.predict(df_sample)
    pred_mitre = target_le.inverse_transform(pred_numeric)
    print("\nPredicted MITRE Technique(s) for the sample:")
    print(pred_mitre)

    # -------------------------------
    # 9. Append Predicted Value to Original Data and Save to CSV
    # -------------------------------
    try:
        df_original = pd.read_csv(args.input)
        df_original.columns = df_original.columns.str.strip().str.lower()
    except Exception as e:
        print(f"Error reloading original input file {args.input}: {e}")
        return

    # Append the predicted MITRE technique as a new column
    df_original['predicted_mitre'] = pred_mitre
    try:
        df_original.to_csv(args.output, index=False)
        print(f"\nPredictions saved to {args.output}")
    except Exception as e:
        print(f"Error saving output file {args.output}: {e}")

if __name__ == "__main__":
    main()
