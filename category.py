#!/usr/bin/env python3
"""
=== Prediction Phase for MITRE Techniques ===

This script loads preprocessed prediction data from a CSV file,
processes the 'timestamp' column, aligns the data to expected training features,
converts categorical columns to numeric codes,
loads a saved model and LabelEncoder (using joblib),
makes predictions, converts numeric predictions back to human-readable category labels,
adds the predicted categories as a new column, and saves the updated data
to a specified output CSV file.

Usage:
    python prediction_phase.py --input <input_csv> --output <output_csv>
"""

import argparse
import pandas as pd
import joblib

def parse_args():
    parser = argparse.ArgumentParser(description="Prediction Phase for MITRE Techniques")
    parser.add_argument("--input", required=True, help="Path to the preprocessed prediction CSV file")
    parser.add_argument("--output", required=True, help="Path to save the updated CSV file with predictions")
    return parser.parse_args()

def main():
    args = parse_args()
    
    print("=== Prediction Phase for MITRE Techniques ===")
    
    # Load the preprocessed prediction data
    try:
        df_preprocessed = pd.read_csv(args.input)
    except Exception as e:
        print(f"Error loading input file {args.input}: {e}")
        return
    
    # Normalize column names: strip spaces and convert to lowercase
    df_preprocessed.columns = df_preprocessed.columns.str.strip().str.lower()
    print("Prediction data columns:", list(df_preprocessed.columns))
    
    # Process the 'timestamp' column if present
    if 'timestamp' in df_preprocessed.columns:
        print("Processing 'timestamp' in prediction data...")
        df_preprocessed['timestamp'] = pd.to_datetime(df_preprocessed['timestamp'], errors='coerce')
        df_preprocessed['hour'] = df_preprocessed['timestamp'].dt.hour
        df_preprocessed.drop(columns=['timestamp'], inplace=True)
        print("'hour' feature created.")
    else:
        print("Warning: 'timestamp' column not found in prediction data.")
    
    # Align prediction data to training features (assumed from training phase)
    available_cols = ['incidentid', 'alertid', 'detectorid', 'alerttitle', 'deviceid',
                      'ipaddress', 'accountsid', 'accountupn', 'accountobjectid',
                      'accountname', 'devicename', 'applicationid', 'applicationname',
                      'filename', 'folderpath', 'osfamily', 'osversion']
    if 'hour' in df_preprocessed.columns and 'hour' not in available_cols:
        available_cols.append('hour')
    
    # Add any missing columns with NA values
    for col in available_cols:
        if col not in df_preprocessed.columns:
            df_preprocessed[col] = pd.NA
            print(f"Added missing column: {col}")
    
    # Select and reorder columns
    df_preprocessed = df_preprocessed[[col for col in available_cols if col in df_preprocessed.columns]]
    print("Final prediction data columns:", list(df_preprocessed.columns))
    
    # Convert object (categorical) columns to numeric codes as done during training
    for col in df_preprocessed.select_dtypes(include='object').columns:
        df_preprocessed[col] = df_preprocessed[col].astype('category').cat.codes

    # Load the saved model and LabelEncoder
    print("Loading saved model and LabelEncoder for prediction...")
    try:
        model = joblib.load('./category_model.pkl')
        le = joblib.load('./category_label.pkl')
    except Exception as e:
        print("Error loading model or LabelEncoder:", e)
        return

    # Make predictions
    print("Making predictions...")
    predictions_numeric = model.predict(df_preprocessed)
    print("Numeric predictions:", predictions_numeric)
    
    # Convert numeric predictions back to original human-readable category labels
    predicted_categories = le.inverse_transform(predictions_numeric)
    print("Predicted Categories:", predicted_categories)
    
    # Add predicted categories as a new column
    df_preprocessed['category'] = predicted_categories
    
    # Save the updated DataFrame back to CSV using the provided output filename
    try:
        df_preprocessed.to_csv(args.output, index=False)
        print(f"Updated CSV file saved as {args.output}")
    except Exception as e:
        print("Error saving updated CSV file:", e)

if __name__ == "__main__":
    main()
