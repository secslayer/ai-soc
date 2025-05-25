#!/usr/bin/env python3
"""
Reinforce Alert Data Imputation

This script loads an input CSV file containing alert data,
applies KNN and Iterative Imputation on numerical columns,
fills missing categorical values with the most frequent value,
and saves the reinforced dataset to an output CSV file.

Usage:
    python reinforce_imputation.py --input <input_file.csv> --output <output_file.csv>
"""

import argparse
import pandas as pd
import numpy as np
from sklearn.impute import KNNImputer
from sklearn.experimental import enable_iterative_imputer  # noqa: F401
from sklearn.impute import IterativeImputer

def parse_args():
    parser = argparse.ArgumentParser(
        description="Reinforce alert data imputation using KNN and Iterative Imputer."
    )
    parser.add_argument('--input', required=True, help='Path to the input CSV file')
    parser.add_argument('--output', required=True, help='Path to save the output CSV file')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Load dataset from input file
    try:
        df = pd.read_csv(args.input)
        print(f"Loaded data from '{args.input}' with {df.shape[0]} rows and {df.shape[1]} columns.")
    except Exception as e:
        print(f"Error reading input file '{args.input}': {e}")
        return

    # Identify numerical and categorical columns
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    cat_cols = df.select_dtypes(include=['object']).columns.tolist()

    # Drop numerical columns that are entirely NaN
    df.dropna(axis=1, how='all', inplace=True)

    # Re-check numerical columns after dropping NaNs
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    if len(num_cols) > 0:
        # Convert numerical columns to float64 for consistency
        df[num_cols] = df[num_cols].astype(float)

        # Apply KNN Imputer to fill missing numerical values
        knn_imputer = KNNImputer(n_neighbors=5)
        df[num_cols] = knn_imputer.fit_transform(df[num_cols])

        # Apply Iterative Imputer for further refinement of missing values
        iter_imputer = IterativeImputer()
        df[num_cols] = iter_imputer.fit_transform(df[num_cols])
    
    # Fill missing values in categorical columns with the most frequent (mode)
    for col in cat_cols:
        if df[col].isnull().sum() > 0:
            df[col].fillna(df[col].mode()[0], inplace=True)

    # Save the reinforced dataset to the output file
    try:
        df.to_csv(args.output, index=False)
        print(f"Reinforced data imputation complete. Saved as '{args.output}'.")
    except Exception as e:
        print(f"Error saving output file '{args.output}': {e}")

if __name__ == "__main__":
    main()
