#!/usr/bin/env python3
"""
Clean and Standardize Alert Data CSV

This script loads an input CSV file containing alert data,
renames columns based on a defined mapping, retains only the required columns,
removes columns that are entirely NaN, and saves the cleaned data
to an output CSV file.

Usage:
    python clean_alert_data.py --input <input_file.csv> --output <output_file.csv>
"""

import argparse
import pandas as pd

def parse_args():
    parser = argparse.ArgumentParser(description="Clean and standardize alert data CSV file.")
    parser.add_argument('--input', required=True, help='Path to the input CSV file')
    parser.add_argument('--output', required=True, help='Path to save the cleaned CSV file')
    return parser.parse_args()

def main():
    args = parse_args()

    # Load dataset from the input file
    try:
        df = pd.read_csv(args.input)
        print(f"Loaded data from {args.input} with {df.shape[0]} rows and {df.shape[1]} columns.")
    except Exception as e:
        print(f"Error reading input file {args.input}: {e}")
        return

    # Define required columns
    required_columns = [
        'Timestamp', 'MitreTechniques', 'DeviceId', 'DeviceName', 'IpAddress', 'AccountSid', 'AccountUpn', 
        'AccountObjectId', 'AccountName', 'ApplicationId', 'ApplicationName', 'OSFamily', 
        'OSVersion', 'FileName', 'FolderPath', 'Category', 'AlertTitle', 'DetectorId', 
        'AlertId', 'IncidentId', 'EntityType', 'Sha256'
    ]

    # Define alternative names mapping for columns (keys are current names, values are desired names)
    column_mapping = {
        'timestamp': 'Timestamp',
        'mitretechniques': 'MitreTechniques',
        'deviceid': 'DeviceId',
        'devicename': 'DeviceName',
        'ipaddress': 'IpAddress',
        'accountsid': 'AccountSid',
        'accountupn': 'AccountUpn',
        'accountobjectid': 'AccountObjectId',
        'accountname': 'AccountName',
        'applicationid': 'ApplicationId',
        'applicationname': 'ApplicationName',
        'osfamily': 'OSFamily',
        'osversion': 'OSVersion',
        'filename': 'FileName',
        'folderpath': 'FolderPath',
        'eventtype': 'Category',    # alternative for Category
        'channel': 'AlertTitle',    # alternative for AlertTitle
        'source': 'DetectorId',     # alternative for DetectorId
        'guid': 'AlertId',          # alternative for AlertId
        'datatype': 'IncidentId',   # alternative for IncidentId
        'entitytype': 'EntityType', # ensure EntityType exists
        'sha256': 'Sha256'
    }

    # Rename columns in the DataFrame if they exist
    df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)

    # Retain only required columns that exist in the DataFrame
    df = df[[col for col in required_columns if col in df.columns]]

    # Drop any columns that are entirely NaN
    df.dropna(axis=1, how='all', inplace=True)

    # Save the cleaned data to the specified output file
    try:
        df.to_csv(args.output, index=False)
        print(f"Data cleaning complete. Cleaned data saved to '{args.output}'.")
    except Exception as e:
        print(f"Error saving output file {args.output}: {e}")

if __name__ == "__main__":
    main()
