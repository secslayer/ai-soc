#!/usr/bin/env python3

import pandas as pd
import numpy as np
import re
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description="Transform generated log CSV to a dataset compatible with the Microsoft Security Incident Prediction Kaggle dataset"
    )
    parser.add_argument('--input', type=str, required=True, help='Path to the generated log CSV file')
    parser.add_argument('--output', type=str, required=True, help='Path to the transformed output CSV file')
    return parser.parse_args()

def clean_value(val):
    """
    Intense cleaning of a field value:
      - Convert to string (if not NaN).
      - Strip leading/trailing whitespace.
      - Remove unwanted characters like curly braces, square brackets.
      - Convert common "not available" values to empty string.
    """
    if pd.isna(val):
        return ""
    # Convert to string and strip whitespace
    s = str(val).strip()
    # Remove unwanted characters
    s = re.sub(r'[\{\}\[\]]', '', s)
    # Convert common placeholders to empty
    if s.lower() in ['not available', 'na', 'none', '-', 'Unknown' ]:
        return ""
    return s

def transform_row(row, mapping):
    """
    For a single row (Series), extract and clean the relevant fields.
    'mapping' is a dictionary where:
      key = lower-case original column name (if present)
      value = target Kaggle column name
    For the target categorical fields (MitreTechniques, IncidentGrade, ThreatFamily, SuspicionLevel, LastVerdict),
    if the value is missing or noisy, we clear it (set to empty string).
    """
    new_row = {}
    for orig, target in mapping.items():
        if orig in row:
            new_row[target] = clean_value(row[orig])
        else:
            # For ThreatFamily (or any field not present), use empty string
            new_row[target] = ""
    return new_row

def transform_dataframe(df):
    """
    Transform the input DataFrame (generated log) to match the Kaggle dataset schema.
    The mapping dictionary below maps the lower-case original column names
    (from the generated log CSV) to the desired Kaggle dataset column names.
    """
    # Define mapping.
    # Note: The generated log CSV includes some target columns:
    #   mitretechniques, incidentgrade, suspicionlevel, lastverdict.
    # ThreatFamily is not present; add it as empty.
    mapping = {
        "timestamp": "Timestamp",
        "mitretechniques": "MitreTechniques",
        "incidentid": "IncidentId",
        "incidentgrade": "IncidentGrade",
        "mitretechniques": "MitreTechniques",
        # Target field: ThreatFamily – not in log? set empty.
        "threatfamily": "ThreatFamily",
        "suspicionlevel": "SuspicionLevel",
        "lastverdict": "LastVerdict",
        "deviceid": "DeviceId",
        "ipaddress": "IpAddress",
        "accountsid": "AccountId",
        "accountupn": "AccountUpn",
        "accountname": "AccountName",
        "devicename": "DeviceName",
        "applicationid": "ApplicationId",
        "applicationname": "ApplicationName",
        "filename": "Filename",
        "folderpath": "FolderPath",
        "osfamily": "OsFamily",
        "osversion": "OsVersion",
        "eventtype": "EventType",
        "channel": "Channel",
        "source": "Source",
        "guid": "Guid",
        "datatype": "Datatype",
        "macaddress": "MacAddress",
        "powershellhash": "PowershellHash",
        "index": "Index"
    }
    
    # Ensure all column names in df are lower-case for matching purposes.
    df.columns = [col.lower() for col in df.columns]
    
    # Create an empty list to store transformed records.
    transformed_records = []
    # Process each row
    for _, row in df.iterrows():
        transformed_records.append(transform_row(row, mapping))
    
    # Create new DataFrame from transformed records.
    new_df = pd.DataFrame(transformed_records)
    return new_df

def main():
    args = parse_args()
    
    try:
        print("Reading input CSV file...")
        df = pd.read_csv(args.input)
    except Exception as e:
        print(f"Error reading input CSV: {e}")
        sys.exit(1)
    
    print("Transforming data with intense parsing...")
    transformed_df = transform_dataframe(df)
    
    # (Optional) Remove rows where ALL target columns are empty
    target_cols = ["IncidentGrade", "ThreatFamily", "SuspicionLevel", "LastVerdict"]
    transformed_df = transformed_df[~transformed_df[target_cols].isnull().all(axis=1)]
    
    print(f"Saving transformed data to {args.output} ...")
    try:
        transformed_df.to_csv(args.output, index=False, encoding='utf-8')
        print("Transformation complete. Output saved.")
    except Exception as e:
        print(f"Error saving output CSV: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
