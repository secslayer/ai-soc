#!/usr/bin/env python3
"""
Orchestrator for Processing Elasticsearch Log Data in Phases

This script executes a sequence of processing phases:
  1. Clean Phase (clean.py)
  2. Transform Phase (transform_generated_log.py)
  3. Reinforce Phase (renforce.py)
  4. Category Prediction Phase (category.py)
  5. Incident Grade Prediction Phase (incident_grade.py)
  6. MITRE Prediction Phase (mitre.py)

Each phase is executed via subprocess and its output file is timestamped.
After all phases complete, the orchestrator reads the original log file and 
attaches the prediction values (from category, incident grade, and predicted MITRE)
to it before saving the final merged CSV.

Usage:
  python3 orchestrator.py --input reinforced_alert_data.csv [--timestamp YYYYMMDD_HHMMSS]

For the incident_grade.py phase, additional arguments (--model and --label)
are provided; for mitre.py, additional arguments (--model, --label, --feature_encoders)
are also provided. Adjust these as needed.
"""

import subprocess
import datetime
import os
import sys
import pandas as pd
import argparse

def get_timestamp(provided_ts=None):
    """Return the provided timestamp or generate a new one in YYYYMMDD_HHMMSS format."""
    if provided_ts:
        return provided_ts
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_phase(script, input_file, output_file, extra_args=None):
    """
    Run a given Python script via subprocess.

    Parameters:
      script (str): Path to the phase script.
      input_file (str): Input CSV file path.
      output_file (str): Output CSV file path.
      extra_args (list): List of extra command-line arguments.
    """
    command = ["python3", script, "--input", input_file, "--output", output_file]
    if extra_args:
        command.extend(extra_args)
    print("Running command:", " ".join(command))
    subprocess.run(command, check=True)

def main():
    parser = argparse.ArgumentParser(description="Orchestrator for Elasticsearch log processing phases.")
    parser.add_argument("--input", required=True,
                        help="Path to the original reinforced_alert_data.csv file")
    parser.add_argument("--timestamp", help="Timestamp string in format YYYYMMDD_HHMMSS (optional)")
    args = parser.parse_args()

    ts = get_timestamp(args.timestamp)
    print(f"Using timestamp: {ts}")

    # Phase 1: Clean Phase
    clean_output = f"clea_{ts}.csv"
    run_phase("clean.py", args.input, clean_output)

    # Phase 2: Transform Phase
    transform_output = f"transform_{ts}.csv"
    run_phase("transform_generated_log.py", clean_output, transform_output)

    # Phase 3: Reinforce Phase
    reinforce_output = f"reinforced_alert_data_{ts}.csv"
    run_phase("renforce.py", transform_output, reinforce_output)

    # Phase 4: Category Prediction Phase (assumed to produce a 'category' column)
    category_output = f"reinforced_alert_data_updated_{ts}.csv"
    run_phase("category.py", reinforce_output, category_output)

    # Phase 5: Incident Grade Prediction Phase (assumed to produce an 'incidentgrade' column)
    incidentgrade_output = f"reinforced_alert_data_updated_i_{ts}.csv"
    extra_args_incident = ["--model", "incident_model.pkl", "--label", "incident_label.pkl"]
    run_phase("incident_grade.py", reinforce_output, incidentgrade_output, extra_args_incident)

    # Phase 6: MITRE Prediction Phase (assumed to produce a 'predicted_mitre' column)
    mitre_output = f"reinforced_alert_data_with_prediction_{ts}.csv"
    extra_args_mitre = ["--model", "mitre_model.pkl", "--label", "mitre_label.pkl", "--feature_encoders", "feature_encoders.pkl"]
    run_phase("mitre.py", reinforce_output, mitre_output, extra_args_mitre)

    # Merge predictions back into the original log file.
    print("\n=== Merging Predictions with Original Log ===")
    try:
        df_orig = pd.read_csv(args.input)
        df_orig.columns = df_orig.columns.str.strip().str.lower()
    except Exception as e:
        print(f"Error loading original input file {args.input}: {e}")
        sys.exit(1)

    try:
        df_cat = pd.read_csv(category_output)
        df_inc = pd.read_csv(incidentgrade_output)
        df_mitre = pd.read_csv(mitre_output)
    except Exception as e:
        print("Error loading one of the prediction outputs:", e)
        sys.exit(1)

    # Attach the prediction columns to the original log.
    # Adjust column names if needed.
    if 'category' in df_cat.columns:
        df_orig['category'] = df_cat['category']
    else:
        print("Warning: 'category' column not found in category predictions.")

    if 'incidentgrade' in df_inc.columns:
        df_orig['incidentgrade'] = df_inc['incidentgrade']
    else:
        print("Warning: 'incidentgrade' column not found in incident grade predictions.")

    if 'predicted_mitre' in df_mitre.columns:
        df_orig['predicted_mitre'] = df_mitre['predicted_mitre']
    else:
        print("Warning: 'predicted_mitre' column not found in MITRE predictions.")

    final_output = f"final_merged_{ts}.csv"
    try:
        df_orig.to_csv(final_output, index=False)
        print(f"Final merged output saved as {final_output}")
    except Exception as e:
        print(f"Error saving final output {final_output}: {e}")

if __name__ == "__main__":
    main()
