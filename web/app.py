from flask import Flask, render_template, request, url_for
import subprocess
import os
import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Pipeline functions for processing each log record

def time_pipeline(log_line):
    """
    Assign or parse a timestamp for a log record.
    If the log line contains "timestamp:" extract it; otherwise, use the current time.
    """
    if "timestamp:" in log_line:
        try:
            # For example, assume the log contains "timestamp:2023-01-01T12:34:56"
            ts_str = log_line.split("timestamp:")[1].split()[0]
            ts = datetime.datetime.fromisoformat(ts_str)
        except Exception:
            ts = datetime.datetime.now()
    else:
        ts = datetime.datetime.now()
    return ts.isoformat()

def inference_pipeline(log_line):
    """
    Perform a dummy inference: label a log as 'anomaly' if it contains 'error'; otherwise, 'normal'.
    """
    if "error" in log_line.lower():
        return "anomaly"
    return "normal"

def embedding_pipeline(log_line):
    """
    Create a dummy embedding for the log by using its length and a simple summary statistic.
    """
    length = len(log_line)
    sum_ord = sum(ord(c) for c in log_line) % 100
    return [length, sum_ord]

def process_log_file(file_content):
    """
    Process the raw output file content.
    Splits the file content by lines and applies the three pipelines:
      - time_pipeline
      - inference_pipeline
      - embedding_pipeline
    Returns a list of dictionaries (one per log record).
    """
    processed_logs = []
    for line in file_content.splitlines():
        if not line.strip():
            continue
        log_record = {
            "raw": line,
            "timestamp": time_pipeline(line),
            "inference": inference_pipeline(line),
            "embedding": embedding_pipeline(line)
        }
        processed_logs.append(log_record)
    return processed_logs

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/extract', methods=['GET', 'POST'])
def extract():
    if request.method == 'POST':
        # Gather form inputs
        host = request.form.get('host')
        port = request.form.get('port')
        username = request.form.get('username')
        password = request.form.get('password')
        index_pattern = request.form.get('index')
        query = request.form.get('query')
        size = request.form.get('size')
        output_file = request.form.get('output')
        verify_ssl = request.form.get('verify_ssl')
        debug = request.form.get('debug')
        from_file = request.form.get('from_file')

        # Build command for external script (assumed to be at '../elasticsearch_extractor.py')
        cmd = ['python', '../elasticsearch_extractor.py', '--host', host]
        if port:
            cmd.extend(['--port', port])
        if username:
            cmd.extend(['--username', username])
        if password:
            cmd.extend(['--password', password])
        if index_pattern:
            cmd.extend(['--index', index_pattern])
        if query:
            cmd.extend(['--query', query])
        if size:
            cmd.extend(['--size', size])
        if output_file:
            cmd.extend(['--output', output_file])
        if verify_ssl == "on":
            cmd.append('--verify-ssl')
        if debug == "on":
            cmd.append('--debug')
        if from_file == "on":
            cmd.append('--from-file')

        # Run the external script via subprocess
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            script_output = result.stdout
        except subprocess.CalledProcessError as e:
            script_output = e.stderr or "An error occurred while running the script."

        # Read the output file content (if it exists)
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except Exception as e:
                file_content = f"Could not read output file: {e}"
        else:
            file_content = "Output file not found or not specified."

        # Process the raw output using the three pipelines
        processed_logs = process_log_file(file_content)

        # Render the result template showing the command, script output,
        # raw output file content, and the processed log records.
        return render_template(
            'extract_result.html',
            cmd=' '.join(cmd),
            output=script_output,
            file_content=file_content,
            processed_logs=processed_logs
        )
    # GET: display the form
    return render_template('extract_form.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
