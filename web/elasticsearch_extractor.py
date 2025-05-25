#!/usr/bin/env python3
"""
Enhanced Elasticsearch Log Extractor

This script connects to an Elasticsearch instance, queries log data,
extracts structured information from the message field, and saves
the extracted data to a CSV file.

The script handles nested JSON structures, different data formats,
and ensures all requested SOC alert fields are captured if available.
"""

import json
import csv
import re
import os
import sys
import logging
import argparse
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError, TransportError
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import ast

# Suppress insecure HTTPS warnings - only use in controlled environments
urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("elasticsearch_extractor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("elasticsearch_extractor")

# Define field mapping with priority order
FIELDS_OF_INTEREST = [
    "id", "orgid", "incidentid", "alertid", "timestamp", "detectorid",
    "alerttitle", "category", "mitretechniques", "incidentgrade",
    "actiongrouped", "actiongranular", "entitytype", "evidencerole",
    "deviceid", "sha256", "ipaddress", "url", "accountsid", 
    "accountupn", "accountobjectid", "accountname", "devicename",
    "networkmessageid", "emailclusterid", "registrykey", "registryvaluename",
    "registryvaluedata", "applicationid", "applicationname", "oauthapplicationid",
    "threatfamily", "filename", "folderpath", "resourceidname",
    "resourcetype", "roles", "osfamily", "osversion", "antispamdirection",
    "suspicionlevel", "lastverdict", "countrycode", "state", "city",
    "eventid", "eventtype", "channel", "source", "guid", "datatype",
    # Additional fields from sample data
    "macaddress", "powershellhash", "index"
]

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract log data from Elasticsearch.')
    parser.add_argument('--host', required=True, help='Elasticsearch host or response file path')
    parser.add_argument('--port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--username', help='Elasticsearch username')
    parser.add_argument('--password', help='Elasticsearch password')
    parser.add_argument('--index', default='default-index-*', help='Elasticsearch index pattern')
    parser.add_argument('--query', default='*', help='Elasticsearch query string')
    parser.add_argument('--size', type=int, default=10000, help='Number of documents to retrieve')
    parser.add_argument('--output', default='elasticsearch_data.csv', help='Output CSV file path')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--from-file', action='store_true', help='Process data from a file instead of querying Elasticsearch')
    
    return parser.parse_args()

def connect_to_elasticsearch(args):
    """Connect to Elasticsearch with the provided credentials."""
    logger.info(f"Connecting to Elasticsearch at {args.host}:{args.port}")
    
    # Ensure the host includes a scheme (http:// or https://)
    if not args.host.startswith("http://") and not args.host.startswith("https://"):
        host_url = f"http://{args.host}:{args.port}"
    else:
        host_url = args.host

    es_config = {
        'hosts': [host_url],
        'verify_certs': args.verify_ssl,
    }
    
    # Add authentication if provided
    if args.username and args.password:
        es_config['http_auth'] = (args.username, args.password)
    
    try:
        es = Elasticsearch(**es_config)
        info = es.info()
        logger.info(f"Connected to Elasticsearch cluster: {info.get('cluster_name', 'unknown')}")
        return es
    except (ApiError, TransportError) as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        sys.exit(1)

def query_elasticsearch(es, args):
    """Query Elasticsearch for log data."""
    logger.info(f"Querying Elasticsearch index: {args.index}")
    
    try:
        # Construct the query
        if args.query == '*':
            query = {"query": {"match_all": {}}}
        else:
            query = {
                "query": {
                    "query_string": {
                        "query": args.query
                    }
                }
            }
        
        # Add size parameter
        query["size"] = args.size
        
        # Execute the query
        response = es.search(index=args.index, body=query)
        
        logger.info(f"Retrieved {len(response['hits']['hits'])} documents")
        return response
    except (ApiError, TransportError) as e:
        logger.error(f"Failed to query Elasticsearch: {e}")
        sys.exit(1)

def parse_message_field(message_str):
    """
    Parse the message field which contains a string representation of a dictionary.
    Returns a dictionary of extracted fields.
    """
    try:
        return json.loads(message_str)
    except json.JSONDecodeError:
        pass
    
    try:
        return ast.literal_eval(message_str)
    except (SyntaxError, ValueError):
        pass
    
    result = {}
    pattern = r'(\w+)=([^,]+?)(?:,\s|\}|$)'
    matches = re.findall(pattern, message_str)
    
    for key, value in matches:
        value = value.strip()
        if value.lower() == "not available":
            result[key.lower()] = None
        else:
            result[key.lower()] = value

    event_props_match = re.search(r'EventProperties=\[(.*?)\]', message_str)
    if event_props_match:
        try:
            props_str = event_props_match.group(1)
            props_items = re.findall(r'(\w+)=([^,]+?)(?:,\s|\]|$)', props_str)
            for prop_key, prop_value in props_items:
                result[f"eventprop_{prop_key.lower()}"] = prop_value.strip()
        except Exception as e:
            logger.debug(f"Failed to parse EventProperties: {e}")
    
    return result

def extract_from_event_xml(xml_str):
    """
    Extract additional information from EventXML field.
    Returns a dictionary of extracted fields.
    """
    result = {}
    data_pattern = r'<Data Name=\'([^\']+)\'>([^<]+)</Data>'
    for name, value in re.findall(data_pattern, xml_str):
        result[f"eventdata_{name.lower()}"] = value
    
    system_patterns = {
        'provider_name': r'<Provider Name=\'([^\']+)\'',
        'provider_guid': r'<Provider[^>]*Guid=\'{([^}]+)}\'',
        'event_id': r'<EventID>(\d+)</EventID>',
        'version': r'<Version>(\d+)</Version>',
        'level': r'<Level>(\d+)</Level>',
        'task': r'<Task>(\d+)</Task>',
        'opcode': r'<Opcode>(\d+)</Opcode>',
        'keywords': r'<Keywords>(0x[0-9a-fA-F]+)</Keywords>',
        'computer': r'<Computer>([^<]+)</Computer>',
        'channel': r'<Channel>([^<]+)</Channel>',
        'time_created': r'<TimeCreated SystemTime=\'([^\']+)\'',
        'event_record_id': r'<EventRecordID>(\d+)</EventRecordID>',
        'process_id': r'<Execution ProcessID=\'(\d+)\'',
        'thread_id': r'<Execution[^>]*ThreadID=\'(\d+)\'',
        'correlation_activity_id': r'<Correlation ActivityID=\'{([^}]+)}\'',
    }
    
    for key, pattern in system_patterns.items():
        match = re.search(pattern, xml_str)
        if match:
            result[f"system_{key}"] = match.group(1)
    
    return result

def normalize_field_names(data):
    """
    Normalize field names to lowercase and handle special cases.
    """
    normalized = {}
    for key, value in data.items():
        normalized_key = key.lower()
        if normalized_key == 'accountupn' and '@' in str(value):
            normalized['accountupn'] = value
        elif normalized_key == 'timestamp' and isinstance(value, str):
            normalized['timestamp'] = value
        else:
            normalized[normalized_key] = value
    return normalized

def extract_data_from_log(hit):
    """
    Extract structured data from a log hit.
    Returns a dictionary of extracted fields.
    """
    result = {}
    
    for field in ['_id', '_index']:
        if field in hit:
            result[field] = hit[field]
    
    if '_source' in hit:
        source = hit['_source']
        for field in ['@timestamp', '@version']:
            if field in source:
                result[field] = source[field]
        
        if 'agent' in source:
            for key, value in source['agent'].items():
                result[f"agent_{key}"] = value
        
        if 'log' in source and 'file' in source['log']:
            for key, value in source['log']['file'].items():
                result[f"log_file_{key}"] = value
        
        if 'log_type' in source:
            result['log_type'] = source['log_type']
        
        if 'message' in source:
            logger.debug(f"Processing message: {source['message'][:200]}...")
            message_data = parse_message_field(source['message'])
            if message_data:
                message_data = normalize_field_names(message_data)
                if 'eventxml' in message_data:
                    xml_data = extract_from_event_xml(message_data['eventxml'])
                    message_data.update(xml_data)
                for field in FIELDS_OF_INTEREST:
                    if field in message_data:
                        result[field] = message_data[field]
                    elif f"event_{field}" in message_data:
                        result[field] = message_data[f"event_{field}"]
                    elif f"eventdata_{field}" in message_data:
                        result[field] = message_data[f"eventdata_{field}"]
                for key, value in message_data.items():
                    if key not in result:
                        result[key] = value
    return result

def save_to_csv(data, output_file):
    """Save extracted data to a CSV file."""
    if not data:
        logger.warning("No data to save")
        return
    all_fields = set()
    for record in data:
        all_fields.update(record.keys())
    fields = []
    for field in FIELDS_OF_INTEREST:
        if field in all_fields:
            fields.append(field)
            all_fields.remove(field)
    fields.extend(sorted(all_fields))
    logger.info(f"Saving {len(data)} records with {len(fields)} fields to {output_file}")
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            for record in data:
                row = {field: record.get(field, '') for field in fields}
                for field, value in row.items():
                    if isinstance(value, (dict, list)):
                        row[field] = json.dumps(value)
                writer.writerow(row)
        logger.info(f"Data successfully saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save data to CSV: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)

def process_file_directly(file_path, output_file):
    """
    Process an Elasticsearch response file directly instead of querying Elasticsearch.
    """
    logger.info(f"Processing file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            response = json.load(f)
        if 'hits' in response and 'hits' in response['hits']:
            hits = response['hits']['hits']
            logger.info(f"Found {len(hits)} records in file")
            extracted_data = []
            for hit in hits:
                record = extract_data_from_log(hit)
                extracted_data.append(record)
            save_to_csv(extracted_data, output_file)
        else:
            logger.error("Invalid Elasticsearch response format in file")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON in file: {e}")
        logger.error("Trying to process as newline-delimited JSON (NDJSON)...")
        try:
            hits = []
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            hit = json.loads(line)
                            hits.append(hit)
                        except json.JSONDecodeError:
                            logger.debug(f"Failed to parse line as JSON: {line[:100]}...")
            if hits:
                logger.info(f"Processed {len(hits)} records from NDJSON file")
                extracted_data = []
                for hit in hits:
                    record = extract_data_from_log(hit)
                    extracted_data.append(record)
                save_to_csv(extracted_data, output_file)
            else:
                logger.error("No valid JSON records found in file")
        except Exception as e2:
            logger.error(f"Failed to process file as NDJSON: {e2}")
    except Exception as e:
        logger.error(f"Failed to process file: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)

def main():
    """Main function to execute the script."""
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    start_time = datetime.now()
    logger.info(f"Script started at {start_time}")
    if args.from_file or os.path.isfile(args.host):
        file_path = args.host
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            sys.exit(1)
        process_file_directly(file_path, args.output)
    else:
        es = connect_to_elasticsearch(args)
        response = query_elasticsearch(es, args)
        extracted_data = []
        for hit in response['hits']['hits']:
            record = extract_data_from_log(hit)
            extracted_data.append(record)
        save_to_csv(extracted_data, args.output)
    end_time = datetime.now()
    duration = end_time - start_time
    logger.info(f"Script completed at {end_time}")
    logger.info(f"Total execution time: {duration}")
    logger.info(f"Output saved to: {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()
