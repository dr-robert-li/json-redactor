#!/usr/bin/env python3
import json
import re
import sys
import os
import argparse
import csv

def redact_pii(obj):
    """
    Recursively redact PII from any JSON
    """
    if isinstance(obj, str):
        # Apply redaction patterns to string
        text = obj
        
        # Redact Salesforce links
        text = re.sub(r'https?://\w+\.lightning\.force\.com/\S+', '[REDACTED SALESFORCE LINK]', text)
        text = re.sub(r'https?://[^/]+\.my\.salesforce\.com/\S+', '[REDACTED SALESFORCE LINK]', text)
        
        # Redact Zendesk links
        text = re.sub(r'https?://[^/]+\.zendesk\.com/\S+', '[REDACTED ZENDESK LINK]', text)
        
        # Redact URLs containing tokens, hashes, auth strings
        text = re.sub(r'https?://[^\s]+(?:[?&/])(token|access_token|auth|key|hash|code|cookie|session|jwt|bearer|oauth|api_key|secret)(?:=|/)[^&\s/]+', '[REDACTED AUTH URL]', text)
        text = re.sub(r'https?://[^\s]+/[0-9a-f]{8,}(?:/|\?|$)', '[REDACTED HASH URL]', text)
        text = re.sub(r'https?://[^\s]+/[A-Za-z0-9+/=_-]{32,}(?:/|\?|$)', '[REDACTED TOKEN URL]', text)        
        # Redact email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED EMAIL]', text)
        
        # Redact international and domestic phone numbers in various formats
        # Standard US/Canada format
        text = re.sub(r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', '[REDACTED PHONE]', text)
        # International format with country code
        text = re.sub(r'\b\+\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,4}\b', '[REDACTED PHONE]', text)
        # Format like (+61)-1800-514-474
        text = re.sub(r'\(\+\d{1,4}\)-\d{3,4}-\d{3}-\d{3,4}', '[REDACTED PHONE]', text)
        # Format like +61-(0)-7-5613-1084
        text = re.sub(r'\+\d{1,4}-\(\d\)-\d{1,2}-\d{4}-\d{4}', '[REDACTED PHONE]', text)
        
        # Redact credit card numbers
        text = re.sub(r'\b(?:\d{4}[- ]?){3}\d{4}\b', '[REDACTED CREDIT CARD]', text)

        # Redact /installs/ URLs
        text = re.sub(r'https?://my\.[^/]+\.com/installs/[a-zA-Z0-9_-]+', '[REDACTED INSTALL URL]', text)

        # Common TLDs        
        # text = re.sub(r'\b[a-zA-Z0-9][a-zA-Z0-9-]*\.(com|org|net|io|co|us|edu|gov|biz|info)\b', '[REDACTED WEBSITE]', text)

        # Subdomains
        # text = re.sub(r'\b[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9][a-zA-Z0-9-]*\.(com|org|net|io|co|us|edu|gov|biz|info)\b', '[REDACTED WEBSITE]', text)

        # Domains with paths
        # text = re.sub(r'\b[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9-]+\.[a-z]{2,}(/[^\s]*)?', '[REDACTED WEBSITE]', text)

        # Redact specific name patterns
        # Common greetings with names
        text = re.sub(r'\b(Hey|Hey there|Hey There|Hello|Hi|Dear|Good morning|Good afternoon|Good evening|Evening|Morning|Afternoon|Greetings|Hiya|Howdy|Sup|sup|Whatsup|Whats up|Yo)[,!.\s-]*\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)', r'\1 [REDACTED NAME]', text)        
        
        # Names with single initial (e.g., "John M" or "Joe L.")
        text = re.sub(r'\b([A-Z][a-z]+)\s+([A-Z]\.?)\b', '[REDACTED NAME]', text)
        
        # Names with titles
        text = re.sub(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+\|\s+([A-Za-z\s]+)', '[REDACTED NAME] | \2', text)
        
        # Names followed by titles on a new line
        text = re.sub(r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\n([A-Z][A-Z\s\.]+)', '[REDACTED NAME]\n\2', text)
        
        # Specific names found in the data - example below
        text = re.sub(r'\bJohn Smith\b', '[REDACTED NAME]', text)
        
        # Names at the end of messages or signatures
        # Common salutations with names
        salutations = (
            r'Thank you!?|Thank you|Thanks|Cheers|Regards|Sincerely|'
            r'Best regards|Kind regards|Best wishes|Warm regards|'
            r'Best|Yours truly|Yours sincerely|Regards from|'
            r'Warmly|Cordially|All the best|Take care|'
            r'Many thanks|With appreciation|Respectfully|'
            r'Looking forward|Best wishes from|Yours faithfully|'
            r'With best regards|With kind regards|With thanks'
        )
    
        # Match salutation followed by punctuation/whitespace and then name
        text = re.sub(
            fr'({salutations})[^\w\n]*[\s\n]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
            r'\1\n[REDACTED NAME]',
            text
        )
    
        # Match salutation followed directly by name
        text = re.sub(
            fr'({salutations})[\s\n]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
            r'\1\n[REDACTED NAME]',
            text
        )
    
        # Match name followed by signature title/role
        text = re.sub(
            fr'({salutations})[^\w\n]*[\s\n]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)[\s\n]+([A-Za-z\s\|]+)',
            r'\1\n[REDACTED NAME]\n\3',
            text
        )

        # Full names with first and last name (more general pattern)
        text = re.sub(r'\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b', '[REDACTED NAME]', text)
        
        # Redact addresses
        # Standard US address format
        text = re.sub(r'\b\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}\b', '[REDACTED ADDRESS]', text)
        
        # International address format
        text = re.sub(r'\b\d+[a-zA-Z]?,\s*L\d+\s+\d+\s+[A-Za-z\s]+\s+St\b', '[REDACTED ADDRESS]', text)
        
        # Specific address pattern - examples below
        text = re.sub(r'10b,\s*L10\s*333\s*Ann\s*St', '[REDACTED ADDRESS]', text)
        text = re.sub(r'504\s*Lavaca\s*St,\s*Suite\s*1000', '[REDACTED ADDRESS]', text)
        
        # City, state/province, postal code, country format
        text = re.sub(r'[A-Za-z\s]+,\s*[A-Za-z]{2,4},\s*\d{4,5}(?:-\d{4})?\s*(?:[A-Za-z\s]+)?', '[REDACTED ADDRESS]', text)
        
        # Specific location - examples below
        text = re.sub(r'Brisbane,\s*QLD,\s*4000', '[REDACTED ADDRESS]', text)
        text = re.sub(r'Austin,\s*TX,\s*78759', '[REDACTED ADDRESS]', text)
        
        # Redact company names that might be confidential in the data - examples below
        text = re.sub(r'ACME Corp.', '[REDACTED COMPANY]', text)
        text = re.sub(r'WP Engine', '[REDACTED COMPANY]', text)

        # Redact file paths with application install names
        text = re.sub(r'(/nas/content/(live|staging)|/var/www|/usr/share/nginx|/usr/share/apache2|/opt/bitnami|/home/\w+/public_html|/srv/www)/[a-zA-Z0-9_-]+', '\\1/[REDACTED INSTALL]', text)
        
        return text
    
    elif isinstance(obj, dict):
        # Process each key-value pair in the dictionary
        redacted_dict = {}
        for key, value in obj.items():
            # Special handling for known sensitive fields
            if key in ['ip_address']:
                redacted_dict[key] = '[REDACTED IP]'
            elif key in ['location']:
                redacted_dict[key] = '[REDACTED LOCATION]'
            elif key in ['latitude', 'longitude']:
                redacted_dict[key] = 0.0
            else:
                # Recursively redact the value
                redacted_dict[key] = redact_pii(value)
        return redacted_dict
    
    elif isinstance(obj, list):
        # Process each item in the list
        return [redact_pii(item) for item in obj]
    
    else:
        # Return non-string, non-container objects unchanged
        return obj
    
def flatten_json(nested_json, prefix=''):
    """
    Flatten a nested JSON into a flat dictionary
    """
    flattened = {}
    
    if isinstance(nested_json, dict):
        for key, value in nested_json.items():
            new_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, (dict, list)):
                flattened.update(flatten_json(value, new_key))
            else:
                flattened[new_key] = value
                
    elif isinstance(nested_json, list):
        for i, item in enumerate(nested_json):
            new_key = f"{prefix}[{i}]"
            
            if isinstance(item, (dict, list)):
                flattened.update(flatten_json(item, new_key))
            else:
                flattened[new_key] = item
                
    return flattened

def export_to_csv(data, csv_path):
    """
    Export JSON data to CSV format sourcing the headers from the JSON keys
    """
    try:
        # Check if data is a list or has a list we can extract
        items = []
        
        # Try to find a list to process
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Look for the first list in the dictionary
            for key, value in data.items():
                if isinstance(value, list) and value:
                    items = value
                    # print(f"Found list under key '{key}' with {len(items)} items") # Debugging line
                    break
            
            # If no list found, use the dict itself as a single item
            if not items:
                items = [data]
        
        if not items:
            print("No data found to export to CSV")
            return False
        
        # Get all unique fields from all items
        all_fields = set()
        flattened_items = []
        
        for item in items:
            flat_item = flatten_json(item)
            flattened_items.append(flat_item)
            all_fields.update(flat_item.keys())
        
        # Sort fields for consistent output
        sorted_fields = sorted(all_fields)
        
        # Create CSV file
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            
            # Write header row
            csv_writer.writerow(sorted_fields)
            
            # Write data rows
            for flat_item in flattened_items:
                row = [flat_item.get(field, '') for field in sorted_fields]
                csv_writer.writerow(row)
        
        print(f"CSV export saved as: {csv_path}")
        return True
    
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
        return False

def process_json_file(file_path, export_csv=False):
    """
    Process a JSON file by redacting PII and optionally exporting to CSV
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Redact PII from the entire JSON structure
        redacted_data = redact_pii(data)
        
        # Create output filename
        base_name = os.path.basename(file_path)
        dir_name = os.path.dirname(file_path)
        output_path = os.path.join(dir_name, f"redacted_{base_name}")
        
        # Write redacted data
        with open(output_path, 'w') as f:
            json.dump(redacted_data, f, indent=2)
        
        print(f"Redacted file saved as: {output_path}")
        
        # Export to CSV if requested
        if export_csv:
            # Use the same name as the redacted JSON file but with .csv extension
            csv_path = output_path.replace('.json', '.csv')
            export_to_csv(redacted_data, csv_path)
        
        return True
        
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return False

def process_directory(directory_path, export_csv=False):
    """Process all JSON files in the specified directory (not including subdirectories)."""
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory")
        return False
    
    # Get all JSON files in the directory (not including subdirectories)
    json_files = [f for f in os.listdir(directory_path) 
                 if os.path.isfile(os.path.join(directory_path, f)) 
                 and f.lower().endswith('.json')]
    
    if not json_files:
        print(f"No JSON files found in {directory_path}")
        return False
    
    success_count = 0
    for file_name in json_files:
        file_path = os.path.join(directory_path, file_name)
        if process_json_file(file_path, export_csv):
            success_count += 1
    
    print(f"Successfully processed {success_count} out of {len(json_files)} files")
    return success_count > 0

def main():
    parser = argparse.ArgumentParser(description='Redact PII from JSON files')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', action='append', help='Path to JSON file(s) to process')
    group.add_argument('-d', '--directory', help='Path to directory containing JSON files to process (non-recursive)')
    parser.add_argument('--csv', action='store_true', help='Export redacted data to CSV format')
    
    args = parser.parse_args()
    
    if args.file:
        success_count = 0
        for file_path in args.file:
            if not os.path.isfile(file_path):
                print(f"Error: {file_path} is not a valid file")
                continue
                
            if not file_path.endswith('.json'):
                print(f"Warning: {file_path} does not appear to be a .json file")
                
            if process_json_file(file_path, args.csv):
                success_count += 1
        
        print(f"Successfully processed {success_count} out of {len(args.file)} files")
    
    elif args.directory:
        process_directory(args.directory, args.csv)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments provided, show help
        print("Error: You must specify one or more files or a directory to process")
        print("Usage examples:")
        print("  Process specific files:  python redaction.py -f file1.json -f file2.json")
        print("  Process all JSON files in a directory:  python redaction.py -d /path/to/directory")
        print("  Export to CSV as well:  python redaction.py -f file1.json --csv")
        sys.exit(1)
    else:
        main()