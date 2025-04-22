# JSON Redaction Tool
## Author: Dr. Robert Li
### Version 2.0

A Python utility for redacting personally identifiable information (PII) from JSON files and exporting the data to CSV format.

## Features

- Redacts PII from JSON files of any structure
- Handles various types of sensitive information:
  - Email addresses
  - Phone numbers
  - Names
  - Addresses
  - Credit card numbers
  - IP addresses
  - Locations
  - Website URLs
  - Salesforce and Zendesk links
- Exports redacted data to CSV format with dynamic column headers
- Processes individual files or entire directories

## Setup

### Creating a Virtual Environment (Recommended)

It's recommended to use a virtual environment to keep dependencies isolated:

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# When finished, deactivate the virtual environment
deactivate
```

## Usage

```bash
# Process a single file
python redaction.py -f path/to/file.json

# Process multiple files
python redaction.py -f path/to/file1.json -f path/to/file2.json

# Process all JSON files in a directory
python redaction.py -d path/to/directory

# Export to CSV as well
python redaction.py -f path/to/file.json --csv
```

## Requirements

- Python 3.6 or higher
- No additional packages required beyond the standard Python library

## Output

- Redacted JSON files are saved with "redacted_" prefix
- CSV files (if requested) use the same name as the redacted JSON but with .csv extension

## License

MIT License

Copyright (c) 2025 Dr. Robert Li

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.