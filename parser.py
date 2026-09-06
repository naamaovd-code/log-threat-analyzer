"""Reading lines from the log file, ignoring comment/junk lines, and extracting the raw data"""
import re
from typing import Generator, Dict, Optional

def parse_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single line from the log file and extract relevant information. if the line does not match the expected format, return None.
    Args:
        line (str): A single line from the log file.
    Returns:
        dict or None: A dictionary containing the extracted data if the line matches the expected format,"""
    if not any(error_code in line for error_code in [ " 401\n" , " 403\n" , " 404\n"]):
        return None

    
    pattern = r'^(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\s+\[(.*?)\]\s+".*?"\s+(\d{3})'

    try:
        #search pattern in log line
        match = re.search(pattern, line)
        #if a match is found, extract the timestamp and IP address
        if match:
            ip_address = match.group(1)
            timestamp = match.group(2)
            status_code = match.group(3)
            
            #return a dictionary with the extracted data
            return {
                "timestamp": timestamp, 
                "ip_address": ip_address,
                "status_code": status_code
                }
        else:#if no match is found, return None
            return None
    except Exception as e:#catch any exceptions that occur during parsing and print an error message
        print(f"Error parsing line: {e}")
        return None
def read_logs(file_path: str) -> Generator[Dict[str, str], None, None]:
    """Read lines from the log file, ignoring comment/junk lines, and extract the raw data.
    Args:
        file_path (str): The path to the log file.
    Yields:
        dict: A dictionary containing the extracted data for each valid log line.
    """
    try:
        #open the log file and read it line by line
        with open(file_path, 'r', encoding ='utf-8') as file:
            #iterate through each line in the file
            for line in file:
                #send the line to the parse_line function
                parsed_data = parse_line(line)
                #if parsed_data is not None, yield the parsed data
                if parsed_data is not None:
                    yield parsed_data

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except PermissionError:
        print(f"Permission denied: {file_path}")
    except Exception as e:
        print(f"Error reading file: {e}")
