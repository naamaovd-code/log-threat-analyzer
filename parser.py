"""Reading lines from the log file, ignoring comment/junk lines, and extracting the raw data"""
import re
from typing import Generator, Dict, Optional

# Only these status codes are relevant for threat detection
SUSPICIOUS_STATUS_ENDINGS = (" 401", " 403", " 404")

LOG_PATTERN = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\s+\[(.*?)\]\s+".*?"\s+(\d{3})')


def parse_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single line from the log file and extract relevant information. if the line does not match the expected format, return None.
    Args:
        line (str): A single line from the log file.
    Returns:
        dict or None: A dictionary containing the extracted data if the line matches the expected format,"""
    # remove the line ending ("\n" on Linux, "\r\n" on Windows, or nothing on the last line)
    line = line.rstrip("\r\n")

    # quick filter before running the regex
    if not line.endswith(SUSPICIOUS_STATUS_ENDINGS):
        return None

    match = LOG_PATTERN.search(line)
    if not match:
        return None

    return {
        "timestamp": match.group(2),
        "ip_address": match.group(1),
        "status_code": match.group(3),
    }


def read_logs(file_path: str) -> Generator[Dict[str, str], None, None]:
    """Read lines from the log file, ignoring comment/junk lines, and extract the raw data.
    Args:
        file_path (str): The path to the log file.
    Yields:
        dict: A dictionary containing the extracted data for each valid log line.
    Raises:
        OSError: if the file cannot be opened (e.g. FileNotFoundError, PermissionError).
            The caller decides how to report it (CLI message, API error, etc.).
    """
    # errors="replace": a single invalid byte should not stop the analysis of the whole file
    with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
        for line in file:
            parsed_data = parse_line(line)
            if parsed_data is not None:
                yield parsed_data
