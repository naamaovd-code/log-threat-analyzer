"""Reading lines from the log file, ignoring comment/junk lines, and extracting the raw data.

The parser only recognizes the *shape* of a log line (Common Log Format, as written by
Apache / Nginx). It does not decide what is suspicious - that is the engine's job.
"""
import re
from typing import Generator, Dict, Optional

# Common Log Format, e.g.
#   201.87.61.169 - - [23/Aug/2026:18:36:31 +0000] "POST /login HTTP/1.1" 401 512
#   ^ IP              ^ time (with zone)          ^ request (quoted)   ^ status ^ size (optional)
LOG_PATTERN = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3})'                                   # 1: IP address
    r'\s+\S+\s+\S+\s+'                                              # identity and user, usually "- -"
    r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'    # 2: timestamp
    r'\s+"[^"]*"'                                                   # the request, in quotes
    r'\s+(\d{3})'                                                   # 3: status code
    r'(?:\s|$)'                                                     # followed by a space (size...) or end of line
)


def parse_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single line from the log file and extract relevant information.
    Args:
        line (str): A single line from the log file.
    Returns:
        dict or None: the extracted data if the line is a valid log line (any status code),
        or None if the line is not a log line at all.
    """
    # remove the line ending ("\n" on Linux, "\r\n" on Windows, or nothing on the last line)
    line = line.rstrip("\r\n")

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    return {
        "timestamp": match.group(2),
        "ip_address": match.group(1),
        "status_code": match.group(3),
    }


def read_logs(file_path: str) -> Generator[Dict[str, str], None, None]:
    """Read lines from the log file, skip lines that are not log lines, and extract the raw data.
    Args:
        file_path (str): The path to the log file.
    Yields:
        dict: the extracted data for every valid log line (any status code).
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
