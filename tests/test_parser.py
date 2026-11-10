"""Unit tests for parser.py"""
import pytest

from parser import parse_line, read_logs

VALID_401 = '10.0.0.1 - - [10/Nov/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401'
EXPECTED_401 = {
    "timestamp": "10/Nov/2026:10:00:01 +0000",
    "ip_address": "10.0.0.1",
    "status_code": "401",
}


# ---------- parse_line ----------

@pytest.mark.parametrize(
    "ending",
    ["\n", "\r\n", ""],
    ids=["linux_newline", "windows_newline", "no_newline_last_line"],
)
def test_parse_line_handles_any_line_ending(ending):
    assert parse_line(VALID_401 + ending) == EXPECTED_401


@pytest.mark.parametrize("code", ["403", "404"])
def test_parse_line_accepts_scanning_status_codes(code):
    line = f'10.0.0.3 - - [10/Nov/2026:10:05:00 +0000] "GET /backup.zip HTTP/1.1" {code}\n'
    assert parse_line(line)["status_code"] == code


@pytest.mark.parametrize(
    "line",
    [
        '10.0.0.9 - - [10/Nov/2026:10:00:00 +0000] "GET /home HTTP/1.1" 200\n',
        "ERROR: System memory dump failed. Restarting service...\n",
        "Nov 10 10:00:00 ubuntu-server sshd[1422]: Failed password for root from 9.9.9.9 port 22 ssh2\n",
        "\n",
        "",
        "this line is garbage but ends with 401\n",
    ],
    ids=["status_200", "error_line", "sshd_line", "empty_line", "empty_string", "garbage_ending_in_401"],
)
def test_parse_line_ignores_irrelevant_lines(line):
    assert parse_line(line) is None


# ---------- read_logs ----------

def test_read_logs_raises_when_file_is_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(read_logs(tmp_path / "does_not_exist.log"))


def test_read_logs_handles_windows_file_without_final_newline(tmp_path):
    log_file = tmp_path / "windows.log"
    log_file.write_bytes((VALID_401 + "\r\n" + VALID_401).encode("utf-8"))

    assert list(read_logs(log_file)) == [EXPECTED_401, EXPECTED_401]


def test_read_logs_survives_invalid_utf8_bytes(tmp_path):
    log_file = tmp_path / "binary_junk.log"
    log_file.write_bytes(b"\xff\xfe\x00 junk line\n" + VALID_401.encode("utf-8") + b"\n")

    assert list(read_logs(log_file)) == [EXPECTED_401]
