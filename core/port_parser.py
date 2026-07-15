from typing import List

MIN_PORT = 1
MAX_PORT = 65535


def parse_ports(expression: str) -> List[int]:
    """
    Parses a flexible port expression into a sorted list of unique ints.

    Accepts comma-separated values, single ports, and inclusive ranges:
        "22,80,443"
        "1-1024"
        "21-25,80,443,8000-8010"

    Raises ValueError with a human-readable message on anything malformed
    or out of the valid TCP port range (1-65535).
    """
    ports: set = set()

    for raw_chunk in expression.split(","):
        chunk = raw_chunk.strip()
        if not chunk:
            continue

        if "-" in chunk:
            start_str, _, end_str = chunk.partition("-")
            try:
                start, end = int(start_str.strip()), int(end_str.strip())
            except ValueError:
                raise ValueError(f"'{chunk}' is not a valid port range (expected e.g. 20-25).")
            if start > end:
                start, end = end, start
            _validate_port(start, chunk)
            _validate_port(end, chunk)
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"'{chunk}' is not a valid port number.")
            _validate_port(port, chunk)
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports were parsed from the input.")

    return sorted(ports)


def _validate_port(port: int, source: str) -> None:
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"Port {port} (from '{source}') is outside the valid range {MIN_PORT}-{MAX_PORT}.")
