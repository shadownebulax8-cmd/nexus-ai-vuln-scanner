import os
from typing import List

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class ScannerSettings(BaseSettings):
    """
    Central configuration object for the scanner. Values are read from the
    environment / .env file and fall back to sane defaults otherwise.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- AI patch engine -------------------------------------------------
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

    # --- Scanning constraints ---------------------------------------------
    GLOBAL_TIMEOUT: float = float(os.getenv("GLOBAL_TIMEOUT", "1.5"))
    BANNER_READ_TIMEOUT: float = float(os.getenv("BANNER_READ_TIMEOUT", "0.6"))
    MAX_CONCURRENCY: int = int(os.getenv("MAX_CONCURRENCY", "250"))

    # --- Port presets ------------------------------------------------------
    # Used when the user doesn't pass --ports/--preset explicitly.
    DEFAULT_PORTS: List[int] = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 9200, 27017,
    ]

    # A small, fast preset for a first-pass sweep (`--preset quick`).
    QUICK_PORTS: List[int] = [21, 22, 23, 25, 80, 443, 3306, 8080]

    # A wide preset for a thorough sweep of the well-known port range.
    FULL_PORTS_RANGE: str = "1-1024"

    # --- Reporting -----------------------------------------------------
    REPORT_OUTPUT_DIR: str = os.getenv("REPORT_OUTPUT_DIR", ".")


settings = ScannerSettings()
