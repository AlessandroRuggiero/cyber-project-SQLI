"""Create the SQLite database and load the demo data."""

import os
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
database_path = Path(
    os.environ.get("DATABASE_PATH", str(BASE_DIR / "database.db"))
)
database_path.parent.mkdir(parents=True, exist_ok=True)

with sqlite3.connect(database_path) as connection:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript((BASE_DIR / "schema.sql").read_text())
    connection.executescript((BASE_DIR / "seed.sql").read_text())

print(f"Database ready at {database_path}")
