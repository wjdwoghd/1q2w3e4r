"""SQLite connection and schema lifecycle for local platform persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS business_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('production', 'development')),
    internet_exposed INTEGER NOT NULL CHECK (internet_exposed IN (0, 1)),
    business_criticality TEXT NOT NULL
        CHECK (business_criticality IN ('critical', 'high', 'medium', 'low')),
    customer_information INTEGER NOT NULL CHECK (customer_information IN (0, 1)),
    credit_information INTEGER NOT NULL CHECK (credit_information IN (0, 1)),
    patch_status TEXT NOT NULL CHECK (patch_status IN ('current', 'pending', 'overdue', 'unknown')),
    vendor TEXT NOT NULL,
    owner TEXT NOT NULL,
    UNIQUE (business_service_id, name),
    FOREIGN KEY (business_service_id) REFERENCES business_services(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    bom_format TEXT NOT NULL,
    spec_version TEXT NOT NULL,
    serial_number TEXT,
    raw_document TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    source_bom_ref TEXT,
    issues_json TEXT NOT NULL,
    UNIQUE (sbom_id, position),
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);
"""


def connect_database(path: str | Path = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()
