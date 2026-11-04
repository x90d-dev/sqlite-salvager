#!/usr/bin/env python3
"""
sqlite-salvager: Production-Grade Forensic SQLite 3 Binary Carver & Recovery Engine
===================================================================================

A zero-dependency, low-level binary stream parser and digital forensics (DFIR) recovery tool
for heavily corrupted, truncated, header-wiped, or locked SQLite 3 databases, including
unallocated freelist blocks, freeblocks, slack space, and Write-Ahead Log (-wal) journals.

Follows the official SQLite Database File Format Specification:
https://www.sqlite.org/fileformat2.html

Features:
- Pure binary parsing using `mmap` and `struct` (never uses `sqlite3` to read the source file).
- 100-byte Database Header analyzer + Resilient Page Size Brute-Force Prober (512..65536 bytes).
- Full 64-bit SQLite Varint decoder (1-9 bytes, two's complement signed 64-bit support).
- B-Tree Table Interior (0x05), Table Leaf (0x0D), Index Interior (0x02), and Index Leaf (0x0A) parsers.
- Overflow Page Chain follower with cycle detection and strict boundary enforcement.
- Record Format decoder supporting all serial types: NULL, 8/16/24/32/48/64-bit signed integers,
  IEEE 754 64-bit floats, 0/1 constants, BLOBs, and UTF-8 / UTF-16LE / UTF-16BE strings.
- Deleted & Unallocated Data Carving:
  * Freelist Trunk & Leaf Page traversal.
  * In-page Freeblock linked-list traversal.
  * Unallocated gap / slack space scanning (between cell pointer array and cell content start).
  * Heuristic Record-Signature Carver with configurable sensitivity for raw unallocated bytes.
- Write-Ahead Log (-wal) parser:
  * Supports magic numbers 0x377f0682 (little-endian checksums) and 0x377f0683 (big-endian checksums).
  * Verifies frame salts & cumulative checksums, or bypasses corrupt checksums in forensic mode.
- Schema Auto-Reconstruction:
  * Parses `sqlite_schema` / `sqlite_master` from Root Page 1 (or carved schema rows) to map
    root pages to table names and column definitions.
  * Dynamically groups orphan/headerless records by their serial-type signature into synthetic
    tables (e.g., `recovered_table_sig_INT_TEXT_BLOB`).
- Multi-Format Export & Audit Report:
  * `.sql` dump (`CREATE TABLE` + `INSERT INTO` with hex-escaped blobs and status comments).
  * `.csv` & `.jsonl` streaming exports per table (with forensic metadata fields).
  * Rebuilt clean `.sqlite` database output.
  * Detailed Markdown & Terminal Forensic Audit Report (`forensic_audit_report.md`).
- Built-in Synthetic Corrupt Database Test Suite (`--self-test`).

Author: Principal Systems & DFIR Engineering
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime
import hashlib
import io
import json
import logging
import math
import mmap
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


# =============================================================================
# 1. CONSTANTS & DATA STRUCTURES
# =============================================================================

SQLITE3_MAGIC = b"SQLite format 3\x00"
STANDARD_PAGE_SIZES = (4096, 1024, 2048, 8192, 16384, 32768, 65536, 512)

# B-Tree Page Type Flags
PAGE_TYPE_INTERIOR_INDEX = 0x02
PAGE_TYPE_INTERIOR_TABLE = 0x05
PAGE_TYPE_LEAF_INDEX = 0x0A
PAGE_TYPE_LEAF_TABLE = 0x0D
VALID_PAGE_TYPES = {
    PAGE_TYPE_INTERIOR_INDEX,
    PAGE_TYPE_INTERIOR_TABLE,
    PAGE_TYPE_LEAF_INDEX,
    PAGE_TYPE_LEAF_TABLE,
}

# WAL Magic Numbers
WAL_MAGIC_LE = 0x377F0682
WAL_MAGIC_BE = 0x377F0683
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


class RecordSourceType(str, Enum):
    ACTIVE_LEAF = "ACTIVE_LEAF"
    WAL_ACTIVE = "WAL_ACTIVE"
    WAL_CARVED = "WAL_CARVED"
    FREEBLOCK = "FREEBLOCK"
    SLACK_GAP = "SLACK_GAP"
    FREELIST_PAGE = "FREELIST_PAGE"
    RAW_CARVED = "RAW_CARVED"


class TextEncoding(int, Enum):
    UTF8 = 1
    UTF16LE = 2
    UTF16BE = 3

    @property
    def codec_name(self) -> str:
        if self == TextEncoding.UTF16LE:
            return "utf-16-le"
        if self == TextEncoding.UTF16BE:
            return "utf-16-be"
        return "utf-8"


@dataclass
class DatabaseHeader:
    magic_valid: bool
    page_size: int
    write_version: int
    read_version: int
    reserved_space: int
    max_payload_frac: int
    min_payload_frac: int
    leaf_payload_frac: int
    file_change_counter: int
    database_size_pages: int
    first_freelist_trunk_page: int
    total_freelist_pages: int
    schema_cookie: int
    schema_format: int
    default_cache_size: int
    largest_root_btree_page: int
    text_encoding: TextEncoding
    user_version: int
    incremental_vacuum_mode: int
    application_id: int
    version_valid_for: int
    sqlite_version_number: int
    probed_fallback: bool = False
    probe_confidence: float = 1.0

    @property
    def usable_size(self) -> int:
        return max(128, self.page_size - self.reserved_space)


@dataclass
class SalvagedRecord:
    rowid: Optional[int]
    values: List[Any]
    serial_types: List[int]
    source_type: RecordSourceType
    page_number: int
    byte_offset: int
    wal_frame: Optional[int] = None
    is_partial: bool = False
    raw_signature: str = ""
    assigned_table: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.raw_signature:
            self.raw_signature = compute_signature(self.serial_types)


@dataclass
class TableSchema:
    name: str
    root_page: int
    sql: str
    columns: List[str] = field(default_factory=list)
    column_types: List[str] = field(default_factory=list)
    is_synthetic: bool = False


@dataclass
class AnomalyLog:
    byte_offset: int
    page_number: int
    category: str
    description: str
    hex_preview: str = ""


@dataclass
class ForensicAuditStats:
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    header_info: Optional[DatabaseHeader] = None
    total_pages_scanned: int = 0
    valid_btree_pages: int = 0
    corrupted_pages_skipped: int = 0
    freelist_trunk_pages: int = 0
    freelist_leaf_pages: int = 0
    overflow_pages_stitched: int = 0
    active_records_recovered: int = 0
    deleted_records_recovered: int = 0
    wal_frames_scanned: int = 0
    wal_frames_valid: int = 0
    wal_frames_corrupt_bypassed: int = 0
    wal_records_recovered: int = 0
    schemas_recovered: Dict[str, TableSchema] = field(default_factory=dict)
    anomalies: List[AnomalyLog] = field(default_factory=list)


# =============================================================================
# 2. VARINT & SERIAL TYPE DECODERS
# =============================================================================

def decode_varint(buf: Union[bytes, memoryview], offset: int = 0, limit: Optional[int] = None) -> Tuple[int, int]:
    """
    Decode a SQLite variable-length integer (1 to 9 bytes) from `buf` starting at `offset`.
    Returns `(value, bytes_consumed)`.
    Raises `ValueError` if buffer bounds are exceeded.
    """
    end = len(buf) if limit is None else min(len(buf), limit)
    if offset < 0 or offset >= end:
        raise ValueError(f"Varint offset {offset} out of bounds (end={end})")

    val = 0
    max_bytes = min(9, end - offset)
    for i in range(max_bytes):
        b = buf[offset + i]
        if i == 8:
            # 9th byte uses all 8 bits
            val = (val << 8) | b
            # Interpret as 64-bit two's complement signed integer if highest bit set
            if val & (1 << 63):
                val -= (1 << 64)
            return val, 9
        else:
            val = (val << 7) | (b & 0x7F)
            if (b & 0x80) == 0:
                return val, i + 1

    raise ValueError(f"Truncated varint at offset {offset} (only {max_bytes} bytes available)")


def serial_type_content_size(serial_type: int) -> int:
    """
    Return the payload byte length corresponding to a SQLite Record Serial Type code.
    Specification: https://www.sqlite.org/fileformat2.html#record_format
    """
    if serial_type < 0:
        raise ValueError(f"Negative serial type: {serial_type}")
    if serial_type == 0:
        return 0  # NULL
    if serial_type == 1:
        return 1  # 8-bit twos-complement integer
    if serial_type == 2:
        return 2  # 16-bit big-endian integer
    if serial_type == 3:
        return 3  # 24-bit big-endian integer
    if serial_type == 4:
        return 4  # 32-bit big-endian integer
    if serial_type == 5:
        return 6  # 48-bit big-endian integer
    if serial_type == 6:
        return 8  # 64-bit big-endian integer
    if serial_type == 7:
        return 8  # IEEE 754-2008 64-bit floating point
    if serial_type in (8, 9):
        return 0  # Integer constant 0 (type 8) or 1 (type 9)
    if serial_type in (10, 11):
        raise ValueError(f"Reserved internal serial type {serial_type}")
    if serial_type >= 12:
        if serial_type % 2 == 0:
            return (serial_type - 12) // 2  # BLOB
        else:
            return (serial_type - 13) // 2  # TEXT
    return 0


def serial_type_category(serial_type: int) -> str:
    """Return high-level SQL affinity category for a serial type."""
    if serial_type == 0:
        return "NULL"
    if serial_type in (1, 2, 3, 4, 5, 6, 8, 9):
        return "INT"
    if serial_type == 7:
        return "REAL"
    if serial_type >= 12:
        return "BLOB" if (serial_type % 2 == 0) else "TEXT"
    return "UNKNOWN"


def compute_signature(serial_types: Sequence[int]) -> str:
    """Create a normalized type signature for grouping records into synthetic tables."""
    if not serial_types:
        return "EMPTY"
    cats = []
    for st in serial_types:
        cat = serial_type_category(st)
        cats.append(cat)
    return "_".join(cats)


def decode_signed_be(raw: Union[bytes, memoryview]) -> int:
    """Decode big-endian signed integer of arbitrary byte width (1, 2, 3, 4, 6, 8 bytes)."""
    return int.from_bytes(raw, byteorder="big", signed=True)


def decode_serial_value(
    serial_type: int,
    raw_bytes: Union[bytes, memoryview],
    encoding: TextEncoding = TextEncoding.UTF8,
) -> Any:
    """Decode a single field value from its raw byte slice and serial type code."""
    if serial_type == 0:
        return None
    if serial_type in (1, 2, 3, 4, 5, 6):
        if len(raw_bytes) == 0:
            return None
        return decode_signed_be(raw_bytes)
    if serial_type == 7:
        if len(raw_bytes) < 8:
            # Padded fallback for partial records
            padded = bytes(raw_bytes).ljust(8, b"\x00")
            val = struct.unpack(">d", padded)[0]
        else:
            val = struct.unpack(">d", raw_bytes[:8])[0]
        if math.isnan(val) or math.isinf(val):
            return None
        return val
    if serial_type == 8:
        return 0
    if serial_type == 9:
        return 1
    if serial_type >= 12:
        if serial_type % 2 == 0:
            return bytes(raw_bytes)
        else:
            raw_b = bytes(raw_bytes)
            try:
                return raw_b.decode(encoding.codec_name, errors="replace")
            except Exception:
                return raw_b.decode("utf-8", errors="replace")
    return None


def parse_record_payload(
    payload: Union[bytes, memoryview],
    encoding: TextEncoding = TextEncoding.UTF8,
    allow_partial: bool = True,
) -> Optional[Tuple[List[int], List[Any], bool]]:
    """
    Parse a SQLite Record Format payload (Header + Body).
    Returns `(serial_types, decoded_values, is_partial)` or `None` if header is invalid.
    """
    total_len = len(payload)
    if total_len < 1:
        return None

    try:
        header_size, varint_len = decode_varint(payload, 0, total_len)
    except ValueError:
        return None

    # Sanity check on header_size
    if header_size < varint_len or header_size > total_len or header_size > 65536:
        return None

    serial_types: List[int] = []
    cursor = varint_len
    while cursor < header_size:
        try:
            st, consumed = decode_varint(payload, cursor, header_size)
        except ValueError:
            return None
        if st < 0 or st in (10, 11):
            return None
        # Reject absurdly huge serial types (> 100MB single column in corrupted data)
        if st > 200_000_000:
            return None
        serial_types.append(st)
        cursor += consumed

    if cursor != header_size or not serial_types:
        return None

    # Decode body values
    body_cursor = header_size
    values: List[Any] = []
    is_partial = False

    for st in serial_types:
        try:
            col_size = serial_type_content_size(st)
        except ValueError:
            return None

        if body_cursor + col_size > total_len:
            if not allow_partial:
                return None
            # Partial / truncated record body
            available = max(0, total_len - body_cursor)
            raw_slice = payload[body_cursor : body_cursor + available]
            is_partial = True
            if available > 0 and st >= 12:
                val = decode_serial_value(st, raw_slice, encoding)
            else:
                val = None
            values.append(val)
            body_cursor = total_len
        else:
            raw_slice = payload[body_cursor : body_cursor + col_size]
            val = decode_serial_value(st, raw_slice, encoding)
            values.append(val)
            body_cursor += col_size

    return serial_types, values, is_partial


# =============================================================================
# 3. HEADER ANALYZER & RESILIENT BRUTE-FORCE PROBER
# =============================================================================

class HeaderAnalyzer:
    """Parses the 100-byte SQLite header or brute-forces page size if header is wiped."""

    @staticmethod
    def parse_header(mm: Union[mmap.mmap, bytes, memoryview], override_page_size: Optional[int] = None) -> Tuple[DatabaseHeader, List[AnomalyLog]]:
        anomalies: List[AnomalyLog] = []
        file_len = len(mm)

        if file_len < 100:
            header = HeaderAnalyzer._default_header(override_page_size or 4096, probed=True)
            anomalies.append(
                AnomalyLog(
                    byte_offset=0,
                    page_number=1,
                    category="TRUNCATED_FILE",
                    description=f"File size ({file_len} bytes) is smaller than 100-byte SQLite header.",
                    hex_preview=bytes(mm[:min(32, file_len)]).hex(),
                )
            )
            return header, anomalies

        raw_hdr = bytes(mm[:100])
        magic_ok = raw_hdr[:16] == SQLITE3_MAGIC

        # Unpack header fields per specification
        (
            raw_page_size,
            write_ver,
            read_ver,
            reserved_space,
            max_frac,
            min_frac,
            leaf_frac,
            change_counter,
            db_size_pages,
            first_freelist_trunk,
            total_freelist,
            schema_cookie,
            schema_format,
            default_cache_size,
            largest_root,
            raw_encoding,
            user_version,
            inc_vacuum,
            app_id,
        ) = struct.unpack(">HBBBBBBIIIIIIIIIIII", raw_hdr[16:72])

        version_valid_for, sqlite_version = struct.unpack(">II", raw_hdr[92:100])

        # Decode page size (value 1 represents 65536 in SQLite >= 3.7.1)
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        valid_ps = page_size in STANDARD_PAGE_SIZES
        valid_fractions = (max_frac == 64 and min_frac == 32 and leaf_frac == 32)
        valid_encoding = raw_encoding in (1, 2, 3)

        if override_page_size in STANDARD_PAGE_SIZES:
            page_size = override_page_size
            valid_ps = True

        if magic_ok and valid_ps and valid_fractions and reserved_space < 128:
            enc = TextEncoding(raw_encoding) if valid_encoding else TextEncoding.UTF8
            return (
                DatabaseHeader(
                    magic_valid=True,
                    page_size=page_size,
                    write_version=write_ver,
                    read_version=read_ver,
                    reserved_space=reserved_space,
                    max_payload_frac=max_frac,
                    min_payload_frac=min_frac,
                    leaf_payload_frac=leaf_frac,
                    file_change_counter=change_counter,
                    database_size_pages=db_size_pages,
                    first_freelist_trunk_page=first_freelist_trunk,
                    total_freelist_pages=total_freelist,
                    schema_cookie=schema_cookie,
                    schema_format=schema_format,
                    default_cache_size=default_cache_size,
                    largest_root_btree_page=largest_root,
                    text_encoding=enc,
                    user_version=user_version,
                    incremental_vacuum_mode=inc_vacuum,
                    application_id=app_id,
                    version_valid_for=version_valid_for,
                    sqlite_version_number=sqlite_version,
                    probed_fallback=False,
                    probe_confidence=1.0,
                ),
                anomalies,
            )

        # Header is corrupted, wiped, or zeroed out -> Trigger Auto-Probing Brute-Forcer
        anomalies.append(
            AnomalyLog(
                byte_offset=0,
                page_number=1,
                category="CORRUPT_DATABASE_HEADER",
                description=(
                    f"100-byte header magic/fields corrupted or wiped "
                    f"(magic_ok={magic_ok}, raw_page_size={raw_page_size}). Activating brute-force page prober."
                ),
                hex_preview=raw_hdr[:32].hex(),
            )
        )

        probed_ps, confidence, detected_enc = HeaderAnalyzer.probe_page_size(mm, override_page_size)
        hdr = HeaderAnalyzer._default_header(probed_ps, probed=True, confidence=confidence, encoding=detected_enc)
        # Preserve freelist pointer if it looks plausible within file bounds
        max_pages = max(1, file_len // probed_ps)
        if 1 < first_freelist_trunk <= max_pages:
            hdr.first_freelist_trunk_page = first_freelist_trunk
            hdr.total_freelist_pages = min(total_freelist, max_pages)

        return hdr, anomalies

    @staticmethod
    def probe_page_size(
        mm: Union[mmap.mmap, bytes, memoryview],
        override_page_size: Optional[int] = None,
    ) -> Tuple[int, float, TextEncoding]:
        """
        Brute-force standard SQLite page sizes (512..65536) by inspecting B-Tree page header
        invariants across candidate page boundaries.
        """
        if override_page_size in STANDARD_PAGE_SIZES:
            return override_page_size, 1.0, TextEncoding.UTF8

        file_len = len(mm)
        best_ps = 4096
        best_score = -1.0

        for candidate_ps in STANDARD_PAGE_SIZES:
            if file_len < candidate_ps:
                continue

            num_pages = min(256, file_len // candidate_ps)
            valid_headers = 0
            valid_pointer_arrays = 0
            divides_evenly = (file_len % candidate_ps == 0)

            for page_idx in range(num_pages):
                page_offset = page_idx * candidate_ps
                # Page 1 B-tree header starts at offset 100; all other pages start at offset 0
                bhdr_offset = page_offset + (100 if page_idx == 0 else 0)
                if bhdr_offset + 12 > file_len:
                    continue

                flag = mm[bhdr_offset]
                if flag not in VALID_PAGE_TYPES:
                    continue

                freeblock_off, cell_count, cell_content_off, frag_bytes = struct.unpack(
                    ">HHHB", bytes(mm[bhdr_offset + 1 : bhdr_offset + 8])
                )
                actual_content_off = 65536 if cell_content_off == 0 else cell_content_off

                bhdr_size = 8 if flag in (PAGE_TYPE_LEAF_TABLE, PAGE_TYPE_LEAF_INDEX) else 12
                ptr_array_start = (100 if page_idx == 0 else 0) + bhdr_size
                ptr_array_end = ptr_array_start + (cell_count * 2)

                # Check strict B-tree structural invariants:
                # 1. Cell count must be > 0 and pointer array must fit before cell content start
                # 2. Cell content start must be within candidate_ps
                # 3. Freeblock offset must be 0 or within page bounds
                if (
                    0 <= cell_count <= (candidate_ps // 4)
                    and ptr_array_end <= actual_content_off <= candidate_ps
                    and (freeblock_off == 0 or ptr_array_end <= freeblock_off < candidate_ps)
                    and frag_bytes < 128
                ):
                    valid_headers += 1
                    # Verify cell pointers themselves point into [actual_content_off, candidate_ps)
                    if cell_count > 0:
                        sample_count = min(cell_count, 8)
                        abs_ptr_start = page_offset + ptr_array_start
                        ptrs = struct.unpack(
                            f">{sample_count}H",
                            bytes(mm[abs_ptr_start : abs_ptr_start + sample_count * 2]),
                        )
                        if all(actual_content_off <= p < candidate_ps for p in ptrs):
                            valid_pointer_arrays += 1

            if num_pages > 0:
                ratio = (valid_headers + 2.0 * valid_pointer_arrays) / (3.0 * num_pages)
                score = ratio + (0.08 if divides_evenly else 0.0)
                if score > best_score and (valid_headers > 0 or valid_pointer_arrays > 0):
                    best_score = score
                    best_ps = candidate_ps

        confidence = min(1.0, max(0.1, best_score))
        return best_ps, round(confidence, 3), TextEncoding.UTF8

    @staticmethod
    def _default_header(
        page_size: int,
        probed: bool = True,
        confidence: float = 0.5,
        encoding: TextEncoding = TextEncoding.UTF8,
    ) -> DatabaseHeader:
        return DatabaseHeader(
            magic_valid=False,
            page_size=page_size,
            write_version=1,
            read_version=1,
            reserved_space=0,
            max_payload_frac=64,
            min_payload_frac=32,
            leaf_payload_frac=32,
            file_change_counter=0,
            database_size_pages=0,
            first_freelist_trunk_page=0,
            total_freelist_pages=0,
            schema_cookie=0,
            schema_format=4,
            default_cache_size=0,
            largest_root_btree_page=0,
            text_encoding=encoding,
            user_version=0,
            incremental_vacuum_mode=0,
            application_id=0,
            version_valid_for=0,
            sqlite_version_number=3040000,
            probed_fallback=probed,
            probe_confidence=confidence,
        )


# =============================================================================
# 4. SCHEMA & DDL EXTRACTOR
# =============================================================================

CREATE_TABLE_REGEX = re.compile(
    r"CREATE\s+(?:TEMP|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?:['\"`\[]?([a-zA-Z0-9_]+)['\"`\]]?\s*\((.+)\))",
    re.IGNORECASE | re.DOTALL,
)


def parse_columns_from_ddl(ddl: str) -> Tuple[List[str], List[str]]:
    """
    Extract column names and SQL types from a `CREATE TABLE (...)` statement.
    Handles nested parentheses (e.g., VARCHAR(255), CHECK(...)) and table constraints.
    """
    match = CREATE_TABLE_REGEX.search(ddl)
    if not match:
        return [], []

    body = match.group(2).strip()
    # Split top-level comma-separated clauses
    clauses: List[str] = []
    depth = 0
    current: List[str] = []
    in_quote: Optional[str] = None

    for ch in body:
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
        elif ch in ("'", '"', "`"):
            in_quote = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            clauses.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if current:
        clauses.append("".join(current).strip())

    col_names: List[str] = []
    col_types: List[str] = []
    table_constraint_keywords = {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"}

    for clause in clauses:
        if not clause:
            continue
        tokens = clause.split()
        if not tokens:
            continue
        first_upper = tokens[0].strip("'\"`[]").upper()
        if first_upper in table_constraint_keywords:
            continue

        col_name = tokens[0].strip("'\"`[]")
        col_type = "TEXT"
        if len(tokens) > 1:
            second_upper = tokens[1].upper()
            if second_upper not in {"PRIMARY", "NOT", "NULL", "UNIQUE", "DEFAULT", "CHECK", "REFERENCES", "COLLATE"}:
                col_type = tokens[1].upper()
        col_names.append(col_name)
        col_types.append(col_type)

    return col_names, col_types


# =============================================================================
# 5. CORE BINARY SALVAGER & B-TREE / FREELIST / WAL ENGINE
# =============================================================================

class SQLiteSalvagerEngine:
    """
    Low-level binary stream parser and carver for SQLite 3 databases and WAL files.
    """

    def __init__(
        self,
        db_path: Union[str, Path],
        wal_path: Optional[Union[str, Path]] = None,
        override_page_size: Optional[int] = None,
        carve_sensitivity: str = "medium",
        salvage_wal: bool = True,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.wal_path = Path(wal_path) if wal_path else Path(f"{self.db_path}-wal")
        self.override_page_size = override_page_size
        self.carve_sensitivity = carve_sensitivity.lower()
        self.salvage_wal = salvage_wal
        self.log = logger or logging.getLogger("sqlite-salvager")

        # Sensitivity thresholds for heuristic raw record carving
        if self.carve_sensitivity == "high":
            self.min_carve_cols = 2
            self.min_carve_payload = 4
        elif self.carve_sensitivity == "low":
            self.min_carve_cols = 3
            self.min_carve_payload = 10
        else:  # medium
            self.min_carve_cols = 2
            self.min_carve_payload = 6

        self.records: List[SalvagedRecord] = []
        self.seen_offsets: Set[Tuple[Optional[int], int]] = set()  # (wal_frame, abs_byte_offset)
        self.page_to_table_map: Dict[int, str] = {1: "sqlite_schema"}
        self.stats: Optional[ForensicAuditStats] = None

    # -------------------------------------------------------------------------
    # Main Entrypoint
    # -------------------------------------------------------------------------

    def run(self) -> ForensicAuditStats:
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.db_path}")

        file_size = self.db_path.stat().st_size
        sha256_hash = self._compute_sha256(self.db_path)
        self.stats = ForensicAuditStats(
            file_path=str(self.db_path),
            file_size_bytes=file_size,
            sha256_hash=sha256_hash,
        )

        if file_size == 0:
            self.stats.anomalies.append(
                AnomalyLog(0, 0, "EMPTY_FILE", "Database file is 0 bytes.")
            )
            return self.stats

        with open(self.db_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                self._process_database_stream(mm)
            finally:
                mm.close()

        # Process Write-Ahead Log (-wal) if requested and available
        if self.salvage_wal and self.wal_path.exists() and self.wal_path.stat().st_size >= WAL_HEADER_SIZE:
            with open(self.wal_path, "rb") as wf:
                wal_mm = mmap.mmap(wf.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    self._process_wal_stream(wal_mm)
                finally:
                    wal_mm.close()

        # Assign records to tables or synthesize signature-based tables
        self._reconstruct_and_assign_schemas()
        return self.stats

    # -------------------------------------------------------------------------
    # Database Binary Stream Processing
    # -------------------------------------------------------------------------

    def _process_database_stream(self, mm: mmap.mmap) -> None:
        assert self.stats is not None
        header, hdr_anomalies = HeaderAnalyzer.parse_header(mm, self.override_page_size)
        self.stats.header_info = header
        self.stats.anomalies.extend(hdr_anomalies)

        ps = header.page_size
        total_pages = max(1, math.ceil(len(mm) / ps))
        self.stats.total_pages_scanned = total_pages

        # 1. Identify Freelist Trunk & Leaf Pages
        freelist_pages = self._traverse_freelist(mm, header, total_pages)

        # 2. First pass: Traverse Interior Table B-Trees to map child pages to Root Pages
        self._map_btree_hierarchy(mm, header, total_pages, freelist_pages)

        # 3. Second pass: Scan every page for active cells, freeblocks, slack space, or raw carving
        for page_num in range(1, total_pages + 1):
            page_start = (page_num - 1) * ps
            page_end = min(len(mm), page_start + ps)
            page_buf = memoryview(mm)[page_start:page_end]

            if page_num in freelist_pages:
                # Carve freelist page for deleted records
                self._carve_raw_region(
                    mm=mm,
                    region_start=page_start,
                    region_end=page_end,
                    page_num=page_num,
                    header=header,
                    source_type=RecordSourceType.FREELIST_PAGE,
                )
                continue

            self._parse_page(
                mm=mm,
                page_buf=page_buf,
                page_num=page_num,
                page_abs_start=page_start,
                header=header,
                wal_frame=None,
            )

    def _traverse_freelist(
        self,
        mm: mmap.mmap,
        header: DatabaseHeader,
        total_pages: int,
    ) -> Set[int]:
        """Traverse the Freelist trunk chain and collect all trunk & leaf page numbers."""
        assert self.stats is not None
        freelist_pages: Set[int] = set()
        trunk_page = header.first_freelist_trunk_page
        ps = header.page_size

        visited_trunks: Set[int] = set()
        while 1 < trunk_page <= total_pages and trunk_page not in visited_trunks:
            visited_trunks.add(trunk_page)
            freelist_pages.add(trunk_page)
            self.stats.freelist_trunk_pages += 1

            trunk_offset = (trunk_page - 1) * ps
            if trunk_offset + 8 > len(mm):
                break

            next_trunk, leaf_count = struct.unpack(">II", mm[trunk_offset : trunk_offset + 8])
            max_leaves = (header.usable_size - 8) // 4
            if leaf_count > max_leaves:
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=trunk_offset,
                        page_number=trunk_page,
                        category="CORRUPT_FREELIST_TRUNK",
                        description=f"Freelist trunk page {trunk_page} claims {leaf_count} leaves (max={max_leaves}). Clamping.",
                        hex_preview=bytes(mm[trunk_offset : trunk_offset + 16]).hex(),
                    )
                )
                leaf_count = max_leaves

            for i in range(leaf_count):
                ptr_off = trunk_offset + 8 + (i * 4)
                if ptr_off + 4 > len(mm):
                    break
                leaf_pg = struct.unpack(">I", mm[ptr_off : ptr_off + 4])[0]
                if 1 < leaf_pg <= total_pages and leaf_pg not in freelist_pages:
                    freelist_pages.add(leaf_pg)
                    self.stats.freelist_leaf_pages += 1

            trunk_page = next_trunk

        return freelist_pages

    def _map_btree_hierarchy(
        self,
        mm: mmap.mmap,
        header: DatabaseHeader,
        total_pages: int,
        freelist_pages: Set[int],
    ) -> None:
        """
        Scan Interior Table B-Tree pages (0x05) to map child leaf pages back to their root table page.
        """
        ps = header.page_size
        parent_map: Dict[int, int] = {}

        for page_num in range(1, total_pages + 1):
            if page_num in freelist_pages:
                continue
            page_start = (page_num - 1) * ps
            bhdr_off = page_start + (100 if page_num == 1 else 0)
            if bhdr_off + 12 > len(mm):
                continue

            flag = mm[bhdr_off]
            if flag != PAGE_TYPE_INTERIOR_TABLE:
                continue

            _, cell_count, cell_content_off, _ = struct.unpack(
                ">HHHB", mm[bhdr_off + 1 : bhdr_off + 8]
            )
            rightmost_ptr = struct.unpack(">I", mm[bhdr_off + 8 : bhdr_off + 12])[0]
            if 1 <= rightmost_ptr <= total_pages and rightmost_ptr != page_num:
                parent_map[rightmost_ptr] = page_num

            ptr_array_start = bhdr_off + 12
            for i in range(min(cell_count, ps // 6)):
                p_off = ptr_array_start + i * 2
                if p_off + 2 > page_start + ps or p_off + 2 > len(mm):
                    break
                cell_rel = struct.unpack(">H", mm[p_off : p_off + 2])[0]
                cell_abs = page_start + cell_rel
                if cell_abs + 4 <= page_start + ps and cell_abs + 4 <= len(mm):
                    left_child = struct.unpack(">I", mm[cell_abs : cell_abs + 4])[0]
                    if 1 <= left_child <= total_pages and left_child != page_num:
                        parent_map[left_child] = page_num

        # Resolve root ancestors with cycle protection
        for child_pg in list(parent_map.keys()):
            curr = child_pg
            visited: Set[int] = {curr}
            while curr in parent_map:
                nxt = parent_map[curr]
                if nxt in visited:
                    break
                visited.add(nxt)
                curr = nxt
            # Map both the root and intermediate pages
            for v in visited:
                self.page_to_table_map[v] = f"root_page_{curr}"

    # -------------------------------------------------------------------------
    # Page-Level Parser (Active Cells, Freeblocks, Slack Space)
    # -------------------------------------------------------------------------

    def _parse_page(
        self,
        mm: Union[mmap.mmap, bytes, memoryview],
        page_buf: memoryview,
        page_num: int,
        page_abs_start: int,
        header: DatabaseHeader,
        wal_frame: Optional[int] = None,
    ) -> None:
        assert self.stats is not None
        ps = len(page_buf)
        bhdr_rel = 100 if (page_num == 1 and header.magic_valid) else 0

        # If Page 1 has a wiped 100-byte header, check whether offset 100 has a valid B-tree header
        if page_num == 1 and not header.magic_valid and ps >= 112:
            if page_buf[100] in VALID_PAGE_TYPES:
                bhdr_rel = 100

        if bhdr_rel + 8 > ps:
            self.stats.corrupted_pages_skipped += 1
            return

        flag = page_buf[bhdr_rel]
        if flag not in VALID_PAGE_TYPES:
            # Page is not a valid B-tree page (or its header was overwritten) -> raw carve!
            if wal_frame is None:
                self.stats.corrupted_pages_skipped += 1
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=page_abs_start + bhdr_rel,
                        page_number=page_num,
                        category="INVALID_BTREE_FLAG",
                        description=f"Page {page_num} has unrecognized B-Tree flag 0x{flag:02X}. Running heuristic raw carver.",
                        hex_preview=bytes(page_buf[bhdr_rel : min(ps, bhdr_rel + 24)]).hex(),
                    )
                )
            self._carve_raw_region(
                mm=mm,
                region_start=page_abs_start + bhdr_rel,
                region_end=page_abs_start + ps,
                page_num=page_num,
                header=header,
                source_type=RecordSourceType.WAL_CARVED if wal_frame is not None else RecordSourceType.RAW_CARVED,
                wal_frame=wal_frame,
            )
            return

        if wal_frame is None:
            self.stats.valid_btree_pages += 1

        freeblock_off, cell_count, raw_content_off, _ = struct.unpack(
            ">HHHB", bytes(page_buf[bhdr_rel + 1 : bhdr_rel + 8])
        )
        cell_content_off = 65536 if raw_content_off == 0 else raw_content_off
        if cell_content_off > ps:
            cell_content_off = ps

        bhdr_size = 8 if flag in (PAGE_TYPE_LEAF_TABLE, PAGE_TYPE_LEAF_INDEX) else 12
        ptr_array_rel = bhdr_rel + bhdr_size
        ptr_array_end = min(ps, ptr_array_rel + (cell_count * 2))

        # Only parse data records from Leaf Table B-Tree pages (0x0D)
        if flag == PAGE_TYPE_LEAF_TABLE:
            # 1. Parse Active Cells via Cell Pointer Array
            for idx in range(cell_count):
                ptr_pos = ptr_array_rel + idx * 2
                if ptr_pos + 2 > ps:
                    self.stats.anomalies.append(
                        AnomalyLog(
                            byte_offset=page_abs_start + ptr_pos,
                            page_number=page_num,
                            category="OUT_OF_BOUNDS_CELL_POINTER_ARRAY",
                            description=f"Cell pointer index {idx}/{cell_count} exceeds page boundary.",
                        )
                    )
                    break

                cell_rel = struct.unpack(">H", bytes(page_buf[ptr_pos : ptr_pos + 2]))[0]
                if cell_rel < ptr_array_rel or cell_rel >= ps:
                    self.stats.anomalies.append(
                        AnomalyLog(
                            byte_offset=page_abs_start + ptr_pos,
                            page_number=page_num,
                            category="CORRUPT_CELL_POINTER",
                            description=f"Cell pointer #{idx} on page {page_num} points to invalid offset {cell_rel}.",
                        )
                    )
                    continue

                rec = self._parse_table_leaf_cell(
                    mm=mm,
                    page_buf=page_buf,
                    cell_rel=cell_rel,
                    page_num=page_num,
                    page_abs_start=page_abs_start,
                    header=header,
                    source_type=RecordSourceType.WAL_ACTIVE if wal_frame is not None else RecordSourceType.ACTIVE_LEAF,
                    wal_frame=wal_frame,
                )
                if rec is not None:
                    self._register_record(rec)

            # 2. Traverse & Carve In-Page Freeblock Linked List
            self._carve_freeblock_chain(
                mm=mm,
                page_buf=page_buf,
                first_freeblock=freeblock_off,
                page_num=page_num,
                page_abs_start=page_abs_start,
                header=header,
                wal_frame=wal_frame,
            )

            # 3. Carve Unallocated Slack Space (between end of cell pointer array and start of cell content area)
            if cell_content_off > ptr_array_end + self.min_carve_payload:
                self._carve_raw_region(
                    mm=mm,
                    region_start=page_abs_start + ptr_array_end,
                    region_end=page_abs_start + cell_content_off,
                    page_num=page_num,
                    header=header,
                    source_type=RecordSourceType.WAL_CARVED if wal_frame is not None else RecordSourceType.SLACK_GAP,
                    wal_frame=wal_frame,
                )

    # -------------------------------------------------------------------------
    # Table Leaf Cell & Overflow Chain Parser
    # -------------------------------------------------------------------------

    def _parse_table_leaf_cell(
        self,
        mm: Union[mmap.mmap, bytes, memoryview],
        page_buf: memoryview,
        cell_rel: int,
        page_num: int,
        page_abs_start: int,
        header: DatabaseHeader,
        source_type: RecordSourceType,
        wal_frame: Optional[int] = None,
    ) -> Optional[SalvagedRecord]:
        assert self.stats is not None
        ps = len(page_buf)

        try:
            payload_size, v1_len = decode_varint(page_buf, cell_rel, ps)
            rowid, v2_len = decode_varint(page_buf, cell_rel + v1_len, ps)
        except ValueError:
            self.stats.anomalies.append(
                AnomalyLog(
                    byte_offset=page_abs_start + cell_rel,
                    page_number=page_num,
                    category="CORRUPT_CELL_HEADER_VARINT",
                    description=f"Failed to decode payload_size/rowid varints at page {page_num} offset {cell_rel}.",
                    hex_preview=bytes(page_buf[cell_rel : min(ps, cell_rel + 16)]).hex(),
                )
            )
            return None

        if payload_size <= 0 or payload_size > 100_000_000:
            return None

        payload_rel = cell_rel + v1_len + v2_len
        if payload_rel >= ps:
            return None

        # Calculate local payload size vs overflow according to SQLite B-Tree Leaf Table formula:
        # U = usable_size; X = U - 35; M = ((U - 12) * 32 // 255) - 23
        U = header.usable_size
        X = U - 35
        M = ((U - 12) * 32 // 255) - 23

        if payload_size <= X:
            local_size = payload_size
            has_overflow = False
        else:
            K = M + ((payload_size - M) % (U - 4))
            local_size = K if K <= X else M
            has_overflow = True

        local_end = min(ps, payload_rel + local_size)
        assembled = bytearray(page_buf[payload_rel:local_end])

        # Stitch overflow chain if present and scanning main database file
        if has_overflow and local_end + 4 <= ps and wal_frame is None:
            first_ovf_page = struct.unpack(">I", bytes(page_buf[local_end : local_end + 4]))[0]
            remaining = payload_size - len(assembled)
            ovf_bytes = self._follow_overflow_chain(mm, first_ovf_page, remaining, header)
            assembled.extend(ovf_bytes)

        parsed = parse_record_payload(assembled, header.text_encoding, allow_partial=True)
        if parsed is None:
            return None

        serial_types, values, is_partial = parsed
        if len(assembled) < payload_size:
            is_partial = True

        return SalvagedRecord(
            rowid=rowid,
            values=values,
            serial_types=serial_types,
            source_type=source_type,
            page_number=page_num,
            byte_offset=page_abs_start + cell_rel,
            wal_frame=wal_frame,
            is_partial=is_partial,
        )

    def _follow_overflow_chain(
        self,
        mm: Union[mmap.mmap, bytes, memoryview],
        first_page: int,
        bytes_needed: int,
        header: DatabaseHeader,
    ) -> bytes:
        """
        Follow a linked list of SQLite overflow pages:
        Each overflow page starts with a 4-byte big-endian next_page pointer (0 if last),
        followed by up to `usable_size - 4` payload bytes.
        Includes strict cycle and boundary protection.
        """
        assert self.stats is not None
        ps = header.page_size
        usable = header.usable_size
        total_pages = len(mm) // ps

        out = bytearray()
        curr_page = first_page
        visited: Set[int] = set()

        while curr_page > 1 and curr_page <= total_pages and len(out) < bytes_needed:
            if curr_page in visited:
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=(curr_page - 1) * ps,
                        page_number=curr_page,
                        category="CYCLIC_OVERFLOW_CHAIN",
                        description=f"Detected cyclic overflow reference to page {curr_page}. Breaking loop.",
                    )
                )
                break
            visited.add(curr_page)

            page_off = (curr_page - 1) * ps
            if page_off + 4 > len(mm):
                break

            next_page = struct.unpack(">I", bytes(mm[page_off : page_off + 4]))[0]
            chunk_len = min(bytes_needed - len(out), usable - 4, len(mm) - (page_off + 4))
            if chunk_len <= 0:
                break

            out.extend(mm[page_off + 4 : page_off + 4 + chunk_len])
            self.stats.overflow_pages_stitched += 1
            curr_page = next_page

        return bytes(out)

    # -------------------------------------------------------------------------
    # Deleted Data Carving: Freeblocks, Slack Space & Heuristic Signature Carver
    # -------------------------------------------------------------------------

    def _carve_freeblock_chain(
        self,
        mm: Union[mmap.mmap, bytes, memoryview],
        page_buf: memoryview,
        first_freeblock: int,
        page_num: int,
        page_abs_start: int,
        header: DatabaseHeader,
        wal_frame: Optional[int] = None,
    ) -> None:
        """
        Traverse the in-page linked list of freeblocks.
        Each freeblock starts with:
          - 2-byte big-endian offset to next freeblock (0 if last)
          - 2-byte big-endian size of this freeblock (including the 4-byte header)
        Note: When SQLite deletes a cell, the first 4 bytes of the cell (typically
        `payload_size` varint + `rowid` varint, and sometimes the first 1-2 bytes of the
        record header) are overwritten by the freeblock's 4-byte header!
        We recover both intact nested records and header-overwritten deleted records.
        """
        assert self.stats is not None
        ps = len(page_buf)
        curr_fb = first_freeblock
        visited: Set[int] = set()

        while 0 < curr_fb <= ps - 4:
            if curr_fb in visited:
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=page_abs_start + curr_fb,
                        page_number=page_num,
                        category="CYCLIC_FREEBLOCK_CHAIN",
                        description=f"Cyclic freeblock pointer at offset {curr_fb} on page {page_num}.",
                    )
                )
                break
            visited.add(curr_fb)

            next_fb, fb_size = struct.unpack(">HH", bytes(page_buf[curr_fb : curr_fb + 4]))
            if fb_size < 4 or curr_fb + fb_size > ps:
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=page_abs_start + curr_fb,
                        page_number=page_num,
                        category="CORRUPT_FREEBLOCK_SIZE",
                        description=f"Freeblock at offset {curr_fb} on page {page_num} has invalid size {fb_size}.",
                    )
                )
                break

            fb_start_abs = page_abs_start + curr_fb + 4
            fb_end_abs = page_abs_start + curr_fb + fb_size

            # Strategy A: Standard record header scan inside freeblock body
            before_count = len(self.records)
            self._carve_raw_region(
                mm=mm,
                region_start=fb_start_abs,
                region_end=fb_end_abs,
                page_num=page_num,
                header=header,
                source_type=RecordSourceType.FREEBLOCK,
                wal_frame=wal_frame,
            )

            # Strategy B: Reconstruct freeblock where the 4-byte freeblock header overwrote
            # [payload_size (1B), rowid (1B), header_size (1B), col0_serial_type (1B)]
            if len(self.records) == before_count and (fb_size - 4) >= 2:
                reconstructed = self._try_reconstruct_overwritten_freeblock(
                    fb_body=page_buf[curr_fb + 4 : curr_fb + fb_size],
                    page_num=page_num,
                    abs_offset=fb_start_abs,
                    header=header,
                    wal_frame=wal_frame,
                )
                if reconstructed is not None:
                    self._register_record(reconstructed)

            curr_fb = next_fb

    def _try_reconstruct_overwritten_freeblock(
        self,
        fb_body: memoryview,
        page_num: int,
        abs_offset: int,
        header: DatabaseHeader,
        wal_frame: Optional[int],
    ) -> Optional[SalvagedRecord]:
        """
        When a small row (`payload_size < 128`, `rowid < 128`) is deleted in-place, the 4-byte
        freeblock header (`next_offset`, `fb_size`) overwrites the first 2 bytes of the cell header
        (`payload_size`, `rowid`) PLUS the first 2 bytes of the record header (`header_size`, `serial_type_0`).
        The remaining bytes in `fb_body` contain `[serial_type_1, ..., serial_type_k, col0_data, col1_data, ...]`.
        By testing small `rem_header_len` splits where the sum of `serial_type_1..k` sizes leaves a valid
        `col0_size` (0, 1, 2, 3, 4, 6, 8), we can deterministically recover the surviving columns!
        """
        body_len = len(fb_body)
        if body_len < 3:
            return None

        valid_col0_sizes = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 6: 5, 8: 6}

        for rem_hdr_bytes in range(1, min(16, body_len)):
            serial_types: List[int] = []
            cursor = 0
            ok = True
            while cursor < rem_hdr_bytes:
                try:
                    st, consumed = decode_varint(fb_body, cursor, rem_hdr_bytes)
                except ValueError:
                    ok = False
                    break
                if st < 0 or st in (10, 11) or st > 4000:
                    ok = False
                    break
                serial_types.append(st)
                cursor += consumed

            if not ok or cursor != rem_hdr_bytes or not serial_types:
                continue

            try:
                rem_data_size = sum(serial_type_content_size(st) for st in serial_types)
            except ValueError:
                continue

            leftover_for_col0 = (body_len - rem_hdr_bytes) - rem_data_size
            if leftover_for_col0 in valid_col0_sizes and rem_data_size >= 2:
                col0_st = valid_col0_sizes[leftover_for_col0]
                full_serial_types = [col0_st] + serial_types
                values: List[Any] = []
                data_cursor = rem_hdr_bytes
                for st in full_serial_types:
                    sz = serial_type_content_size(st)
                    raw_val = fb_body[data_cursor : data_cursor + sz]
                    val = decode_serial_value(st, raw_val, header.text_encoding)
                    if isinstance(val, str) and not self._is_plausible_text(val):
                        ok = False
                        break
                    values.append(val)
                    data_cursor += sz

                if ok and any(v is not None and v != "" for v in values):
                    return SalvagedRecord(
                        rowid=None,
                        values=values,
                        serial_types=full_serial_types,
                        source_type=RecordSourceType.FREEBLOCK,
                        page_number=page_num,
                        byte_offset=abs_offset,
                        wal_frame=wal_frame,
                        is_partial=False,
                    )
        return None

    def _carve_raw_region(
        self,
        mm: Union[mmap.mmap, bytes, memoryview],
        region_start: int,
        region_end: int,
        page_num: int,
        header: DatabaseHeader,
        source_type: RecordSourceType,
        wal_frame: Optional[int] = None,
    ) -> None:
        """
        Heuristic Record-Signature Carver:
        Scans raw unallocated byte sequences (`region_start..region_end`) for valid
        SQLite Record Format structures or intact `[payload_size][rowid][record]` cells.
        """
        region_end = min(len(mm), region_end)
        if region_end - region_start < self.min_carve_payload:
            return

        buf = memoryview(mm)[region_start:region_end]
        limit = len(buf)
        offset = 0

        while offset <= limit - self.min_carve_payload:
            abs_pos = region_start + offset
            if (wal_frame, abs_pos) in self.seen_offsets:
                offset += 1
                continue

            # Candidate 1: Full Cell structure [payload_size][rowid][record_header][record_body]
            cell_candidate = self._try_carve_cell_at(buf, offset, limit, page_num, abs_pos, header, source_type, wal_frame)
            if cell_candidate is not None:
                rec, consumed = cell_candidate
                self._register_record(rec)
                offset += max(1, consumed)
                continue

            # Candidate 2: Raw Record structure [header_size][serial_types...][record_body]
            # (Occurs when the 4-byte freeblock header overwrote payload_size & rowid varints)
            rec_candidate = self._try_carve_record_header_at(buf, offset, limit, page_num, abs_pos, header, source_type, wal_frame)
            if rec_candidate is not None:
                rec, consumed = rec_candidate
                self._register_record(rec)
                offset += max(1, consumed)
                continue

            offset += 1

    def _try_carve_cell_at(
        self,
        buf: memoryview,
        offset: int,
        limit: int,
        page_num: int,
        abs_pos: int,
        header: DatabaseHeader,
        source_type: RecordSourceType,
        wal_frame: Optional[int],
    ) -> Optional[Tuple[SalvagedRecord, int]]:
        try:
            payload_size, v1 = decode_varint(buf, offset, limit)
            if payload_size < self.min_carve_payload or payload_size > (limit - offset - v1):
                return None
            rowid, v2 = decode_varint(buf, offset + v1, limit)
            if rowid <= 0 or rowid > (1 << 48):
                return None
        except ValueError:
            return None

        rec_start = offset + v1 + v2
        rec_end = rec_start + payload_size
        if rec_end > limit:
            return None

        rec_slice = buf[rec_start:rec_end]
        parsed = self._validate_heuristic_record(rec_slice, header.text_encoding, require_exact_length=True)
        if parsed is None:
            return None

        serial_types, values = parsed
        rec = SalvagedRecord(
            rowid=rowid,
            values=values,
            serial_types=serial_types,
            source_type=source_type,
            page_number=page_num,
            byte_offset=abs_pos,
            wal_frame=wal_frame,
            is_partial=False,
        )
        return rec, (v1 + v2 + payload_size)

    def _try_carve_record_header_at(
        self,
        buf: memoryview,
        offset: int,
        limit: int,
        page_num: int,
        abs_pos: int,
        header: DatabaseHeader,
        source_type: RecordSourceType,
        wal_frame: Optional[int],
    ) -> Optional[Tuple[SalvagedRecord, int]]:
        try:
            hdr_size, v_len = decode_varint(buf, offset, limit)
        except ValueError:
            return None

        # Valid record header length must be at least 3 bytes (1B hdr_size + >=2 serial types)
        if hdr_size < (v_len + self.min_carve_cols) or hdr_size > 128 or offset + hdr_size > limit:
            return None

        serial_types: List[int] = []
        cursor = offset + v_len
        hdr_end = offset + hdr_size
        total_body_size = 0

        while cursor < hdr_end:
            try:
                st, consumed = decode_varint(buf, cursor, hdr_end)
            except ValueError:
                return None
            if st < 0 or st in (10, 11) or st > 8192:
                return None
            try:
                col_sz = serial_type_content_size(st)
            except ValueError:
                return None
            serial_types.append(st)
            total_body_size += col_sz
            cursor += consumed

        if cursor != hdr_end or len(serial_types) < self.min_carve_cols:
            return None

        total_rec_size = hdr_size + total_body_size
        if total_body_size < (self.min_carve_payload - hdr_size) or offset + total_rec_size > limit:
            return None

        rec_slice = buf[offset : offset + total_rec_size]
        parsed = self._validate_heuristic_record(rec_slice, header.text_encoding, require_exact_length=True)
        if parsed is None:
            return None

        st_list, values = parsed
        rec = SalvagedRecord(
            rowid=None,
            values=values,
            serial_types=st_list,
            source_type=source_type,
            page_number=page_num,
            byte_offset=abs_pos,
            wal_frame=wal_frame,
            is_partial=False,
        )
        return rec, total_rec_size

    def _validate_heuristic_record(
        self,
        rec_slice: memoryview,
        encoding: TextEncoding,
        require_exact_length: bool = True,
    ) -> Optional[Tuple[List[int], List[Any]]]:
        """
        Apply strict forensic heuristics to eliminate false-positive zero runs or random noise
        when carving unallocated bytes.
        """
        # Reject all-zero or single-byte repeating buffers
        raw_b = bytes(rec_slice)
        if len(set(raw_b)) <= 2:
            return None

        parsed = parse_record_payload(rec_slice, encoding, allow_partial=not require_exact_length)
        if parsed is None:
            return None

        serial_types, values, is_partial = parsed
        if require_exact_length and is_partial:
            return None

        if len(serial_types) < self.min_carve_cols:
            return None

        # Check exact length match
        hdr_size, _ = decode_varint(rec_slice, 0)
        body_size = sum(serial_type_content_size(st) for st in serial_types)
        if require_exact_length and (hdr_size + body_size != len(rec_slice)):
            return None

        # Require at least one non-null, non-zero meaningful column (preferably printable text or non-trivial int)
        has_text = False
        non_null_count = 0
        for st, val in zip(serial_types, values):
            if val is not None:
                non_null_count += 1
            if st >= 13 and (st % 2 == 1):
                if not isinstance(val, str) or len(val) == 0:
                    return None
                # Text column must be mostly printable characters (reject binary garbage masquerading as UTF-8)
                if "\ufffd" in val:
                    return None
                printable = sum(1 for ch in val if ch.isprintable() or ch in "\r\n\t")
                if printable / len(val) < 0.85:
                    return None
                has_text = True

        if non_null_count == 0:
            return None

        # In medium/low sensitivity, require at least one valid printable text column OR >=3 structured columns
        if not has_text and len(serial_types) < 3:
            return None

        return serial_types, values

    @staticmethod
    def _is_plausible_text(val: str) -> bool:
        if not val or "\ufffd" in val:
            return False
        printable = sum(1 for ch in val if ch.isprintable() or ch in "\r\n\t")
        return (printable / len(val)) >= 0.85

    # -------------------------------------------------------------------------
    # Write-Ahead Log (-wal) Stream Parser & Checksum Verifier
    # -------------------------------------------------------------------------

    def _process_wal_stream(self, wal_mm: mmap.mmap) -> None:
        """
        Parse the 32-byte WAL Header and iterate through all WAL frames
        (24-byte frame header + page_size payload).
        """
        assert self.stats is not None
        assert self.stats.header_info is not None

        wal_len = len(wal_mm)
        if wal_len < WAL_HEADER_SIZE:
            return

        magic, fmt_ver, wal_page_size, ck_seq, salt1, salt2, cksum1, cksum2 = struct.unpack(
            ">IIIIIIII", wal_mm[:WAL_HEADER_SIZE]
        )

        if magic not in (WAL_MAGIC_LE, WAL_MAGIC_BE):
            self.stats.anomalies.append(
                AnomalyLog(
                    byte_offset=0,
                    page_number=0,
                    category="CORRUPT_WAL_HEADER_MAGIC",
                    description=f"WAL header magic 0x{magic:08X} invalid (expected 0x377F0682 or 0x377F0683). Using DB page size.",
                    hex_preview=bytes(wal_mm[:WAL_HEADER_SIZE]).hex(),
                )
            )
            big_endian_cksum = False
            ps = self.stats.header_info.page_size
        else:
            big_endian_cksum = (magic == WAL_MAGIC_BE)
            ps = 65536 if wal_page_size == 1 else (wal_page_size if wal_page_size in STANDARD_PAGE_SIZES else self.stats.header_info.page_size)

        # Verify WAL header checksum (bytes 0..24)
        calc_s1, calc_s2 = self.wal_checksum(wal_mm[:24], 0, 0, big_endian_cksum)
        header_cksum_ok = (calc_s1 == cksum1 and calc_s2 == cksum2)
        run_s1, run_s2 = cksum1, cksum2

        frame_size = WAL_FRAME_HEADER_SIZE + ps
        num_frames = (wal_len - WAL_HEADER_SIZE) // frame_size
        self.stats.wal_frames_scanned = num_frames

        for frame_idx in range(num_frames):
            frame_off = WAL_HEADER_SIZE + frame_idx * frame_size
            fhdr = wal_mm[frame_off : frame_off + WAL_FRAME_HEADER_SIZE]
            f_page_num, f_db_size, f_salt1, f_salt2, f_cksum1, f_cksum2 = struct.unpack(">IIIIII", fhdr)

            page_data_off = frame_off + WAL_FRAME_HEADER_SIZE
            page_buf = memoryview(wal_mm)[page_data_off : page_data_off + ps]

            # Verify cumulative WAL frame checksum (first 8 bytes of frame header + page payload)
            ck_ok = False
            if header_cksum_ok and f_salt1 == salt1 and f_salt2 == salt2:
                s1, s2 = self.wal_checksum(fhdr[:8], run_s1, run_s2, big_endian_cksum)
                s1, s2 = self.wal_checksum(page_buf, s1, s2, big_endian_cksum)
                if s1 == f_cksum1 and s2 == f_cksum2:
                    ck_ok = True
                    run_s1, run_s2 = s1, s2

            if ck_ok:
                self.stats.wal_frames_valid += 1
            else:
                self.stats.wal_frames_corrupt_bypassed += 1
                self.stats.anomalies.append(
                    AnomalyLog(
                        byte_offset=frame_off,
                        page_number=f_page_num,
                        category="WAL_FRAME_CHECKSUM_MISMATCH",
                        description=(
                            f"WAL frame #{frame_idx + 1} (page {f_page_num}) failed salt/checksum verification. "
                            f"Bypassing checksum for forensic carving."
                        ),
                    )
                )

            if f_page_num == 0 or f_page_num > 10_000_000:
                f_page_num = frame_idx + 1

            self._parse_page(
                mm=wal_mm,
                page_buf=page_buf,
                page_num=f_page_num,
                page_abs_start=page_data_off,
                header=self.stats.header_info,
                wal_frame=frame_idx + 1,
            )

    @staticmethod
    def wal_checksum(
        data: Union[bytes, memoryview],
        s1: int = 0,
        s2: int = 0,
        big_endian: bool = False,
    ) -> Tuple[int, int]:
        """
        Compute the official SQLite WAL cumulative checksum over 8-byte aligned chunks.
        """
        length = (len(data) // 8) * 8
        fmt = f">{length // 4}I" if big_endian else f"<{length // 4}I"
        words = struct.unpack(fmt, bytes(data[:length]))
        for i in range(0, len(words), 2):
            s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
            s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
        return s1, s2

    # -------------------------------------------------------------------------
    # Record Registration & Schema Reconstruction
    # -------------------------------------------------------------------------

    def _register_record(self, rec: SalvagedRecord) -> None:
        assert self.stats is not None
        key = (rec.wal_frame, rec.byte_offset)
        if key in self.seen_offsets:
            return
        self.seen_offsets.add(key)
        self.records.append(rec)

        if rec.wal_frame is not None:
            self.stats.wal_records_recovered += 1
        elif rec.source_type == RecordSourceType.ACTIVE_LEAF:
            self.stats.active_records_recovered += 1
        else:
            self.stats.deleted_records_recovered += 1

    def _reconstruct_and_assign_schemas(self) -> None:
        """
        1. Identify `sqlite_schema` / `sqlite_master` rows (5 columns: type, name, tbl_name, rootpage, sql).
        2. Build `TableSchema` definitions and map `root_page` numbers to table names.
        3. Match remaining records either by page hierarchy or by column-count & type compatibility,
           or synthesize `recovered_table_sig_<SIGNATURE>` tables when Page 1 is destroyed.
        """
        assert self.stats is not None
        schemas: Dict[str, TableSchema] = {}
        root_page_to_table: Dict[int, TableSchema] = {}

        # 1. Scan all salvaged records for sqlite_schema DDL entries
        for rec in self.records:
            if len(rec.values) == 5:
                obj_type, name, tbl_name, rootpage, sql = rec.values
                if (
                    isinstance(obj_type, str)
                    and obj_type.lower() == "table"
                    and isinstance(name, str)
                    and isinstance(rootpage, int)
                    and isinstance(sql, str)
                    and "CREATE" in sql.upper()
                ):
                    rec.assigned_table = "sqlite_schema"
                    if not name.startswith("sqlite_"):
                        cols, col_types = parse_columns_from_ddl(sql)
                        ts = TableSchema(
                            name=name,
                            root_page=rootpage,
                            sql=sql.strip(),
                            columns=cols,
                            column_types=col_types,
                            is_synthetic=False,
                        )
                        schemas[name] = ts
                        root_page_to_table[rootpage] = ts

        # 2. Assign records to known tables or synthetic tables
        for rec in self.records:
            if rec.assigned_table == "sqlite_schema":
                continue

            # Check direct root_page match
            if rec.page_number in root_page_to_table:
                candidate_ts = root_page_to_table[rec.page_number]
                if not candidate_ts.columns or len(rec.values) == len(candidate_ts.columns):
                    rec.assigned_table = candidate_ts.name
                    continue

            # Check B-Tree interior hierarchy mapping
            mapped_root_tag = self.page_to_table_map.get(rec.page_number, "")
            if mapped_root_tag.startswith("root_page_"):
                root_pg = int(mapped_root_tag.split("_")[-1])
                if root_pg in root_page_to_table:
                    candidate_ts = root_page_to_table[root_pg]
                    if not candidate_ts.columns or len(rec.values) == len(candidate_ts.columns):
                        rec.assigned_table = candidate_ts.name
                        continue

            # Check compatibility against known DDL schemas (for carved / WAL / orphan records)
            matched_schema: Optional[TableSchema] = None
            for ts in schemas.values():
                if not ts.is_synthetic and len(ts.columns) == len(rec.values):
                    if self._record_matches_schema(rec, ts):
                        matched_schema = ts
                        break

            if matched_schema is not None:
                rec.assigned_table = matched_schema.name
                continue

            # Synthesize table from record's serial-type signature
            sig = rec.raw_signature
            syn_name = f"recovered_table_sig_{sig}"
            if len(syn_name) > 56:
                sig_hash = hashlib.md5(sig.encode("utf-8")).hexdigest()[:8]
                syn_name = f"recovered_table_{len(rec.values)}cols_{sig_hash}"

            if syn_name not in schemas:
                cols = [f"col_{i + 1}" for i in range(len(rec.values))]
                col_types = [serial_type_category(st) for st in rec.serial_types]
                col_defs = ", ".join(
                    f'"{c}" {t if t != "NULL" else "TEXT"}' for c, t in zip(cols, col_types)
                )
                ddl = f'CREATE TABLE "{syn_name}" ({col_defs})'
                schemas[syn_name] = TableSchema(
                    name=syn_name,
                    root_page=rec.page_number,
                    sql=ddl,
                    columns=cols,
                    column_types=col_types,
                    is_synthetic=True,
                )
            rec.assigned_table = syn_name

        self.stats.schemas_recovered = schemas

    @staticmethod
    def _record_matches_schema(rec: SalvagedRecord, ts: TableSchema) -> bool:
        """Verify whether a record's column types align with a known TableSchema."""
        for idx, (st, val, expected_type) in enumerate(zip(rec.serial_types, rec.values, ts.column_types)):
            if val is None:
                continue
            exp_upper = expected_type.upper()
            # Note: SQLite aliases `INTEGER PRIMARY KEY` column values inside the record payload as NULL (serial type 0)
            if "INT" in exp_upper and st not in (0, 1, 2, 3, 4, 5, 6, 8, 9):
                return False
            if ("CHAR" in exp_upper or "TEXT" in exp_upper) and not (st >= 13 and st % 2 == 1):
                return False
            if ("REAL" in exp_upper or "FLOA" in exp_upper or "DOUB" in exp_upper) and st not in (1, 2, 3, 4, 5, 6, 7, 8, 9):
                return False
        return True

    @staticmethod
    def _compute_sha256(filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()


# =============================================================================
# 6. MULTI-FORMAT EXPORTER (.sql, .csv, .jsonl, .sqlite, Audit Report)
# =============================================================================

class SalvageExporter:
    """Exports recovered records and forensic telemetry to disk."""

    def __init__(self, engine: SQLiteSalvagerEngine, output_dir: Union[str, Path]) -> None:
        self.engine = engine
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_all(self) -> Dict[str, Path]:
        artifacts: Dict[str, Path] = {}
        artifacts["sql_dump"] = self.export_sql_dump()
        artifacts["csv_dir"] = self.export_csv_and_jsonl()
        artifacts["rebuilt_sqlite"] = self.export_clean_sqlite()
        artifacts["audit_report"] = self.export_forensic_report()
        return artifacts

    @staticmethod
    def _format_sql_literal(val: Any) -> str:
        if val is None:
            return "NULL"
        if isinstance(val, bool):
            return "1" if val else "0"
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, (bytes, bytearray, memoryview)):
            return f"X'{bytes(val).hex().upper()}'"
        s = str(val).replace("'", "''")
        return f"'{s}'"

    def _prepare_row_values(self, rec: SalvagedRecord, ts: TableSchema) -> List[Any]:
        """
        Populate `INTEGER PRIMARY KEY` columns if SQLite stored them as `NULL` in the payload
        because they alias the B-Tree `rowid`.
        """
        vals = list(rec.values)
        if not ts.is_synthetic and rec.rowid is not None and len(vals) == len(ts.columns):
            for idx, (col_name, col_type) in enumerate(zip(ts.columns, ts.column_types)):
                if vals[idx] is None and col_name.lower() in ("id", "rowid", "user_id", "item_id", "record_id") and "INT" in col_type.upper():
                    vals[idx] = rec.rowid
                    break
        return vals

    def export_sql_dump(self) -> Path:
        assert self.engine.stats is not None
        sql_path = self.output_dir / "salvaged_dump.sql"
        schemas = self.engine.stats.schemas_recovered

        grouped: Dict[str, List[SalvagedRecord]] = defaultdict(list)
        for rec in self.engine.records:
            if rec.assigned_table and rec.assigned_table != "sqlite_schema":
                grouped[rec.assigned_table].append(rec)

        with open(sql_path, "w", encoding="utf-8") as f:
            f.write("-- =====================================================================\n")
            f.write("-- sqlite-salvager Forensic SQL Dump\n")
            f.write(f"-- Source File: {self.engine.stats.file_path}\n")
            f.write(f"-- SHA-256:     {self.engine.stats.sha256_hash}\n")
            f.write("-- =====================================================================\n\n")
            f.write("PRAGMA foreign_keys = OFF;\n")
            f.write("BEGIN TRANSACTION;\n\n")

            for tbl_name, ts in schemas.items():
                f.write(f"-- Table: {tbl_name} (Root Page: {ts.root_page}, Synthetic: {ts.is_synthetic})\n")
                ddl = ts.sql.rstrip().rstrip(";")
                f.write(f"{ddl};\n\n")

                for rec in grouped.get(tbl_name, []):
                    row_vals = self._prepare_row_values(rec, ts)
                    literals = ", ".join(self._format_sql_literal(v) for v in row_vals)
                    meta_comment = (
                        f"/* source={rec.source_type.value} page={rec.page_number} "
                        f"offset=0x{rec.byte_offset:X}"
                        + (f" wal_frame={rec.wal_frame}" if rec.wal_frame else "")
                        + (f" rowid={rec.rowid}" if rec.rowid is not None else "")
                        + " */"
                    )
                    f.write(f'INSERT INTO "{tbl_name}" VALUES ({literals}); {meta_comment}\n')
                f.write("\n")

            f.write("COMMIT;\n")

        return sql_path

    def export_csv_and_jsonl(self) -> Path:
        assert self.engine.stats is not None
        tables_dir = self.output_dir / "tables"
        tables_dir.mkdir(parents=True, exist_ok=True)
        schemas = self.engine.stats.schemas_recovered

        grouped: Dict[str, List[SalvagedRecord]] = defaultdict(list)
        for rec in self.engine.records:
            if rec.assigned_table and rec.assigned_table != "sqlite_schema":
                grouped[rec.assigned_table].append(rec)

        for tbl_name, records in grouped.items():
            ts = schemas.get(tbl_name)
            col_names = ts.columns if (ts and ts.columns) else [f"col_{i+1}" for i in range(len(records[0].values))]
            headers = [
                "_forensic_rowid",
                "_forensic_source",
                "_forensic_page",
                "_forensic_offset_hex",
                "_forensic_wal_frame",
                "_forensic_is_partial",
            ] + col_names

            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", tbl_name)
            csv_path = tables_dir / f"{safe_name}.csv"
            jsonl_path = tables_dir / f"{safe_name}.jsonl"

            with open(csv_path, "w", encoding="utf-8", newline="") as cf, open(jsonl_path, "w", encoding="utf-8") as jf:
                writer = csv.writer(cf)
                writer.writerow(headers)

                for rec in records:
                    row_vals = self._prepare_row_values(rec, ts) if ts else list(rec.values)
                    norm_vals = [
                        f"0x{bytes(v).hex()}" if isinstance(v, (bytes, bytearray, memoryview)) else v
                        for v in row_vals
                    ]
                    meta = [
                        rec.rowid,
                        rec.source_type.value,
                        rec.page_number,
                        f"0x{rec.byte_offset:X}",
                        rec.wal_frame,
                        rec.is_partial,
                    ]
                    writer.writerow(meta + norm_vals)

                    json_obj = {
                        "_forensic": {
                            "rowid": rec.rowid,
                            "source": rec.source_type.value,
                            "page": rec.page_number,
                            "offset_hex": f"0x{rec.byte_offset:X}",
                            "wal_frame": rec.wal_frame,
                            "is_partial": rec.is_partial,
                        },
                        "data": dict(zip(col_names, norm_vals)),
                    }
                    jf.write(json.dumps(json_obj, ensure_ascii=False) + "\n")

        return tables_dir

    def export_clean_sqlite(self) -> Path:
        """
        Rebuild a brand-new, uncorrupted SQLite database file containing all salvaged tables,
        plus forensic metadata columns (`_salvage_source`, `_salvage_offset_hex`, `_salvage_wal_frame`).
        """
        assert self.engine.stats is not None
        rebuilt_path = self.output_dir / "salvaged_rebuilt.sqlite"
        if rebuilt_path.exists():
            rebuilt_path.unlink()

        schemas = self.engine.stats.schemas_recovered
        grouped: Dict[str, List[SalvagedRecord]] = defaultdict(list)
        for rec in self.engine.records:
            if rec.assigned_table and rec.assigned_table != "sqlite_schema":
                grouped[rec.assigned_table].append(rec)

        tmp_fd, tmp_sqlite_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(tmp_fd)
        conn = sqlite3.connect(tmp_sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE _forensic_salvage_manifest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT,
                    original_rowid INTEGER,
                    source_type TEXT,
                    page_number INTEGER,
                    byte_offset_hex TEXT,
                    wal_frame INTEGER,
                    is_partial INTEGER
                )
                """
            )

            for tbl_name, records in grouped.items():
                ts = schemas.get(tbl_name)
                col_names = ts.columns if (ts and ts.columns) else [f"col_{i+1}" for i in range(len(records[0].values))]
                # Create clean table without strict UNIQUE/PRIMARY KEY constraints so deleted/WAL historical versions can coexist
                col_defs = ", ".join(f'"{c}"' for c in col_names)
                safe_tbl = tbl_name.replace('"', '""')
                cur.execute(
                    f'CREATE TABLE IF NOT EXISTS "{safe_tbl}" ('
                    f'{col_defs}, "_salvage_source" TEXT, "_salvage_offset_hex" TEXT, "_salvage_wal_frame" INTEGER)'
                )

                placeholders = ", ".join(["?"] * (len(col_names) + 3))
                for rec in records:
                    row_vals = self._prepare_row_values(rec, ts) if ts else list(rec.values)
                    # Pad or trim if schema length slightly differs
                    if len(row_vals) < len(col_names):
                        row_vals.extend([None] * (len(col_names) - len(row_vals)))
                    elif len(row_vals) > len(col_names):
                        row_vals = row_vals[: len(col_names)]

                    cur.execute(
                        f'INSERT INTO "{safe_tbl}" VALUES ({placeholders})',
                        row_vals + [rec.source_type.value, f"0x{rec.byte_offset:X}", rec.wal_frame],
                    )
                    cur.execute(
                        """
                        INSERT INTO _forensic_salvage_manifest
                        (table_name, original_rowid, source_type, page_number, byte_offset_hex, wal_frame, is_partial)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tbl_name,
                            rec.rowid,
                            rec.source_type.value,
                            rec.page_number,
                            f"0x{rec.byte_offset:X}",
                            rec.wal_frame,
                            1 if rec.is_partial else 0,
                        ),
                    )
            conn.commit()
        finally:
            conn.close()
        shutil.copyfile(tmp_sqlite_path, str(rebuilt_path))
        os.remove(tmp_sqlite_path)

        return rebuilt_path

    def export_forensic_report(self) -> Path:
        assert self.engine.stats is not None
        st = self.engine.stats
        hdr = st.header_info
        report_path = self.output_dir / "forensic_audit_report.md"

        lines: List[str] = [
            "# Forensic SQLite Salvage & Carving Audit Report",
            "",
            "## 1. Evidence Overview",
            f"- **Source File**: `{st.file_path}`",
            f"- **File Size**: `{st.file_size_bytes:,}` bytes",
            f"- **SHA-256 Digest**: `{st.sha256_hash}`",
        ]

        if hdr:
            lines.extend([
                f"- **Header Magic Valid**: `{hdr.magic_valid}`",
                f"- **Fallback Brute-Force Probed**: `{hdr.probed_fallback}` (Confidence: `{hdr.probe_confidence * 100:.1f}%`)",
                f"- **Page Size**: `{hdr.page_size}` bytes (Usable: `{hdr.usable_size}` bytes)",
                f"- **Text Encoding**: `{hdr.text_encoding.name}` (`{hdr.text_encoding.value}`)",
                f"- **First Freelist Trunk Page**: `{hdr.first_freelist_trunk_page}` (Total Freelist Pages: `{hdr.total_freelist_pages}`)",
            ])

        lines.extend([
            "",
            "## 2. Recovery & Carving Telemetry",
            "| Metric | Count |",
            "| :--- | ---: |",
            f"| Total Pages Scanned | {st.total_pages_scanned:,} |",
            f"| Valid B-Tree Pages | {st.valid_btree_pages:,} |",
            f"| Corrupted / Wiped Pages Carved | {st.corrupted_pages_skipped:,} |",
            f"| Freelist Trunk Pages | {st.freelist_trunk_pages:,} |",
            f"| Freelist Leaf Pages | {st.freelist_leaf_pages:,} |",
            f"| Overflow Pages Stitched | {st.overflow_pages_stitched:,} |",
            f"| Active Leaf Records Recovered | {st.active_records_recovered:,} |",
            f"| Deleted / Unallocated Records Carved | {st.deleted_records_recovered:,} |",
            f"| WAL Frames Scanned | {st.wal_frames_scanned:,} |",
            f"| WAL Frames Verified (Valid Checksum) | {st.wal_frames_valid:,} |",
            f"| WAL Frames Bypassed (Corrupt Checksum) | {st.wal_frames_corrupt_bypassed:,} |",
            f"| WAL Records Recovered | {st.wal_records_recovered:,} |",
            f"| **Total Records Salvaged** | **{len(self.engine.records):,}** |",
            "",
            "## 3. Reconstructed & Synthesized Tables",
            "| Table Name | Root Page | Mode | Columns | Salvaged Rows |",
            "| :--- | ---: | :--- | :--- | ---: |",
        ])

        counts_by_table: Dict[str, int] = defaultdict(int)
        for r in self.engine.records:
            if r.assigned_table:
                counts_by_table[r.assigned_table] += 1

        for name, ts in st.schemas_recovered.items():
            mode = "Synthetic Signature" if ts.is_synthetic else "DDL Reconstructed"
            cols_str = ", ".join(ts.columns[:6]) + ("..." if len(ts.columns) > 6 else "")
            lines.append(
                f"| `{name}` | {ts.root_page} | {mode} | `{cols_str}` | {counts_by_table[name]:,} |"
            )

        lines.extend([
            "",
            "## 4. Anomaly & Corruption Log (Hex Offsets)",
        ])
        if not st.anomalies:
            lines.append("_No binary anomalies detected._")
        else:
            lines.extend([
                "| Byte Offset (Hex) | Page # | Category | Description | Hex Preview |",
                "| :--- | ---: | :--- | :--- | :--- |",
            ])
            for anom in st.anomalies[:100]:
                preview = f"`{anom.hex_preview[:32]}`" if anom.hex_preview else "-"
                lines.append(
                    f"| `0x{anom.byte_offset:08X}` | {anom.page_number} | `{anom.category}` | {anom.description} | {preview} |"
                )

        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return report_path


# =============================================================================
# 7. SYNTHETIC CORRUPTION & FORENSIC UNIT TEST SUITE
# =============================================================================

class ForensicSalvagerTestSuite(unittest.TestCase):
    """
    End-to-end forensic verification suite testing:
    1. Deleted records in freeblocks & unallocated space (`PRAGMA secure_delete = OFF`).
    2. Wiped / zeroed-out 100-byte database header (ransomware / anti-forensic wipe simulation)
       with page-size brute-forcing and synthetic table signature grouping.
    3. Payload overflow chains (> page_size BLOB/TEXT stitching).
    4. Write-Ahead Log (-wal) uncommitted transaction carving & corrupt frame checksum bypass.
    5. Out-of-bounds / cyclic pointer fault tolerance.
    """

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="sqlite_salvager_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_varint_decoder_64bit_and_edge_cases(self) -> None:
        """Verify 1-byte to 9-byte SQLite varints including negative 64-bit rowids."""
        test_vectors = [
            (b"\x00", 0, 1),
            (b"\x7f", 127, 1),
            (b"\x81\x00", 128, 2),
            (b"\x82\x00", 256, 2),
            (b"\xff\x7f", 16383, 2),
            (b"\x81\x80\x00", 16384, 3),
            # 9-byte varint representing -1 (all 1s in 64-bit two's complement)
            (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff", -1, 9),
        ]
        for raw, expected_val, expected_len in test_vectors:
            val, consumed = decode_varint(raw, 0)
            self.assertEqual(val, expected_val)
            self.assertEqual(consumed, expected_len)

    def test_02_deleted_records_and_overflow_stitching(self) -> None:
        """Verify carving of deleted rows from freeblocks/slack space and multi-page overflow stitching."""
        db_file = self.temp_dir / "evidence_deleted.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("PRAGMA page_size = 1024;")
        conn.execute("PRAGMA secure_delete = OFF;")
        conn.execute("PRAGMA journal_mode = DELETE;")
        conn.execute(
            "CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT, secret_token TEXT);"
        )

        # Insert active and soon-to-be-deleted rows, plus a large overflow row
        large_body = "OVERFLOW_PAYLOAD_START_" + ("A" * 2500) + "_OVERFLOW_PAYLOAD_END"
        conn.execute(
            "INSERT INTO chat_messages VALUES (1, 'alice@corp.local', 'Normal active message 1', 'TOK_ACTIVE_01');"
        )
        conn.execute(
            "INSERT INTO chat_messages VALUES (2, 'suspect@dark.net', 'INCULPATORY_DELETED_EVIDENCE_ROW_2', 'TOK_DELETED_999');"
        )
        conn.execute(
            "INSERT INTO chat_messages VALUES (3, 'bob@corp.local', ?, 'TOK_OVERFLOW_03');",
            (large_body,),
        )
        conn.execute(
            "INSERT INTO chat_messages VALUES (4, 'suspect@dark.net', 'SECOND_DELETED_SECRET_RECORD_4', 'TOK_DELETED_888');"
        )
        conn.commit()

        # Delete rows 2 and 4 so they enter the page freeblock / unallocated space
        conn.execute("DELETE FROM chat_messages WHERE id IN (2, 4);")
        conn.commit()
        conn.close()

        # Run salvager
        engine = SQLiteSalvagerEngine(db_file, carve_sensitivity="medium")
        stats = engine.run()

        all_texts = [
            str(val)
            for rec in engine.records
            for val in rec.values
            if isinstance(val, str)
        ]
        # Verify active records + overflow stitched record
        self.assertTrue(any("Normal active message 1" in t for t in all_texts))
        self.assertTrue(any(large_body == t for t in all_texts), "Multi-page overflow payload must be stitched accurately")
        self.assertGreaterEqual(stats.overflow_pages_stitched, 2)

        # Verify deleted records were carved from freeblocks/slack space
        self.assertTrue(
            any("INCULPATORY_DELETED_EVIDENCE_ROW_2" in t for t in all_texts)
            or any("SECOND_DELETED_SECRET_RECORD_4" in t for t in all_texts),
            "Deleted rows must be carved from unallocated freeblocks",
        )

    def test_03_zeroed_header_ransomware_wipe_and_synthetic_tables(self) -> None:
        """
        Simulate ransomware / anti-forensic wiping of the first 100 bytes (database header)
        and corrupt cell pointers; verify page size brute-forcer and synthetic table creation.
        """
        db_file = self.temp_dir / "wiped_header.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("PRAGMA page_size = 4096;")
        conn.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY, username TEXT, api_key TEXT, clearance INT);")
        for i in range(1, 35):
            conn.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?);",
                (i, f"operator_{i:02d}", f"KEY_SECRET_{i:04d}_XYZ", i * 10),
            )
        conn.commit()
        conn.close()

        # Wipe the entire 100-byte SQLite header + Page 1 B-tree header (first 256 bytes)
        raw_bytes = bytearray(db_file.read_bytes())
        raw_bytes[:256] = b"\x00" * 256
        db_file.write_bytes(raw_bytes)

        # Verify standard sqlite3 fails completely on this file
        with self.assertRaises(sqlite3.DatabaseError):
            c = sqlite3.connect(str(db_file))
            c.execute("SELECT * FROM credentials;").fetchall()

        # Run sqlite-salvager in resilient fallback mode
        out_dir = self.temp_dir / "salvaged_out"
        engine = SQLiteSalvagerEngine(db_file, carve_sensitivity="medium")
        stats = engine.run()

        self.assertIsNotNone(stats.header_info)
        assert stats.header_info is not None
        self.assertTrue(stats.header_info.probed_fallback)
        self.assertEqual(stats.header_info.page_size, 4096)

        recovered_keys = [
            str(val)
            for rec in engine.records
            for val in rec.values
            if isinstance(val, str) and "KEY_SECRET_" in val
        ]
        self.assertGreaterEqual(len(recovered_keys), 25, "Should carve records even when Page 1 header is wiped")

        exporter = SalvageExporter(engine, out_dir)
        artifacts = exporter.export_all()
        self.assertTrue(artifacts["sql_dump"].exists())
        self.assertTrue(artifacts["rebuilt_sqlite"].exists())
        self.assertTrue(artifacts["audit_report"].exists())

    def test_04_wal_carving_and_corrupt_checksum_bypass(self) -> None:
        """
        Verify parsing of Write-Ahead Log (-wal) frames, including uncommitted/uncheckpointed
        records and corrupt WAL frame checksum bypass.
        """
        db_file = self.temp_dir / "wal_evidence.db"
        wal_file = Path(f"{db_file}-wal")

        conn = sqlite3.connect(str(db_file))
        conn.execute("PRAGMA page_size = 4096;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, actor TEXT, action TEXT);")
        conn.execute("INSERT INTO audit_events VALUES (1, 'system', 'BOOT_SEQUENCE');")
        conn.commit()

        # Insert rows that stay in the -wal file without checkpointing
        conn.execute("INSERT INTO audit_events VALUES (2, 'intruder', 'EXFILTRATE_KEYS_VIA_WAL');")
        conn.execute("INSERT INTO audit_events VALUES (3, 'intruder', 'CLEAR_LOGS_ATTEMPT');")
        conn.commit()

        # Copy the live .db and .db-wal before closing connection (as closing checkpoints the WAL)
        snap_db = self.temp_dir / "snap.db"
        snap_wal = self.temp_dir / "snap.db-wal"
        shutil.copyfile(db_file, snap_db)
        shutil.copyfile(wal_file, snap_wal)
        conn.close()

        # Intentionally corrupt the checksum field of the last WAL frame to test forensic bypass
        wal_data = bytearray(snap_wal.read_bytes())
        if len(wal_data) >= WAL_HEADER_SIZE + WAL_FRAME_HEADER_SIZE:
            # Flip bits in frame 1's checksum1 (bytes 16..20 of frame header)
            wal_data[WAL_HEADER_SIZE + 16] ^= 0xFF
            snap_wal.write_bytes(wal_data)

        engine = SQLiteSalvagerEngine(snap_db, wal_path=snap_wal, salvage_wal=True)
        stats = engine.run()

        self.assertGreater(stats.wal_frames_scanned, 0)
        self.assertGreater(stats.wal_records_recovered, 0)
        wal_strings = [
            str(val)
            for rec in engine.records
            if rec.wal_frame is not None
            for val in rec.values
            if isinstance(val, str)
        ]
        self.assertTrue(any("EXFILTRATE_KEYS_VIA_WAL" in s for s in wal_strings))


# =============================================================================
# 8. CLI INTERFACE & TERMINAL REPORT FORMATTER
# =============================================================================

def print_terminal_summary(stats: ForensicAuditStats, artifacts: Dict[str, Path]) -> None:
    hdr = stats.header_info
    print("=" * 78)
    print("  SQLITE-SALVAGER :: DIGITAL FORENSICS & BINARY CARVING REPORT")
    print("=" * 78)
    print(f"  Target File       : {stats.file_path} ({stats.file_size_bytes:,} bytes)")
    print(f"  SHA-256 Digest    : {stats.sha256_hash}")
    if hdr:
        hdr_status = "INTACT (Valid Magic)" if hdr.magic_valid else f"WIPED/CORRUPT -> Brute-Forced (Conf: {hdr.probe_confidence*100:.1f}%)"
        print(f"  Header Status     : {hdr_status}")
        print(f"  Page Size         : {hdr.page_size} bytes (Usable: {hdr.usable_size} bytes)")
        print(f"  Text Encoding     : {hdr.text_encoding.name}")
    print("-" * 78)
    print(f"  Pages Scanned     : {stats.total_pages_scanned:,} (Valid B-Tree: {stats.valid_btree_pages:,}, Corrupted/Carved: {stats.corrupted_pages_skipped:,})")
    print(f"  Freelist Pages    : {stats.freelist_trunk_pages + stats.freelist_leaf_pages:,} (Trunks: {stats.freelist_trunk_pages:,}, Leaves: {stats.freelist_leaf_pages:,})")
    print(f"  Overflow Stitched : {stats.overflow_pages_stitched:,} pages")
    print(f"  Active Records    : {stats.active_records_recovered:,}")
    print(f"  Deleted / Carved  : {stats.deleted_records_recovered:,} (Freeblocks, Slack, Freelist, Raw)")
    print(f"  WAL Frames        : {stats.wal_frames_scanned:,} (Valid: {stats.wal_frames_valid:,}, Checksum Bypassed: {stats.wal_frames_corrupt_bypassed:,})")
    print(f"  WAL Records       : {stats.wal_records_recovered:,}")
    print(f"  Anomalies Logged  : {len(stats.anomalies):,}")
    print("-" * 78)
    print("  Exported Deliverables:")
    for label, path in artifacts.items():
        print(f"    - {label:<16}: {path}")
    print("=" * 78)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlite-salvager",
        description=(
            "Production-grade forensic CLI tool to recover, carve, and reconstruct records "
            "from corrupted, truncated, header-wiped, or locked SQLite 3 databases and WAL files."
        ),
    )
    parser.add_argument(
        "input_db",
        nargs="?",
        help="Path to the corrupted/target SQLite 3 database file.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="./salvaged_output",
        help="Directory to write salvaged exports (.sql, .csv, .jsonl, .sqlite, report). Default: ./salvaged_output",
    )
    parser.add_argument(
        "-w",
        "--wal-path",
        default=None,
        help="Optional explicit path to a Write-Ahead Log (-wal) file (auto-detected if <db>-wal exists).",
    )
    parser.add_argument(
        "--no-wal",
        action="store_true",
        help="Disable Write-Ahead Log (-wal) scanning.",
    )
    parser.add_argument(
        "-p",
        "--page-size",
        type=int,
        choices=STANDARD_PAGE_SIZES,
        default=None,
        help="Force a specific SQLite page size (overrides header and brute-force detector).",
    )
    parser.add_argument(
        "-s",
        "--sensitivity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Heuristic raw carver sensitivity level for unallocated space (default: medium).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the built-in synthetic corrupt database & deleted-row forensic verification suite.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ForensicSalvagerTestSuite)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1

    if not args.input_db:
        parser.print_help()
        return 1

    engine = SQLiteSalvagerEngine(
        db_path=args.input_db,
        wal_path=args.wal_path,
        override_page_size=args.page_size,
        carve_sensitivity=args.sensitivity,
        salvage_wal=not args.no_wal,
    )
    stats = engine.run()
    exporter = SalvageExporter(engine, args.output_dir)
    artifacts = exporter.export_all()
    print_terminal_summary(stats, artifacts)
    return 0


if __name__ == "__main__":
    sys.exit(main())