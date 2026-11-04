# Forensic SQLite Salvage & Carving Audit Report

## 1. Evidence Overview
- **Source File**: `/tmp/salvager_pkg_lqyr_g1t/sqlite-salvager/samples/wiped_header_ransomware.db`
- **File Size**: `8,192` bytes
- **SHA-256 Digest**: `f0c0f3ebf8211eb5a8f0be03487ee54001726293a18391baffe03bc6e8cba4ee`
- **Header Magic Valid**: `False`
- **Fallback Brute-Force Probed**: `True` (Confidence: `58.0%`)
- **Page Size**: `4096` bytes (Usable: `4096` bytes)
- **Text Encoding**: `UTF8` (`1`)
- **First Freelist Trunk Page**: `0` (Total Freelist Pages: `0`)

## 2. Recovery & Carving Telemetry
| Metric | Count |
| :--- | ---: |
| Total Pages Scanned | 2 |
| Valid B-Tree Pages | 1 |
| Corrupted / Wiped Pages Carved | 1 |
| Freelist Trunk Pages | 0 |
| Freelist Leaf Pages | 0 |
| Overflow Pages Stitched | 0 |
| Active Leaf Records Recovered | 24 |
| Deleted / Unallocated Records Carved | 1 |
| WAL Frames Scanned | 0 |
| WAL Frames Verified (Valid Checksum) | 0 |
| WAL Frames Bypassed (Corrupt Checksum) | 0 |
| WAL Records Recovered | 0 |
| **Total Records Salvaged** | **25** |

## 3. Reconstructed & Synthesized Tables
| Table Name | Root Page | Mode | Columns | Salvaged Rows |
| :--- | ---: | :--- | :--- | ---: |
| `vault_keys` | 2 | DDL Reconstructed | `id, account, secret_key, clearance` | 24 |

## 4. Anomaly & Corruption Log (Hex Offsets)
| Byte Offset (Hex) | Page # | Category | Description | Hex Preview |
| :--- | ---: | :--- | :--- | :--- |
| `0x00000000` | 1 | `CORRUPT_DATABASE_HEADER` | 100-byte header magic/fields corrupted or wiped (magic_ok=False, raw_page_size=0). Activating brute-force page prober. | `00000000000000000000000000000000` |
| `0x00000000` | 1 | `INVALID_BTREE_FLAG` | Page 1 has unrecognized B-Tree flag 0x00. Running heuristic raw carver. | `00000000000000000000000000000000` |
