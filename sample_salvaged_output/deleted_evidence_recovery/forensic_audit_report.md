# Forensic SQLite Salvage & Carving Audit Report

## 1. Evidence Overview
- **Source File**: `/tmp/salvager_pkg_lqyr_g1t/sqlite-salvager/samples/corrupted_deleted_evidence.db`
- **File Size**: `4,096` bytes
- **SHA-256 Digest**: `f3aee9f5def1f559465aed72f2d9797dc7fe8ad24003e5ddbceefe96ba9a70c6`
- **Header Magic Valid**: `True`
- **Fallback Brute-Force Probed**: `False` (Confidence: `100.0%`)
- **Page Size**: `1024` bytes (Usable: `1024` bytes)
- **Text Encoding**: `UTF8` (`1`)
- **First Freelist Trunk Page**: `0` (Total Freelist Pages: `0`)

## 2. Recovery & Carving Telemetry
| Metric | Count |
| :--- | ---: |
| Total Pages Scanned | 4 |
| Valid B-Tree Pages | 2 |
| Corrupted / Wiped Pages Carved | 2 |
| Freelist Trunk Pages | 0 |
| Freelist Leaf Pages | 0 |
| Overflow Pages Stitched | 2 |
| Active Leaf Records Recovered | 3 |
| Deleted / Unallocated Records Carved | 1 |
| WAL Frames Scanned | 0 |
| WAL Frames Verified (Valid Checksum) | 0 |
| WAL Frames Bypassed (Corrupt Checksum) | 0 |
| WAL Records Recovered | 0 |
| **Total Records Salvaged** | **4** |

## 3. Reconstructed & Synthesized Tables
| Table Name | Root Page | Mode | Columns | Salvaged Rows |
| :--- | ---: | :--- | :--- | ---: |
| `forensic_messages` | 2 | DDL Reconstructed | `id, sender, message, token` | 3 |

## 4. Anomaly & Corruption Log (Hex Offsets)
| Byte Offset (Hex) | Page # | Category | Description | Hex Preview |
| :--- | ---: | :--- | :--- | :--- |
| `0x00000800` | 3 | `INVALID_BTREE_FLAG` | Page 3 has unrecognized B-Tree flag 0x00. Running heuristic raw carver. | `00000004585858585858585858585858` |
| `0x00000C00` | 4 | `INVALID_BTREE_FLAG` | Page 4 has unrecognized B-Tree flag 0x00. Running heuristic raw carver. | `00000000585858585858585858585858` |
