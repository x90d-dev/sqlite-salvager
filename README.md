# sqlite-salvager — Digital Forensics (DFIR) SQLite 3 Binary Carver & Recovery Tool

`sqlite-salvager` adalah tool forensik digital (DFIR) dan low-level binary parser tanpa dependensi eksternal (zero-dependency) untuk mengekstrak, memulihkan (salvage), dan melakukan file carving pada database SQLite 3 yang rusak parah (corrupted), terpotong (truncated), terkunci, atau terkena penghapusan header (zeroed/wiped header), termasuk pemulihan baris yang telah dihapus (deleted records) di freelist, freeblock, slack space, serta jurnal Write-Ahead Log (-wal).

## Cara Penggunaan (CLI)

1. Menjalankan Unit Test & Simulasi Database Rusak (Self-Test):
   python3 sqlite_salvager.py --self-test
   (Atau klik ganda run_self_test.bat di Windows)

2. Memulihkan Database Rusak / Mengambil Data Terhapus:
   python3 sqlite_salvager.py samples/corrupted_deleted_evidence.db -o ./hasil_recovery

3. Memulihkan Database dengan Header Terhapus (Wiped Header) & Sensitivitas Tinggi:
   python3 sqlite_salvager.py samples/wiped_header_ransomware.db -o ./hasil_wiped --sensitivity high

## Struktur Isi Paket ZIP
- sqlite_salvager.py : Source code utama CLI tool (standalone, zero-dependency, siap produksi).
- README.md          : Dokumentasi arsitektur dan panduan penggunaan.
- run_self_test.bat  : Launcher Windows 1-klik untuk menjalankan unit test forensik.
- run_self_test.sh   : Launcher Linux/macOS untuk menjalankan unit test forensik.
- samples/           : Berisi 2 sampel database korup/terhapus untuk pengujian langsung.
- sample_salvaged_output/ : Contoh hasil ekspor (.sql, .csv, .jsonl, .sqlite, dan forensic_audit_report.md).
