<div align="center">

  # sqlite-salvager
  ### Digital Forensics & Incident Response (DFIR) SQLite 3 Low-Level Binary Carver & Database Recovery Engine

  [![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
  [![Zero External Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-brightgreen)](#-arsitektur--zero-dependency)
  [![DFIR Artifacts](https://img.shields.io/badge/Carving-Freelist%20%7C%20Freeblocks%20%7C%20WAL-red)](#-kemampuan-forensik)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#-panduan-penggunaan-cli)

  <p align="center">
    <a href="#-ringkasan-proyek">Ringkasan</a> •
    <a href="#-masalah-lapangan-vs-solusi-biner">Masalah vs Solusi</a> •
    <a href="#-kemampuan-forensik">Fitur Forensik</a> •
    <a href="#-arsitektur--spesifikasi-biner">Spesifikasi Biner</a> •
    <a href="#-panduan-penggunaan-cli">Panduan CLI</a> •
    <a href="#-struktur-direktori">Struktur Repo</a> •
    <a href="#-format-hasil-ekspor">Format Ekspor</a>
  </p>

</div>

---

## 📌 Ringkasan Proyek

**`sqlite-salvager`** adalah perkakas investigasi forensik digital (DFIR) dan *low-level binary stream parser* berkinerja tinggi yang dirancang khusus untuk memulihkan, merekonstruksi (*salvage*), dan melakukan *file carving* terhadap basis data **SQLite 3** yang mengalami kerusakan fatal (*malformed database*), terpotong (*truncated*), terkunci (*locked*), maupun terkena serangan ransomware (penghapusan header 100-byte / *zeroed-header*).

Berbeda dari driver SQLite konvensional yang langsung gagal (*throw disk image is malformed exception*), tool ini membongkar byte stream fisik secara langsung (*out-of-band byte parsing*) menggunakan algoritma penelusuran struktur B-Tree, decoding Varint internal, serta pemindaian heuristik pada area data yang tidak dialokasikan (*unallocated slack space*).

---

## ⚡ Masalah Lapangan vs Solusi Biner

| Skenario Kerusakan | Respon Driver Konvensional (`sqlite3` / GUI) | Pendekatan `sqlite-salvager` (Low-Level Carver) |
|---|---|---|
| **Header 100-byte Rusak / Terhapus Ransomware** | Menolak file: `file is not a database` | **Auto-Probing Brute-Force:** Memindai ukuran page standar (512–65536 byte) berdasarkan pola valid B-Tree flag. |
| **Record Dihapus Pengguna / Pelaku Kejahatan** | Mengabaikan data (dianggap kosong via SQL query) | **Slack & Freelist Scraper:** Memindai Freelist leaf/trunk, cell gap, dan freeblock untuk merekonstruksi record terhapus. |
| **Transaksi Belum Tersimpan / Crash** | Mengabaikan WAL atau gagal membuka database | **WAL Journal Rebuilder:** Membaca header 32-byte WAL dan membedah frame 24-byte untuk mengambil transaksi terbaru. |
| **Kerusakan Halaman Skema (Page 1 Korup)** | Gagal memetakan tabel sama sekali | **Synthetic Schema Auto-Grouper:** Mengelompokkan record berdasarkan kemiripan *serial type signature* menjadi tabel sintesis. |

---

## 🔍 Kemampuan Forensik

```text
       ┌─────────────────────────────────────────────────────────┐
       │             SQLite 3 Physical File Stream               │
       └────────────────────────────┬────────────────────────────┘
                                    │
     ┌──────────────────────────────┼────────────────────────────┐
     ▼                              ▼                            ▼
[ 100-Byte Header ]        [ B-Tree Pages ]             [ Unallocated / Freelist ]
 • Resilient Auto-Probe     • Flag Identifiers (0x0D,   • Deleted Rows Carving
 • Page Size Extraction       0x05, 0x0A, 0x02)         • Freeblock List Walk
 • Encoding Autodetect      • Pointer Array Validation  • Gap Slack Extraction
                            • Dynamic Varint Decoder    • Heuristic Signature Scan
```

* **Zero-Dependency Architecture:** Murni dibangun di atas pustaka standar Python (`struct`, `mmap`, `dataclasses`, `os`, `sys`). Tidak memerlukan kompilasi C++ eksternal atau dependensi pihak ketiga.
* **Memory-Mapped I/O (`mmap`):** Pemrosesan streaming efisien untuk menangani basis data berukuran gigabyte tanpa risiko kehabisan memori (*RAM exhaustion*).
* **Fault-Tolerant Boundary Checker:** Setiap pointer sel divalidasi ketat terhadap batas halaman. Jika sel korup ditemukan, engine akan melewatinya secara terisolasi tanpa menghentikan proses *carving*.
* **Deep Serial-Type Unpacker:** Mendukung decoding tipe data SQLite penuh: NULL, Integer (8/16/24/32/48/64-bit), IEEE 754 Floating Point, Konstanta 0/1, string UTF-8/UTF-16, dan BLOB biner.

---

## ⚙️ Arsitektur & Spesifikasi Biner

Tool ini mengimplementasikan spesifikasi internal SQLite format 3 secara presisi:

1. **B-Tree Page Type Decoding:**
   * `0x0D`: *Leaf Table B-Tree* (Penyimpanan data payload aktual).
   * `0x05`: *Interior Table B-Tree* (Navigasi penunjuk halaman anak).
   * `0x0A`: *Leaf Index B-Tree*.
   * `0x02`: *Interior Index B-Tree*.
2. **Varint Decoder Engine:**
   * Mendekode integer panjang variabel (1 hingga 9 byte) berbasis bitwise shifting untuk mengekstrak `payload_size`, `rowid`, dan *record header length*.
3. **Payload Overflow Stitching:**
   * Melacak pointer halaman *overflow* jika panjang string/BLOB melebihi kapasitas lokal dalam satu sel.
4. **Forensic Heuristic Scanning (`--sensitivity`):**
   * **Normal:** Memindai tabel aktif dan area freelist terdaftar.
   * **High:** Memindai seluruh raw byte yang tidak dialokasikan di dalam file untuk mencari pola header serial-type record yang masih utuh.

---

## 🚀 Panduan Penggunaan (CLI)

### 1. Menjalankan Unit Test Mandiri (Self-Test Simulation)
Verifikasi seluruh fungsionalitas parser dan engine rekonstruksi menggunakan basis data sintetis yang sengaja dirusak:

* **Linux / macOS:**
  ```bash
  python3 sqlite_salvager.py --self-test
  # Atau gunakan launcher shell:
  chmod +x run_self_test.sh && ./run_self_test.sh
  ```
* **Windows:**
  ```cmd
  python sqlite_salvager.py --self-test
  :: Atau klik ganda run_self_test.bat
  ```

---

### 2. Memulihkan Database Korup & Record yang Dihapus
Ekstrak seluruh baris aktif dan artefak data yang telah dihapus ke direktori tujuan:

```bash
python3 sqlite_salvager.py samples/corrupted_deleted_evidence.db -o ./hasil_recovery
```

---

### 3. Memulihkan Database dengan Header Terhapus (Ransomware Artifact)
Gunakan mode sensitivitas tinggi (`--sensitivity high`) agar engine mem-brute force ukuran halaman dan menyisir seluruh slack space:

```bash
python3 sqlite_salvager.py samples/wiped_header_ransomware.db -o ./hasil_wiped --sensitivity high
```

---

### 4. Argumen CLI Lengkap

```text
usage: sqlite_salvager.py [-h] [-o OUTPUT_DIR] [--page-size PAGE_SIZE]
                          [--sensitivity {normal,high}] [--ignore-wal]
                          [--self-test] [input_path]

Positional Arguments:
  input_path                    Path menuju file database SQLite (.db, .sqlite, .bin)

Optional Arguments:
  -h, --help                    Menampilkan pesan bantuan dan keluar
  -o, --output-dir OUTPUT_DIR   Direktori penyimpanan hasil rekonstruksi (Default: ./salvaged_output)
  --page-size PAGE_SIZE         Paksa ukuran halaman secara manual (512, 1024, 2048, 4096, dst.)
  --sensitivity {normal,high}   Tingkat sensitivitas carving (Normal: B-Tree & Freelist, High: Full Slack Carving)
  --ignore-wal                  Abaikan file Write-Ahead Log (-wal) yang berdampingan
  --self-test                   Jalankan verifikasi mandiri dan simulasi database korup
```

---

## 📂 Struktur Direktori

```plaintext
sqlite-salvager/
├── sqlite_salvager.py          # Engine inti (Zero-dependency low-level binary carver)
├── README.md                   # Dokumentasi teknis & panduan investigasi
├── run_self_test.bat           # Launcher automasi 1-klik untuk Windows
├── run_self_test.sh            # Launcher executable untuk Linux/macOS
│
├── samples/                    # Sampel artefak uji coba forensik
│   ├── corrupted_deleted_evidence.db # DB rusak parsial dengan data terhapus
│   └── wiped_header_ransomware.db   # DB dengan header 100-byte terhapus/zeroed
│
└── sample_salvaged_output/     # Contoh artefak hasil pemulihan
    ├── recovered_database.sqlite     # Basis data bersih yang berhasil dibangun ulang
    ├── dump_recovered.sql            # Dump query SQL (CREATE TABLE & INSERT)
    ├── forensic_audit_report.md      # Laporan ringkasan audit integritas biner
    ├── export_csv/                   # Ekspor data per tabel format .csv
    └── export_jsonl/                 # Streaming normalized data format .jsonl
```

---

## 📊 Format Hasil Ekspor

Setiap sesi *salvage* menghasilkan laporan dan artefak komprehensif:

1. **`recovered_database.sqlite`:** File basis data SQLite murni yang sudah bersih, konsisten, dan dapat dibuka menggunakan SQLite browser standar.
2. **`dump_recovered.sql`:** Skrip SQL terstruktur yang berisi DDL dan *INSERT statements* dari data yang berhasil diselamatkan.
3. **`export_csv/` & `export_jsonl/`:** Ekspor tabular yang siap diintegrasikan ke pipeline *data science* atau alat analisis forensik lain (Autopsy, FTK, dsb).
4. **`forensic_audit_report.md`:** Ringkasan audit investigasi yang mencatat:
   * Total halaman fisik yang dipindai vs halaman rusak yang dilewati.
   * Jumlah record aktif vs record terhapus (*freelist/slack*) yang diselamatkan.
   * Log transaksi *Write-Ahead Log* (-wal) yang direkonstruksi.
   * Peta offset heksadesimal dari anomali data.

---

## ⚖️ Lisensi

Proyek ini didistribusikan di bawah lisensi **MIT**. Anda bebas menggunakan, memodifikasi, dan mengintegrasikan tool ini untuk kebutuhan operasional investigasi forensik, keamanan siber, maupun riset akademik.
