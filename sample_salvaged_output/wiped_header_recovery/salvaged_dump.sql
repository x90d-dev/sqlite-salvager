-- =====================================================================
-- sqlite-salvager Forensic SQL Dump
-- Source File: /tmp/salvager_pkg_lqyr_g1t/sqlite-salvager/samples/wiped_header_ransomware.db
-- SHA-256:     f0c0f3ebf8211eb5a8f0be03487ee54001726293a18391baffe03bc6e8cba4ee
-- =====================================================================

PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

-- Table: vault_keys (Root Page: 2, Synthetic: False)
CREATE TABLE vault_keys (id INTEGER PRIMARY KEY, account TEXT, secret_key TEXT, clearance INT);

INSERT INTO "vault_keys" VALUES (1, 'vault_admin_01', 'SECRET_KEY_RECOVERY_0001_ABCDEF', 100); /* source=ACTIVE_LEAF page=2 offset=0x1FCB rowid=1 */
INSERT INTO "vault_keys" VALUES (2, 'vault_admin_02', 'SECRET_KEY_RECOVERY_0002_ABCDEF', 200); /* source=ACTIVE_LEAF page=2 offset=0x1F95 rowid=2 */
INSERT INTO "vault_keys" VALUES (3, 'vault_admin_03', 'SECRET_KEY_RECOVERY_0003_ABCDEF', 300); /* source=ACTIVE_LEAF page=2 offset=0x1F5F rowid=3 */
INSERT INTO "vault_keys" VALUES (4, 'vault_admin_04', 'SECRET_KEY_RECOVERY_0004_ABCDEF', 400); /* source=ACTIVE_LEAF page=2 offset=0x1F29 rowid=4 */
INSERT INTO "vault_keys" VALUES (5, 'vault_admin_05', 'SECRET_KEY_RECOVERY_0005_ABCDEF', 500); /* source=ACTIVE_LEAF page=2 offset=0x1EF3 rowid=5 */
INSERT INTO "vault_keys" VALUES (6, 'vault_admin_06', 'SECRET_KEY_RECOVERY_0006_ABCDEF', 600); /* source=ACTIVE_LEAF page=2 offset=0x1EBD rowid=6 */
INSERT INTO "vault_keys" VALUES (7, 'vault_admin_07', 'SECRET_KEY_RECOVERY_0007_ABCDEF', 700); /* source=ACTIVE_LEAF page=2 offset=0x1E87 rowid=7 */
INSERT INTO "vault_keys" VALUES (8, 'vault_admin_08', 'SECRET_KEY_RECOVERY_0008_ABCDEF', 800); /* source=ACTIVE_LEAF page=2 offset=0x1E51 rowid=8 */
INSERT INTO "vault_keys" VALUES (9, 'vault_admin_09', 'SECRET_KEY_RECOVERY_0009_ABCDEF', 900); /* source=ACTIVE_LEAF page=2 offset=0x1E1B rowid=9 */
INSERT INTO "vault_keys" VALUES (10, 'vault_admin_10', 'SECRET_KEY_RECOVERY_0010_ABCDEF', 1000); /* source=ACTIVE_LEAF page=2 offset=0x1DE5 rowid=10 */
INSERT INTO "vault_keys" VALUES (11, 'vault_admin_11', 'SECRET_KEY_RECOVERY_0011_ABCDEF', 1100); /* source=ACTIVE_LEAF page=2 offset=0x1DAF rowid=11 */
INSERT INTO "vault_keys" VALUES (12, 'vault_admin_12', 'SECRET_KEY_RECOVERY_0012_ABCDEF', 1200); /* source=ACTIVE_LEAF page=2 offset=0x1D79 rowid=12 */
INSERT INTO "vault_keys" VALUES (13, 'vault_admin_13', 'SECRET_KEY_RECOVERY_0013_ABCDEF', 1300); /* source=ACTIVE_LEAF page=2 offset=0x1D43 rowid=13 */
INSERT INTO "vault_keys" VALUES (14, 'vault_admin_14', 'SECRET_KEY_RECOVERY_0014_ABCDEF', 1400); /* source=ACTIVE_LEAF page=2 offset=0x1D0D rowid=14 */
INSERT INTO "vault_keys" VALUES (15, 'vault_admin_15', 'SECRET_KEY_RECOVERY_0015_ABCDEF', 1500); /* source=ACTIVE_LEAF page=2 offset=0x1CD7 rowid=15 */
INSERT INTO "vault_keys" VALUES (16, 'vault_admin_16', 'SECRET_KEY_RECOVERY_0016_ABCDEF', 1600); /* source=ACTIVE_LEAF page=2 offset=0x1CA1 rowid=16 */
INSERT INTO "vault_keys" VALUES (17, 'vault_admin_17', 'SECRET_KEY_RECOVERY_0017_ABCDEF', 1700); /* source=ACTIVE_LEAF page=2 offset=0x1C6B rowid=17 */
INSERT INTO "vault_keys" VALUES (18, 'vault_admin_18', 'SECRET_KEY_RECOVERY_0018_ABCDEF', 1800); /* source=ACTIVE_LEAF page=2 offset=0x1C35 rowid=18 */
INSERT INTO "vault_keys" VALUES (19, 'vault_admin_19', 'SECRET_KEY_RECOVERY_0019_ABCDEF', 1900); /* source=ACTIVE_LEAF page=2 offset=0x1BFF rowid=19 */
INSERT INTO "vault_keys" VALUES (20, 'vault_admin_20', 'SECRET_KEY_RECOVERY_0020_ABCDEF', 2000); /* source=ACTIVE_LEAF page=2 offset=0x1BC9 rowid=20 */
INSERT INTO "vault_keys" VALUES (21, 'vault_admin_21', 'SECRET_KEY_RECOVERY_0021_ABCDEF', 2100); /* source=ACTIVE_LEAF page=2 offset=0x1B93 rowid=21 */
INSERT INTO "vault_keys" VALUES (22, 'vault_admin_22', 'SECRET_KEY_RECOVERY_0022_ABCDEF', 2200); /* source=ACTIVE_LEAF page=2 offset=0x1B5D rowid=22 */
INSERT INTO "vault_keys" VALUES (23, 'vault_admin_23', 'SECRET_KEY_RECOVERY_0023_ABCDEF', 2300); /* source=ACTIVE_LEAF page=2 offset=0x1B27 rowid=23 */
INSERT INTO "vault_keys" VALUES (24, 'vault_admin_24', 'SECRET_KEY_RECOVERY_0024_ABCDEF', 2400); /* source=ACTIVE_LEAF page=2 offset=0x1AF1 rowid=24 */

COMMIT;
