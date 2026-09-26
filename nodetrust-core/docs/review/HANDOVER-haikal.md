# Handover review untuk Haikal: task MVP Brian

> Disiapkan 26 Sep 2026. Semua status di bawah adalah **usulan**.
> Sesuai Definition of Done, tidak ada yang Done sebelum kamu review. Jam Aktual sengaja kosong.

## 1. Cara mengambil dan menjalankan

```bash
# dua repo berdampingan dalam satu folder
git clone <nodetrust-core> && git clone <nodetrust-ci>
cd nodetrust-core && git switch brian/mvp-review
cd ../nodetrust-ci && git switch brian/mvp-review
cd ../nodetrust-core && pip install -e ".[dev]" && python scripts/check.py   # harus PASS
cd ../nodetrust-ci && python scripts/check.py                                # harus PASS
```

- `main` hanya berisi commit awal kosong. Semua pekerjaan ada di `brian/mvp-review`, jadi
  `git diff main..brian/mvp-review` = seluruh isi yang perlu direview.
- Bukti terakhir: core **155 tes**, e2e **8 tes** (termasuk step `action.yml` dijalankan dengan bash),
  ci **19 tes**. Semua offline, tanpa request keluar.
- Coba dashboard: `README.md` → "Quick start (offline demo)" (`nodetrust demo`, lalu `nodetrust serve`).

## 2. Urutan review yang disarankan

1. **Kontrak bersama** (`src/nodetrust/contracts/`, `docs/contracts.md`, exit code CI 0/1/2/3).
   Ini milikmu (NT-003). Drafnya ditulis Brian supaya task-nya bisa terintegrasi. Perubahan di sini harus
   dilakukan di dua repo sekaligus.
2. **NT-001 sudah Done**: D01–D07 disepakati 26 Sep 2026 (`docs/decisions/NT-001-brian-review.md`).
   D05 opsi 1 sudah diterapkan dan diuji. Aturan "eskalasi lintas ≥2 project" belum terdefinisi.
3. **Bagian yang sensitif secara keamanan**: `api/auth.py`, `sbom/`, `alerts/` (SMTP), `nodetrust-ci`
   (`action.yml`, client). Hasil self-review ada di `docs/audit/NT-040-audit.md` §6–§7.
   NT-041 (audit keamanan independen olehmu) tetap diperlukan.
4. **Stand-in di area kamu** (tabel §5). Pilih mana yang diganti dan mana yang dipertahankan.
5. Task Brian lainnya (tabel §3).

## 3. Task Brian dan yang perlu kamu cek

| Kode | Usulan status | Cek saat review | Bukti | Masih terbuka |
|---|---|---|---|---|
| NT-040 | Review | Workflow kontributor (`CONTRIBUTING.md`), quality gate | `docs/audit/NT-040-audit.md`, `scripts/check.py` | Jam kalibrasi (manusia) |
| NT-002 | In Progress | Setup dari clone bersih di mesinmu | Uji clean clone + venv baru + `pip install .`, `docker compose config` valid | **Build image Docker** (butuh jaringan), keputusan Neo4j (NT-013) |
| NT-006 | Review | Checkpoint, replay setelah crash | `tests/test_ingest.py` | **Endpoint change-feed npm asli** (butuh jaringan) |
| NT-007 | Review | Normalisasi packument | + 1.024 packument npm **asli** dari cache lokal: 0 crash (`docs/audit/real-data-check.md`) | Fetch langsung dari registry (jaringan) |
| NT-009 | Review | Diff antarversi, kasus integrity | Perbaikan performa: `react` 595 s → 1,1 s, delta identik pada 6.448 versi asli | – |
| NT-010 | Review | **Bobot `rules-v1`** | Distribusi tier pada 291.040 versi asli | Keputusan bobot, lihat observasi di `real-data-check.md` |
| NT-011 | Review | Range, alias, withdrawn, `MAL-*` | `tests/test_osv.py` | Import `all.zip` / OSV API asli (jaringan) |
| NT-017 | Review | Isolasi project, role, revoke, throttle | `tests/test_api.py`, `test_hardening.py` | – |
| NT-018 | Review | Validasi SBOM, batas fetch | `tests/test_sbom.py`, `test_hardening.py` | – |
| NT-019 | Review | Overlay, choke point, unknown ≠ aman | `exposure/report.py` + tes | Bergantung stand-in NT-012/013 |
| NT-020 | Review | Identitas commit, tanpa duplikat | `exposure/drift.py` + tes | – |
| NT-022 | Review | Skenario NT-001 | `tests/test_policy.py` (D05 opsi 1) | Definisi eskalasi lintas ≥2 project |
| NT-023 | Review | Dedup, retry, triage, **TLS SMTP** | `tests/test_smtp.py` (percakapan SMTP/STARTTLS asli di loopback) | Uji ke penyedia email asli; port 465 belum didukung |
| NT-024 | In Progress | `action.yml`, exit code | + step Submit dijalankan dengan bash, output `GITHUB_OUTPUT` diuji | **Runner GitHub asli**, jalur Syft (jaringan) |
| NT-025 | Review | Tanpa LKG = tanpa pin; patch hanya draf | `lkg/` + tes | Estimasi ulang (scope berubah karena D01) |
| NT-026 | Review | Coba dengan keyboard dan screen reader | Walkthrough keyboard otomatis: 0 isu setelah perbaikan | Screen reader dan graph besar (manusia) |
| NT-029 | In Progress | Docs Inggris | README ×2, `docs/` | Lisensi, paket rilis (NT-028/044) |
| NT-042 | Review | Backup/restore, runbook | `tests/test_ops.py`, `docs/runbook.md` | Periode retensi |

## 4. Keputusan yang butuh kalian berdua

1. D05: opsi 1 sudah diterapkan. Yang belum: definisi "eskalasi lintas ≥2 project" (siapa yang dieskalasi,
   dan apakah itu mengubah keputusan build).
2. Kode exit CI, lisensi (usul Apache-2.0), periode retensi. Ini di luar tabel NT-001.
3. Teks acceptance NT-024 di backlog perlu disesuaikan dengan D01 (lockfile default, Syft opsional).
4. NT-010, dari data asli: pindah nama paket yang sah terlihat seperti takeover, dan base version untuk
   prerelease/canary kadang diambil dari lini rilis lain. Detail ada di `docs/audit/real-data-check.md`.

## 5. Stand-in di area kamu

| Task | Stand-in | Catatan |
|---|---|---|
| NT-003 kontrak | `contracts/`, `docs/contracts.md` | Draf, belum disepakati |
| NT-004/008 graph store | `graph/store.py` (SQLite) | Idempotent + riwayat integrity |
| NT-005 resolver | `semver.py` | Semver + range npm, belum resolusi lockfile penuh |
| NT-012 reverse BFS | `graph/blast.py` | Hop, jalur, siklus, truncation |
| NT-013 centrality | `graph/centrality.py` | networkx + choke point |
| NT-015 forecast | `forecast/` | **Heuristik, `validated: false`**, bukan hasil riset |
| NT-021 matching | `exposure/matching.py` | Versi exact + UNKNOWN |
| NT-027 demo | `nodetrust demo`, `fixtures/demo` | Data sintetis `ntdemo-*`. Setelah D05 opsi 1, `demo-exposed` berakhir `gate` (project kecil). Untuk memperlihatkan alur approval perlu project sintetis ≥ 200 versi. |

Tidak disentuh: NT-014/016 (riset butuh sumber asli), NT-028/041/043/044, NT-031..039.

## 6. Yang tidak bisa dikerjakan offline

Semuanya butuh akses jaringan dan belum dijalankan. Sebaiknya dikerjakan saat review, dengan persetujuan
kalian berdua:

- Verifikasi endpoint change-feed dan packument npm (NT-006/007).
- Import OSV asli (NT-011).
- Kirim email ke relay asli (NT-023).
- `docker compose up --build` (NT-002).
- Jalankan action di runner GitHub asli, lalu pin `uses:` ke SHA lengkap (NT-024/044).
- Jalur Syft dengan versi dan sha256 resmi (NT-024).

## 7. Setelah review

- Status → Done hanya oleh reviewer, setelah acceptance terbukti.
- Jam Aktual diisi dengan jam manusia yang sebenarnya (review/verifikasi), bukan estimasi.
- Temuan review dicatat sebagai commit baru di branch ini atau di branch per task (`CONTRIBUTING.md` aturan 5).
