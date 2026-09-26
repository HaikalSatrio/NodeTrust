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

## 2. Urutan review (ikuti dependensi di backlog)

Semua task Brian sudah dibangun lebih awal dari jadwalnya, jadi review dan Done harus mengikuti urutan
dependensi, bukan nomor task. Sebuah task baru bisa Done setelah semua dependensinya Done.

| Urutan | Task | Butuh Done dulu | Catatan |
|---|---|---|---|
| 1 | **NT-040** (Brian) | – | Workflow kontributor, quality gate |
| 2 | **NT-002** (Brian) | NT-001 ✅, NT-040 | Checklist di bawah |
| 3 | **NT-003** (kamu) | NT-001 ✅ | Kontrak di `contracts/` masih draf stand-in dari Brian. Banyak task Brian menunggu ini. |
| 4 | NT-006, NT-017 (Brian) | NT-002, NT-003 | |
| 5 | NT-007 (Brian) | NT-006 | |
| 6 | Seterusnya sesuai kolom Dependensi dan Jadwal | | Task yang bergantung pada NT-005/008/012/013/015/021 (kamu) menunggu task itu |

Di luar urutan itu, bagian yang sensitif secara keamanan (`api/auth.py`, `sbom/`, `alerts/`, `nodetrust-ci`)
tetap perlu audit independen di NT-041. Self-review ada di `docs/audit/NT-040-audit.md` §6–§7.

### Checklist review NT-002 (dari kolom "Review Manusia": setup dari mesin bersih, tidak ada secret)

1. Di mesinmu, clone kedua repo berdampingan, lalu ikuti `docs/setup.md` bagian "Local development" persis.
   `python scripts/check.py` harus PASS di kedua repo.
2. `cp .env.example .env`, isi `NODETRUST_ADMIN_TOKEN` (32+ karakter) dan `NEO4J_PASSWORD`, lalu
   `docker compose up --build` dan `docker compose --profile neo4j up -d neo4j`. Kemudian
   `curl http://127.0.0.1:8080/readyz` dan `python scripts/check_neo4j.py` harus OK.
3. `python scripts/scan_history.py` dan `python scripts/scan_history.py ../nodetrust-ci`: tidak boleh ada FAIL.
   Nilai yang didaftar "for a human to judge" adalah nilai uji. Periksa sendiri untuk memastikan.
4. Catat jam yang kamu pakai untuk review ini di Jam Aktual.

## 3. Task Brian dan yang perlu kamu cek

| Kode | Usulan status | Cek saat review | Bukti | Masih terbuka |
|---|---|---|---|---|
| NT-040 | Review | Workflow kontributor (`CONTRIBUTING.md`), quality gate | `docs/audit/NT-040-audit.md`, `scripts/check.py` (lint + pin SHA action wajib) | Jam kalibrasi (manusia) |
| NT-002 | Review | Setup dari clone bersih, `docker compose up --build`, `--profile neo4j` | Semua kriteria terverifikasi: clean clone, build + run Docker, Neo4j healthy + `check_neo4j.py` OK, lint, tidak ada secret, image di-pin digest (`docs/audit/live-checks.md`) | Pemakaian Neo4j/GDS diputuskan di NT-013 |
| NT-006 | Review | Checkpoint, replay setelah crash, start pertama dari head | `tests/test_ingest.py`; uji live ke npm (`docs/audit/live-checks.md`): bug `since=now` → 400 ditemukan dan diperbaiki | – |
| NT-007 | Review | Normalisasi packument | 1.024 packument asli dari cache lokal: 0 crash; uji live 14 packument dari registry npm: 0 gagal | – |
| NT-009 | Review | Diff antarversi, kasus integrity | Perbaikan performa: `react` 595 s → 1,1 s, delta identik pada 6.448 versi asli | – |
| NT-010 | Review | **Bobot `rules-v1`** | Distribusi tier pada 291.040 versi asli | Keputusan bobot, lihat observasi di `real-data-check.md` |
| NT-011 | Review | Range, alias, withdrawn, `MAL-*`, volume data asli | `tests/test_osv.py`, `tests/test_scale.py`; import `all.zip` asli 229.416 record dalam 75 s, OSV API live, paginasi | Observasi ua-parser-js (GHSA, bukan MAL) untuk review D04 |
| NT-017 | Review | Isolasi project, role, revoke, throttle | `tests/test_api.py`, `test_hardening.py` | – |
| NT-018 | Review | Validasi SBOM, batas fetch | `tests/test_sbom.py`, `test_hardening.py` | – |
| NT-019 | Review | Overlay, choke point, unknown ≠ aman | `exposure/report.py` + tes | Bergantung stand-in NT-012/013 |
| NT-020 | Review | Identitas commit, tanpa duplikat | `exposure/drift.py` + tes | – |
| NT-022 | Review | Skenario NT-001 | `tests/test_policy.py` (D05 opsi 1) | Definisi eskalasi lintas ≥2 project |
| NT-023 | Review | Dedup, retry, triage, **TLS SMTP** | `tests/test_smtp.py` (percakapan SMTP/STARTTLS asli di loopback) | Uji ke penyedia email asli; port 465 belum didukung |
| NT-024 | In Progress | `action.yml`, exit code, jalur Syft | Step action dijalankan di `ubuntu:24.04` (lockfile + Syft 1.52.0): 2 bug Syft diperbaiki, checksum salah ditolak, verdict kedua jalur sama; SHA action di-pin | **Run di runner GitHub asli di repo contoh** (perlu push ke GitHub) |
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

## 6. Yang masih terbuka di luar laptop

Verifikasi live yang sudah dijalankan ada di `docs/audit/live-checks.md`. Yang tersisa butuh kredensial
atau publikasi:

- Jalankan action di runner GitHub asli pada repo contoh (NT-024), perlu push ke GitHub.
- Kirim email ke relay asli (NT-023, opsional: acceptance terpenuhi dengan uji SMTP di loopback), perlu kredensial SMTP.

## 7. Setelah review

- Status → Done hanya oleh reviewer, setelah acceptance terbukti.
- Jam Aktual diisi dengan jam manusia yang sebenarnya (review/verifikasi), bukan estimasi.
- Temuan review dicatat sebagai commit baru di branch ini atau di branch per task (`CONTRIBUTING.md` aturan 5).
