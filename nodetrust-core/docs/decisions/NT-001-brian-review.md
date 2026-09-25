# NT-001: Draf review Brian atas D01–D07

> **Status: DRAF untuk Brian.** Disusun saat mengimplementasikan task Brian, 25 Sep 2026.
> Belum menjadi review resmi. Brian perlu membaca, mengubah bila perlu, lalu mencatatnya di NT-001.
> Tidak ada keputusan yang dianggap disepakati.

Implementasi di `nodetrust-core` mengikuti draf D01–D07 apa adanya. Parameternya ditaruh di policy per project
yang terversi, jadi keputusan final cukup mengubah nilai tanpa menulis ulang kode. Catatan di bawah muncul
saat draf diterjemahkan ke kode dan tes.

| ID | Usulan posisi Brian | Catatan dari implementasi |
|---|---|---|
| D01 | Setuju, dengan 2 catatan | (a) CI client hanya mendukung `package-lock.json` v2/v3 (npm ≥ 7); v1 ditolak dengan pesan jelas. (b) Default action membuat SBOM dari lockfile, bukan Syft. Syft tetap tersedia, tetapi wajib versi + sha256 yang di-pin. Alasannya: tanpa jaringan, SHA/tag Syft tidak bisa diverifikasi, dan tool supply-chain sebaiknya tidak menarik binary yang tidak di-pin. Ini menyimpang dari teks acceptance NT-024 ("menjalankan Syft"), jadi **perlu disepakati**. |
| D02 | Setuju | Graph sementara memakai SQLite + networkx (stand-in) sampai Haikal memutuskan Neo4j/GDS di NT-002/013. Kontrak (NT-003) ditulis sebagai draf agar task Brian bisa terintegrasi, dan tetap milik Haikal. |
| D03 | Setuju | Diimplementasikan: WATCH tanpa email default, dengan opt-in `watch_email`. Kunci dedup = project + incident + evidence_version + (tier, decision, evidence status). Retry pengiriman tidak mengubah verdict. |
| D04 | Setuju dengan klarifikasi | (a) **"Coverage incomplete" perlu definisi presisi**, karena di enforce mode artinya build gagal. Implementasi saat ini: incomplete = SBOM tanpa relasi dari root, ADA komponen npm tanpa versi exact, atau komponen npm tidak terjangkau dari root. Komponen ekosistem lain (mis. `pkg:github`) dilaporkan out-of-scope dan tidak menurunkan kualitas. Package npm yang belum ada di graph tetap UNKNOWN di laporan, tetapi tidak membuat verdict incomplete (matching insiden hanya butuh versi exact). Mohon dikonfirmasi. (b) Advisory OSV kerentanan hanya informasi, tidak memengaruhi keputusan. (c) Laporan OSV `MAL-*` → incident UNVERIFIED skor 80 (INVESTIGATE). Nilai 80 adalah usulan. |
| D05 | **Usul revisi** | Dengan ambang 20%, hampir semua paparan di project kecil tergolong "besar". Contoh tes: 2 dari 3 versi = 66%. Akibatnya gate otomatis praktis tidak pernah terjadi di project kecil; alurnya selalu eskalasi/approval. Opsi: (1) terapkan ambang % hanya bila total ≥ N versi (mis. 200); (2) pakai ambang absolut saja; (3) biarkan, karena konservatif memang disengaja. Tes batas 99/100 dan 19/20 sudah lulus sesuai draf. |
| D06 | Setuju dengan definisi | (a) "Satu run" = `GITHUB_RUN_ID` + `GITHUB_RUN_ATTEMPT`. Re-run attempt dihitung run baru; retry di run yang sama boleh memakai override yang sama. (b) Override terikat project + commit + versi policy + *evidence fingerprint* (hash SBOM + versi bukti setiap insiden), maksimum 24 jam. (c) Mode snapshot/demo tidak dinilai stale, tetapi setiap verdict diberi label `offline_snapshot`. (d) PR dari fork tidak mendapat secret, sehingga key kosong = error konfigurasi (exit 2). Rekomendasi: workflow melewati job untuk fork (ada di contoh). |
| D07 | Setuju | Dua project fixture sintetis tersedia (`demo-exposed`, `demo-clean`) dengan data `ntdemo-*`. Insiden simulasi hanya berlaku di project yang mengaktifkan `include_simulations`, sehingga tidak bercampur dengan bukti nyata. Tidak ada klaim validasi forecast; output forecast berlabel `validated: false`. |

## Usulan tambahan untuk disepakati

1. **Kode exit CI**: 0 = pass/warn · 1 = gate/pending_approval · 2 = error konfigurasi (kedua mode) · 3 = assessment unavailable (enforce).
2. **Lisensi (NT-029)**: usul Apache-2.0 (ada patent grant, umum untuk tool keamanan). Keputusan tim.
3. **Retensi**: purge otomatis hanya untuk data operasional (fetch job selesai, file outbox). Scan, verdict, alert dan audit disimpan sampai periode retensinya disepakati.
4. **Skor**: bobot `rules-v1` adalah draf heuristik Brian dan perlu review Haikal.

## Checklist NT-001 (belum diubah)

- [ ] Brian mereview; hasilnya dicatat tanpa mengasumsikan persetujuan → **draf ini menunggu Brian**
- [ ] Keputusan final, tanggal dan pihak yang menyetujui dicatat
- [ ] Dampak ke scope/kontrak/kriteria/estimasi downstream diselaraskan
