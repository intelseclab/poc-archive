# Authorized use

This repository is a restricted local cyber range for security research,
remediation validation, and education.

Run the reproducer only against the included loopback-bound Docker labs. The
released PoC accepts only the fixed loopback host forms and the port declared
by the selected exact profile, does not accept an arbitrary command, and
interacts with the target only through the lab's declared network interface.
The RCE profiles execute only the fixed benign `id` command. The worker
profiles return a fresh random token plus stdout to an allowlisted callback;
the Express profile returns stdout on its loopback request socket. None accepts
caller-supplied shell input.
Container setup and exact image identity verification are separate operator
actions.

The Docker callback example binds the listener to `0.0.0.0` only when the
operator requests it explicitly so the isolated lab can reach the host. Keep
that listener behind a local firewall, do not forward its port, and prefer the
default `127.0.0.1` listener for a native same-host lab.

Do not use this material to access or disrupt third-party systems, acquire
third-party data or credentials, establish persistence, evade controls, or
perform any activity without explicit authorization.

`profiles.json` identifies exact builds, preserves research provenance, and
keeps compatibility claims reproducible. A profile entry is not authorization
to test another system.

## Penggunaan berizin

Repositori ini adalah laboratorium siber lokal terbatas untuk riset keamanan,
validasi perbaikan, dan pendidikan.

Jalankan reproducer hanya terhadap laboratorium loopback yang disertakan.
Klien membatasi target ke bentuk alamat loopback tetap dan port yang dinyatakan
oleh profil tepat yang dipilih, menolak perintah arbitrer, dan hanya menjalankan
perintah `id` tetap untuk menghasilkan bukti baru berisi `uid=` dan `gid=`.
Profil worker memakai callback yang diizinkan, sedangkan profil Express
mengembalikan stdout lewat socket request loopback. Opsi listener `0.0.0.0`
hanya untuk koneksi balik dari container lokal; lindungi dengan firewall lokal
dan jangan teruskan port tersebut ke jaringan publik.

Jangan gunakan materi ini untuk mengakses atau mengganggu sistem pihak ketiga,
mengambil data atau kredensial pihak ketiga, membuat persistensi, menghindari
kontrol, atau melakukan aktivitas apa pun tanpa izin tertulis yang sesuai.

`profiles.json` dipertahankan untuk mengidentifikasi build secara tepat,
menjaga asal-usul bukti riset, dan membuat klaim kompatibilitas dapat
direproduksi. Entri profil bukan izin untuk menguji sistem lain.
