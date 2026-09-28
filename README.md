# Panel Deploy

Panel deploy otomatis berbasis Docker. Deploy aplikasi dari GitHub/GitLab langsung dari browser.

## Fitur

- Login Owner & Member
- Token multi-device (satu token bisa dipakai di HP/laptop/browser manapun)
- Auto deploy dari GitHub, GitLab, Bitbucket (public & private)
- Auto detect runtime: Node.js, Python, Go, Ruby, PHP, Java, Static
- Auto install dependencies (pip, npm, bundle, composer, go)
- Auto baca Procfile & app.json
- Live console log real-time
- File manager (lihat, edit, upload, download, rename, hapus)
- Preview gambar, video, audio, PDF di browser
- Auto expire container saat token habis
- Auto restart container kalau crash
- UI tema light dengan aksen emas

## Persyaratan

- Node.js minimal 22.5.0 (wajib karena pakai node:sqlite)
- Docker minimal 20.x
- OS Ubuntu 22.04 / Debian 12 (rekomendasi)
- RAM minimal 2 GB
- Storage minimal 20 GB

## Deploy di VPS

### 1. Login VPS

    ssh root@IP_VPS_KAMU

### 2. Install Docker & Node.js 22

    apt update && apt upgrade -y
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt install -y nodejs git curl screen
    curl -fsSL https://get.docker.com | sh

Cek versi:

    node -v
    docker --version

Pastikan Node.js v22.5.0 atau lebih tinggi.

### 3. Clone project

    cd /root
    git clone https://github.com/jokokendi/panel-deploy
    cd panel-deploy

### 4. Install dependencies

    npm install

### 5. Setup awal

    node setup.js

Isi pertanyaan:

- Nama web (branding) - contoh: DeployKu
- Port panel - tekan Enter untuk default 5000
- Username owner - bebas
- Password owner - bebas
- Lokasi database - tekan Enter untuk default ./data/paas.db

Simpan kredensial yang muncul.

### 6. Jalankan di screen

    screen -S panel
    node server.js

Server tetap jalan walau SSH ditutup.

### 7. Buka di browser

    http://IP_VPS_KAMU:5000

### 8. Buka firewall (kalau pakai UFW)

    ufw allow 22
    ufw allow 5000
    ufw enable

## Perintah Screen

Lihat daftar screen:

    screen -ls

Balik ke panel:

    screen -r panel

Detach (keluar tapi tetap jalan):

    Ctrl + A, lalu D

Matikan screen:

    screen -r panel
    Ctrl + C

Hapus screen mati:

    screen -wipe

## Cara Pakai Panel

### Owner

1. Login dengan username dan password owner
2. Atur durasi token (contoh 7 hari)
3. Klik + Token
4. Klik Salin dan kirim ke user

### Member

1. Login pakai token PAAS-XXXXXX
2. Buka tab Startup
3. Isi Git Repo URL (contoh https://github.com/user/repo)
4. Isi GitHub token kalau repo private (opsional)
5. Repository wajib ada app.json dan Procfile
6. Klik Scan Repository
7. Isi environment variables kalau ada
8. Klik Deploy Server
9. Buka tab Console untuk lihat log real-time
9. Klik Buka Web kalau URL muncul

## Struktur Project

    panel-deploy/
    ├── .env                 konfigurasi (jangan commit)
    ├── .gitignore
    ├── package.json
    ├── server.js            backend express
    ├── setup.js             wizard setup
    ├── README.md
    ├── data/
    │   └── paas.db          database sqlite (auto-generated)
    └── public/
        └── index.html       frontend panel

## Update Panel

    screen -r panel
    Ctrl + C
    git pull
    npm install
    node server.js
    Ctrl + A, lalu D

## Perintah Berguna

Lihat semua container user:

    docker ps

Hapus container yang nyangkut:

    docker rm -f app-paas_xxxxx

Lihat semua volume:

    docker volume ls

Bersihkan container yang gak dipakai:

    docker system prune -a

## Troubleshooting

### Server tidak bisa dibuka

    screen -r panel
    ufw status

Cek port 5000 sudah dibuka di firewall.

### Cannot find module 'node:sqlite'

Node.js di bawah versi 22.5.0. Update:

    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt install -y nodejs
    node -v

### Docker permission denied

    usermod -aG docker $USER
    newgrp docker

### Container user tidak mau jalan

    docker logs app-paas_xxxxx

Ganti app-paas_xxxxx dengan nama container dari docker ps.

### File Manager error "Volume belum dibuat"

User harus deploy dulu minimal sekali sebelum file manager aktif.

## Backup & Restore

Backup database:

    cp data/paas.db data/paas.db.backup-$(date +%Y%m%d)

Restore:

    screen -r panel
    Ctrl + C
    cp data/paas.db.backup-20250101 data/paas.db
    node server.js
    Ctrl + A, lalu D

## Keamanan

- Password owner di-hash dengan bcrypt cost 12
- JWT expired 4 jam untuk owner, 12 jam untuk member
- Rate limit login 5x per 15 menit
- Rate limit deploy 5x per 10 menit
- GitHub token tidak disimpan di database
- Path traversal dicegah di file manager
- Environment variable terlarang diblokir (JWT_SECRET, OWNER_HASH, dll)

Tips:

- Jangan commit file .env ke Git
- Pakai password owner yang kuat
- Pasang SSL kalau akses dari internet
- Backup data/paas.db secara berkala

## Lisensi

MIT License

## Developer

pySmartDL

Telegram: https://t.me/pySmartDL
