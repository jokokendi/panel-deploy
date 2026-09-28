#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const FIXED_BASE_IMAGE = 'jokokendil/polyglot:latest';
const TELEGRAM_USER = 'pySmartDL';

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const C = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    cyan: '\x1b[36m'
};

function ask(question, defaultValue = '') {
    return new Promise(resolve => {
        const hint = defaultValue ?
            `${C.dim}[${defaultValue}]${C.reset}` :
            `${C.dim}[kosong]${C.reset}`;
        rl.question(`${question} ${hint}\n> `, answer => {
            resolve(answer.trim() || defaultValue);
        });
    });
}

function askPassword(question, defaultValue = '') {
    return new Promise(resolve => {
        const hint = defaultValue ? `${C.dim}[${defaultValue}]${C.reset}` : '';
        process.stdout.write(`${question} ${hint}\n> `);
        
        if (!process.stdin.isTTY) {
            rl.question('', answer => resolve(answer.trim() || defaultValue));
            return;
        }
        
        const stdin = process.stdin;
        const wasRaw = stdin.isRaw;
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding('utf8');
        
        let password = '';
        const onData = (char) => {
            char = char.toString();
            switch (char) {
                case '\n':
                case '\r':
                case '\u0004':
                    stdin.setRawMode(wasRaw);
                    stdin.removeListener('data', onData);
                    process.stdout.write('\n');
                    resolve(password || defaultValue);
                    break;
                case '\u0003':
                    process.exit();
                    break;
                case '\u007f':
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                        process.stdout.write('\b \b');
                    }
                    break;
                default:
                    password += char;
                    process.stdout.write('*');
                    break;
            }
        };
        stdin.on('data', onData);
    });
}

async function main() {
    console.log(`\n${C.bold}====================================${C.reset}`);
    console.log(`${C.bold}   Panel Setup — Otomatis${C.reset}`);
    console.log(`${C.bold}====================================${C.reset}`);
    console.log(`${C.dim}   Tekan ENTER untuk pakai nilai default${C.reset}\n`);
    
    const envPath = path.join(process.cwd(), '.env');
    
    if (fs.existsSync(envPath)) {
        console.log(`${C.yellow}File .env sudah ada.${C.reset}`);
        const overwrite = await ask('Timpa dengan konfigurasi baru? (y/N)', 'n');
        if (overwrite.toLowerCase() !== 'y') {
            console.log(`\n${C.dim}Dibatalkan.${C.reset}\n`);
            rl.close();
            process.exit(0);
        }
        console.log('');
    }
    
    console.log(`${C.bold}Konfigurasi:${C.reset}\n`);
    
    const appName = await ask('Nama web (branding)', 'Panel-Deploy');
    const port = await ask('Port panel', '5000');
    const ownerUser = await ask('Username owner', 'admin');
    const ownerPass = await askPassword('Password owner', 'admin123');
    const dbPath = await ask('Lokasi database', './data/paas.db');
    
    console.log(`\n${C.bold}Preview konfigurasi:${C.reset}`);
    console.log(`   Nama web:      ${C.cyan}${appName}${C.reset}`);
    console.log(`   Port:          ${C.cyan}${port}${C.reset}`);
    console.log(`   Username:      ${C.cyan}${ownerUser}${C.reset}`);
    console.log(`   Password:      ${C.cyan}${ownerPass}${C.reset}`);
    console.log(`   DB path:       ${C.cyan}${dbPath}${C.reset}`);
    console.log(`   Docker image:  ${C.cyan}${FIXED_BASE_IMAGE}${C.reset} ${C.dim}(terkunci)${C.reset}`);
    
    const confirm = await ask(`\nLanjut? (Y/n)`, 'y');
    if (confirm.toLowerCase() === 'n') {
        console.log(`\n${C.dim}Dibatalkan.${C.reset}\n`);
        rl.close();
        process.exit(0);
    }
    
    console.log(`\n${C.dim}Generate kredensial...${C.reset}`);
    
    const jwtSecret = crypto.randomBytes(32).toString('hex');
    console.log(`${C.green}[OK]${C.reset} JWT_SECRET`);
    
    let bcrypt;
    try {
        bcrypt = require('bcryptjs');
    } catch (err) {
        console.error(`\n${C.red}[ERR] bcryptjs belum terinstall.${C.reset}`);
        console.error(`   Jalankan: ${C.cyan}npm install${C.reset}\n`);
        rl.close();
        process.exit(1);
    }
    
    const passHash = bcrypt.hashSync(ownerPass, 12);
    console.log(`${C.green}[OK]${C.reset} Password hash (bcrypt cost 12)`);
    
    const envContent = `APP_NAME=${appName}
PORT=${port}
JWT_SECRET=${jwtSecret}
OWNER_USER=${ownerUser}
OWNER_PASS_HASH=${passHash}
BASE_IMAGE=${FIXED_BASE_IMAGE}
DB_PATH=${dbPath}
`;
    
    fs.writeFileSync(envPath, envContent, { mode: 0o600 });
    console.log(`${C.green}[OK]${C.reset} File .env ditulis (permission 600)`);
    
    const dirs = ['data', 'public'];
    for (const d of dirs) {
        const dirPath = path.join(process.cwd(), d);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            console.log(`${C.green}[OK]${C.reset} Folder ${d}/ dibuat`);
        }
    }
    
    const gitignorePath = path.join(process.cwd(), '.gitignore');
    const gitignoreEntries = ['.env', 'data/', 'node_modules/', 'uploads/', '*.log', '.DS_Store'];
    
    if (!fs.existsSync(gitignorePath)) {
        fs.writeFileSync(gitignorePath, gitignoreEntries.join('\n') + '\n');
        console.log(`${C.green}[OK]${C.reset} .gitignore dibuat`);
    } else {
        let content = fs.readFileSync(gitignorePath, 'utf8');
        const lines = content.split('\n').map(l => l.trim());
        const added = [];
        for (const entry of gitignoreEntries) {
            if (!lines.includes(entry)) {
                content += (content.endsWith('\n') ? '' : '\n') + entry + '\n';
                added.push(entry);
            }
        }
        if (added.length) {
            fs.writeFileSync(gitignorePath, content);
            console.log(`${C.green}[OK]${C.reset} .gitignore: ditambah ${added.join(', ')}`);
        }
    }
    
    const verify = bcrypt.compareSync(ownerPass, passHash);
    console.log(`${C.green}[OK]${C.reset} Verifikasi hash: ${verify ? 'OK' : C.red + 'GAGAL' + C.reset}`);
    
    const { execSync } = require('child_process');
    try {
        execSync('docker info', { stdio: 'ignore' });
        console.log(`${C.green}[OK]${C.reset} Docker terdeteksi`);
    } catch {
        console.log(`${C.yellow}[WARN]${C.reset} Docker tidak terdeteksi`);
    }
    
    console.log(`\n${C.bold}====================================${C.reset}`);
    console.log(`${C.bold}   SETUP SELESAI${C.reset}`);
    console.log(`${C.bold}====================================${C.reset}\n`);
    
    console.log(`${C.bold}Kredensial login:${C.reset}\n`);
    console.log(`   Username: ${C.cyan}${C.bold}${ownerUser}${C.reset}`);
    console.log(`   Password: ${C.cyan}${C.bold}${ownerPass}${C.reset}`);
    console.log('');
    
    console.log(`${C.bold}Cara jalankan:${C.reset}\n`);
    console.log(`   ${C.cyan}node server.js${C.reset}\n`);
    
    console.log(`${C.bold}Buka di browser:${C.reset}\n`);
    console.log(`   ${C.cyan}http://localhost:${port}${C.reset}\n`);
    
    console.log(`${C.bold}Developer:${C.reset}`);
    console.log(`   Telegram: ${C.cyan}@${TELEGRAM_USER}${C.reset}\n`);
    
    console.log(`${C.yellow}JANGAN commit file .env ke GitHub!${C.reset}\n`);
    
    rl.close();
}

main().catch(err => {
    console.error(`\n${C.red}Error:${C.reset}`, err.message);
    rl.close();
    process.exit(1);
});
