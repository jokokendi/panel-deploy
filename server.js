require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const OWNER_USER = process.env.OWNER_USER;
const OWNER_HASH = process.env.OWNER_PASS_HASH;
const DB_PATH = process.env.DB_PATH || './data/paas.db';
const APP_NAME = process.env.APP_NAME || 'Panel-Deploy';
const TELEGRAM_USER = 'pySmartDL';

const LOCKED_BASE_IMAGE = 'jokokendil/polyglot:latest';
const ENV_BASE_IMAGE = process.env.BASE_IMAGE;
const BASE_IMAGE = LOCKED_BASE_IMAGE;
if (ENV_BASE_IMAGE && ENV_BASE_IMAGE !== LOCKED_BASE_IMAGE) {
  console.warn(`[WARN] BASE_IMAGE di .env diabaikan, dikunci ke ${LOCKED_BASE_IMAGE}`);
}

const missing = Object.entries({ JWT_SECRET, OWNER_USER, OWNER_HASH })
  .filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error(`[ERR] ENV belum di set: ${missing.join(', ')}`);
  process.exit(1);
}
console.log(`[OK] ENV | App: ${APP_NAME} | Owner: ${OWNER_USER} | DB: ${DB_PATH}`);

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    container TEXT,
    volume TEXT,
    expired_at TEXT,
    status TEXT
  )
`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_expired ON tokens(expired_at)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_container ON tokens(container)`);

try {
  const cols = db.prepare(`PRAGMA table_info(tokens)`).all();
  if (cols.some(c => c.name === 'device_id')) {
    try {
      db.exec(`ALTER TABLE tokens DROP COLUMN device_id`);
      console.log(`[OK] Migrasi: kolom device_id dihapus`);
    } catch (e) {
      console.log(`[INFO] Kolom device_id diabaikan`);
    }
  }
} catch (e) {
  console.error('[migrasi]', e.message);
}

console.log(`[OK] DB ready: ${DB_PATH}`);

const logsCache = new Map();
const statusCache = new Map();
const volPathCache = new Map();
const LOGS_TTL = 3000;
const STATUS_TTL = 4000;

function getCached(map, key, ttl, loader) {
  const now = Date.now();
  const c = map.get(key);
  if (c && (now - c.ts) < ttl) return c.data;
  const fresh = loader();
  map.set(key, { data: fresh, ts: now });
  return fresh;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of logsCache.entries()) if (now - v.ts > 300000) logsCache.delete(k);
  for (const [k, v] of statusCache.entries()) if (now - v.ts > 300000) statusCache.delete(k);
}, 300000);

function sh(cmd, timeout = 600000) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch (err) {
    return (err.stdout || '') + (err.stderr || err.message);
  }
}
function shSafe(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 5000 }).trim(); }
  catch { return ''; }
}

function sanitize(str) {
  return String(str)
    .replace(/ghp_[A-Za-z0-9]+/g, 'ghp_***')
    .replace(/github_pat_[A-Za-z0-9_]+/g, 'github_pat_***')
    .replace(/gho_[A-Za-z0-9]+/g, 'gho_***')
    .replace(/ghs_[A-Za-z0-9]+/g, 'ghs_***')
    .replace(/glpat-[A-Za-z0-9_-]+/g, 'glpat-***')
    .replace(/https:\/\/[^@]+@/g, 'https://***@');
}

function calcSisa(expiredAt) {
  try {
    const diff = new Date(expiredAt) - new Date();
    if (diff < 0) return 'expired';
    const d = Math.floor(diff / 86400000);
    const h = Math.floor((diff % 86400000) / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    if (d > 0) return `${d} hari ${h} jam`;
    if (h > 0) return `${h} jam ${m} menit`;
    return `${m} menit`;
  } catch { return '?'; }
}

const rateLimits = new Map();
function checkRateLimit(ip, action, max, windowMs) {
  const key = `${ip}:${action}`;
  const now = Date.now();
  const rec = rateLimits.get(key) || { count: 0, reset: now + windowMs };
  if (now > rec.reset) { rec.count = 0; rec.reset = now + windowMs; }
  rec.count++;
  rateLimits.set(key, rec);
  return rec.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of rateLimits.entries()) if (now > r.reset) rateLimits.delete(k);
}, 600000);

function validateGithubToken(token) {
  if (!token) return { ok: true, token: '' };
  const t = String(token).trim();
  if (/^ghp_[A-Za-z0-9]{36}$/.test(t)) return { ok: true, token: t };
  if (/^github_pat_[A-Za-z0-9_]{82}$/.test(t)) return { ok: true, token: t };
  if (/^gho_[A-Za-z0-9]{36}$/.test(t)) return { ok: true, token: t };
  if (/^ghs_[A-Za-z0-9]{36}$/.test(t)) return { ok: true, token: t };
  if (/^glpat-[A-Za-z0-9_-]{20}$/.test(t)) return { ok: true, token: t, type: 'gitlab' };
  return { ok: false, error: 'Format token tidak valid' };
}

function buildCloneUrl(repoUrl, token) {
  if (!token) return repoUrl;
  if (repoUrl.includes('github.com')) {
    return repoUrl.replace('https://github.com/', `https://${token}@github.com/`);
  }
  if (repoUrl.includes('gitlab.com')) {
    return repoUrl.replace('https://gitlab.com/', `https://oauth2:${token}@gitlab.com/`);
  }
  return repoUrl;
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'no token' });
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET, {
      issuer: 'raju-deploy', audience: 'panel'
    });
    req.userRole = decoded.role;
    req.userToken = decoded.token;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}
function ownerOnly(req, res, next) {
  if (req.userRole !== 'owner') return res.status(403).json({ error: 'forbidden' });
  next();
}
function memberOnly(req, res, next) {
  if (req.userRole !== 'member') return res.status(403).json({ error: 'forbidden' });
  next();
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '512kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
  }
}));

app.get('/api/config', (req, res) => {
  res.json({ appName: APP_NAME, developer: { telegram: TELEGRAM_USER } });
});

app.get('/api/health', (req, res) => {
  const dockerOut = shSafe('docker ps 2>&1');
  res.json({
    backend: 'ok',
    docker: dockerOut.includes('CONTAINER ID') || dockerOut.includes('NAMES'),
    runtime: 'node',
    appName: APP_NAME
  });
});

app.post('/api/owner/login', async (req, res) => {
  if (!checkRateLimit(req.ip, 'owner-login', 5, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan. Tunggu 15 menit.' });
  }

  const { username, password } = req.body || {};
  await new Promise(r => setTimeout(r, 150 + Math.random() * 100));

  if (username !== OWNER_USER || !(await bcrypt.compare(password || '', OWNER_HASH))) {
    return res.status(403).json({ error: 'Login gagal' });
  }

  const jwtToken = jwt.sign(
    { role: 'owner' },
    JWT_SECRET,
    { expiresIn: '4h', issuer: 'raju-deploy', audience: 'panel' }
  );
  res.json({ jwt: jwtToken });
});

app.post('/api/owner/generate-token', auth, ownerOnly, (req, res) => {
  const days = Math.max(1, Math.min(365, parseInt(req.body?.days || 7)));
  const token = 'PAAS-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const expiredAt = new Date(Date.now() + days * 86400000).toISOString();
  const volume = 'vol_' + token.toLowerCase().replace(/-/g, '_');

  db.prepare('INSERT INTO tokens (token, container, volume, expired_at, status) VALUES (?, ?, ?, ?, ?)')
    .run(token, null, volume, expiredAt, 'active');

  res.json({ token, expired_at: expiredAt, days });
});

app.get('/api/owner/tokens', auth, ownerOnly, (req, res) => {
  const rows = db.prepare(
    'SELECT token, container, expired_at FROM tokens ORDER BY expired_at DESC'
  ).all();

  const containerNames = rows.filter(r => r.container).map(r => r.container);
  const statusMap = {};
  if (containerNames.length > 0) {
    const out = shSafe(
      `docker inspect --format '{{.Name}}|{{.State.Status}}' ${containerNames.join(' ')} 2>/dev/null`
    );
    for (const line of out.split('\n')) {
      const [name, status] = line.split('|');
      if (name) statusMap[name.replace(/^\//, '').trim()] = (status || 'unknown').trim();
    }
  }

  const data = rows.map(r => ({
    token: r.token,
    container: r.container,
    containerStatus: r.container ? (statusMap[r.container] || 'unknown') : 'belum deploy',
    expired_at: r.expired_at,
    sisa: calcSisa(r.expired_at)
  }));

  res.json(data);
});

app.post('/api/owner/extend/:token', auth, ownerOnly, (req, res) => {
  const days = Math.max(1, Math.min(365, parseInt(req.body?.days || 7)));
  const row = db.prepare('SELECT expired_at FROM tokens WHERE token=?').get(req.params.token);
  if (!row) return res.status(404).json({ error: 'not found' });

  const newExp = new Date(new Date(row.expired_at).getTime() + days * 86400000).toISOString();
  db.prepare('UPDATE tokens SET expired_at=? WHERE token=?').run(newExp, req.params.token);
  res.json({ new_expired: newExp });
});

app.post('/api/owner/delete/:token', auth, ownerOnly, (req, res) => {
  const row = db.prepare('SELECT container, volume FROM tokens WHERE token=?').get(req.params.token);
  if (!row) return res.status(404).json({ error: 'not found' });

  if (row.container) shSafe(`docker rm -f ${row.container} 2>/dev/null`);
  if (row.volume) shSafe(`docker volume rm ${row.volume} 2>/dev/null`);
  db.prepare('DELETE FROM tokens WHERE token=?').run(req.params.token);

  if (row.container) {
    logsCache.delete(row.container);
    statusCache.delete(row.container);
  }
  if (row.volume) volPathCache.delete(row.volume);

  res.json({ ok: true });
});

app.post('/api/member/login', async (req, res) => {
  if (!checkRateLimit(req.ip, 'member-login', 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan' });
  }

  const { token } = req.body || {};
  const tk = String(token || '').toUpperCase().trim();

  if (!tk) return res.status(400).json({ error: 'Token kosong' });

  const row = db.prepare(
    'SELECT expired_at, container, volume FROM tokens WHERE token=?'
  ).get(tk);

  if (!row) return res.status(404).json({ error: 'Token tidak valid' });

  if (new Date(row.expired_at) < new Date()) {
    if (row.container) shSafe(`docker rm -f ${row.container} 2>/dev/null`);
    if (row.volume) shSafe(`docker volume rm ${row.volume} 2>/dev/null`);
    db.prepare('DELETE FROM tokens WHERE token=?').run(tk);
    return res.status(403).json({ error: 'Token expired' });
  }

  const jwtToken = jwt.sign(
    { role: 'member', token: tk },
    JWT_SECRET,
    { expiresIn: '12h', issuer: 'raju-deploy', audience: 'panel' }
  );

  res.json({ jwt: jwtToken, token: tk });
});

app.get('/api/member/status', auth, memberOnly, (req, res) => {
  const row = db.prepare(
    'SELECT container, expired_at FROM tokens WHERE token=?'
  ).get(req.userToken);

  if (!row) return res.json({ running: false });

  const sisa = calcSisa(row.expired_at);

  if (!row.container) {
    return res.json({
      running: false,
      container: null,
      status: 'not created',
      sisa,
      expired_at: row.expired_at
    });
  }

  const status = getCached(statusCache, row.container, STATUS_TTL, () => {
    return shSafe(`docker inspect -f '{{.State.Status}}' ${row.container} 2>&1`) || 'unknown';
  });

  res.json({
    running: String(status).toLowerCase().includes('running'),
    container: row.container,
    status,
    sisa,
    expired_at: row.expired_at
  });
});

function detectRuntime(dir) {
  const files = fs.readdirSync(dir);
  if (files.includes('package.json')) return 'node';
  if (files.includes('requirements.txt') || files.includes('pyproject.toml') || files.includes('Pipfile')) return 'python';
  if (files.includes('go.mod')) return 'go';
  if (files.includes('Gemfile')) return 'ruby';
  if (files.includes('composer.json')) return 'php';
  if (files.includes('pom.xml') || files.includes('build.gradle')) return 'java';
  if (files.includes('index.html')) return 'static';
  return 'unknown';
}

function defaultStartCmd(runtime) {
  const map = {
    node: 'npm start',
    python: 'python main.py',
    go: './app',
    ruby: 'ruby app.rb',
    php: 'php -S 0.0.0.0:$PORT',
    java: 'java -jar app.jar',
    static: 'python3 -m http.server $PORT'
  };
  return map[runtime] || 'echo "no start cmd"';
}

app.post('/api/member/scrap', auth, memberOnly, (req, res) => {
  if (!checkRateLimit(req.ip, 'scrap', 20, 60 * 60 * 1000)) {
    return res.status(429).json({ error: 'Terlalu banyak scrap. Coba lagi nanti.' });
  }

  const repo = String(req.body?.repo || '').trim();
  const branch = String(req.body?.branch || 'main').slice(0, 64);
  const ghp = String(req.body?.ghp || '').trim();

  if (!repo) return res.json({ ok: false, error: 'Repo kosong' });

  if (!/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(\.git)?$/.test(repo)) {
    return res.status(400).json({ error: 'URL repo tidak valid' });
  }

  const tokenCheck = validateGithubToken(ghp);
  if (!tokenCheck.ok) return res.status(400).json({ error: tokenCheck.error });
  const cleanGhp = tokenCheck.token;

  const tmp = `/tmp/scrap-${crypto.randomBytes(8).toString('hex')}`;
  const cloneUrl = buildCloneUrl(repo, cleanGhp);

  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' };

  try {
    execSync(`git clone --depth 1 -b ${branch} ${cloneUrl} ${tmp} 2>&1`,
      { encoding: 'utf8', timeout: 60000, env, stdio: 'pipe' });
  } catch (err) {
    let errMsg = (err.stdout || '') + (err.stderr || '') + err.message;
    errMsg = sanitize(errMsg);
    shSafe(`rm -rf ${tmp}`);
    if (errMsg.toLowerCase().includes('not found') || errMsg.toLowerCase().includes('repository')) {
      return res.status(400).json({ error: 'Repo tidak ditemukan atau private (butuh token GitHub)' });
    }
    if (errMsg.toLowerCase().includes('authentication') || errMsg.includes('403')) {
      return res.status(400).json({ error: 'Token GitHub salah atau tidak punya akses' });
    }
    return res.status(400).json({ error: 'Gagal clone: ' + errMsg.slice(0, 200) });
  }

  if (!fs.existsSync(tmp)) return res.status(400).json({ error: 'Gagal clone repo' });

  const result = {
    ok: true, repo, branch, runtime: 'unknown', startCmd: '',
    processes: {}, env: {}, addons: [], scripts: {},
    description: '', name: '', detectedFiles: [],
    isPrivate: !!cleanGhp
  };

  try {
    const rootFiles = fs.readdirSync(tmp).filter(f => !f.startsWith('.'));
    result.detectedFiles = rootFiles.slice(0, 30);
    result.runtime = detectRuntime(tmp);

    const procfilePath = path.join(tmp, 'Procfile');
    if (fs.existsSync(procfilePath)) {
      const procContent = fs.readFileSync(procfilePath, 'utf8').slice(0, 5000);
      for (const line of procContent.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const match = trimmed.match(/^([\w-]+):\s*(.+)$/);
        if (match) result.processes[match[1]] = match[2].trim();
      }
      if (result.processes.web) result.startCmd = result.processes.web;
      else if (result.processes.worker) result.startCmd = result.processes.worker;
    }

    const appJsonPath = path.join(tmp, 'app.json');
    if (fs.existsSync(appJsonPath)) {
      try {
        const appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8').slice(0, 50000));
        result.name = appJson.name || '';
        result.description = appJson.description || '';

        if (appJson.env && typeof appJson.env === 'object') {
          for (const [key, val] of Object.entries(appJson.env)) {
            if (typeof val === 'string') {
              result.env[key] = { value: val, description: '', required: true };
            } else if (val && typeof val === 'object') {
              result.env[key] = {
                description: val.description || '',
                value: val.value || '',
                required: val.required !== false,
                generator: val.generator || null
              };
            }
          }
        }
        if (Array.isArray(appJson.addons)) {
          result.addons = appJson.addons.map(a =>
            typeof a === 'string' ? a : (a.plan || JSON.stringify(a)));
        }
        if (appJson.scripts && typeof appJson.scripts === 'object') {
          result.scripts = appJson.scripts;
        }
      } catch (e) { console.error('[scrap] app.json error:', e.message); }
    }

    if (!result.startCmd) {
      result.startCmd = defaultStartCmd(result.runtime);
      if (result.runtime === 'node') {
        try {
          const pkg = JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8'));
          if (pkg.scripts?.start) result.startCmd = 'npm start';
          else if (pkg.main) result.startCmd = `node ${pkg.main}`;
        } catch {}
      }
      if (result.runtime === 'python') {
        for (const f of ['start.sh', 'start', 'main.py', 'bot.py', 'app.py', 'server.py']) {
          if (fs.existsSync(path.join(tmp, f))) {
            result.startCmd = f.startsWith('start') ? `bash ${f}` : `python3 ${f}`;
            break;
          }
        }
      }
    }

    for (const info of Object.values(result.env)) {
      if (info.generator === 'secret' && !info.value) {
        info.value = crypto.randomBytes(32).toString('hex');
        info.generated = true;
      }
    }
  } finally {
    shSafe(`rm -rf ${tmp}`);
  }

  res.json(result);
});

const BLOCKED_KEY_PATTERNS = [
  /^OWNER/i, /^ADMIN/i, /^MASTER/i, /^RAJU/i, /^PANEL/i,
  /JWT_SECRET/i, /OWNER_PASS/i, /OWNER_HASH/i,
  /BASE_IMAGE/i, /DB_PATH/i
];

function isBlockedKey(k) {
  return BLOCKED_KEY_PATTERNS.some(rx => rx.test(k));
}

app.post('/api/member/deploy', auth, memberOnly, (req, res) => {
  if (!checkRateLimit(req.ip, 'deploy', 5, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Terlalu banyak deploy. Tunggu 10 menit.' });
  }

  const { repo, ghp, env, startCmd: userStartCmd, branch } = req.body || {};
  const token = req.userToken;

  if (!repo || !/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(\.git)?$/.test(repo)) {
    return res.status(400).json({ error: 'URL repo tidak valid' });
  }

  const tokenCheck = validateGithubToken(ghp);
  if (!tokenCheck.ok) return res.status(400).json({ error: tokenCheck.error });
  const cleanGhp = tokenCheck.token;

  const cleanEnv = {};
  let count = 0;
  for (const [k, v] of Object.entries(env || {})) {
    if (count++ > 40) break;
    const key = String(k).slice(0, 64).replace(/[^A-Z0-9_]/gi, '_');
    const val = String(v).slice(0, 2048);
    if (key && !isBlockedKey(key)) cleanEnv[key] = val;
  }

  const row = db.prepare('SELECT container, volume FROM tokens WHERE token=?').get(token);
  if (!row) return res.status(404).json({ error: 'Token invalid' });

  if (row.container) {
    shSafe(`docker rm -f ${row.container} 2>/dev/null`);
    logsCache.delete(row.container);
    statusCache.delete(row.container);
  }

  const appName = `app-${token.toLowerCase().replace(/-/g, '_')}-${crypto.randomBytes(2).toString('hex')}`;
  shSafe(`docker volume create ${row.volume} 2>/dev/null`);

  const envFlags = Object.entries(cleanEnv)
    .map(([k, v]) => `-e ${k}=${JSON.stringify(v)}`)
    .join(' ');

  const cloneUrl = buildCloneUrl(repo, cleanGhp);
  const safeBranch = String(branch || 'main').replace(/[^A-Za-z0-9_.-/]/g, '').slice(0, 64);
  const userStart = String(userStartCmd || '').trim().slice(0, 512);

  const deployScript = `set -e
echo "=====> [1/5] Clone repo"
cd /tmp && rm -rf src
git clone --depth 1 -b ${safeBranch} ${cloneUrl} src 2>&1
cd src

echo "=====> [2/5] Copy ke /app"
mkdir -p /app
cp -r . /app/ 2>/dev/null
cd /app

echo "=====> [3/5] Install dependencies (auto-detect)"
if [ -f requirements.txt ]; then
  echo "--- pip install -r requirements.txt"
  pip3 install --no-cache-dir -r requirements.txt 2>&1 | tail -20 || true
fi
if [ -f pyproject.toml ]; then
  echo "--- pip install ."
  pip3 install --no-cache-dir . 2>&1 | tail -20 || true
fi
if [ -f package.json ]; then
  echo "--- npm install"
  npm install --omit=dev 2>&1 | tail -20 || true
fi
if [ -f Gemfile ]; then
  echo "--- bundle install"
  (gem install bundler 2>&1 | tail -3; bundle install 2>&1 | tail -20) || true
fi
if [ -f go.mod ]; then
  echo "--- go build"
  (go mod download 2>&1 | tail -10; go build -o app . 2>&1 | tail -20) || true
fi
if [ -f composer.json ]; then
  echo "--- composer install"
  composer install --no-dev --no-interaction 2>&1 | tail -20 || true
fi

echo "=====> [4/5] Determine start command"
START_CMD=""
USER_START=${JSON.stringify(userStart)}

if [ -n "$USER_START" ]; then
  START_CMD="$USER_START"
  echo "Source: user override"
elif [ -f Procfile ]; then
  WEB=$(grep -E '^web:' Procfile | head -1 | sed 's/^web:[[:space:]]*//')
  WORKER=$(grep -E '^worker:' Procfile | head -1 | sed 's/^worker:[[:space:]]*//')
  if [ -n "$WEB" ]; then
    START_CMD="$WEB"
    echo "Source: Procfile web"
  elif [ -n "$WORKER" ]; then
    START_CMD="$WORKER"
    echo "Source: Procfile worker"
  fi
fi

if [ -z "$START_CMD" ]; then
  if [ -f start.sh ]; then START_CMD="bash start.sh"
  elif [ -f start ]; then START_CMD="bash start"
  elif [ -f main.py ]; then START_CMD="python3 main.py"
  elif [ -f bot.py ]; then START_CMD="python3 bot.py"
  elif [ -f app.py ]; then START_CMD="python3 app.py"
  elif [ -f index.js ]; then START_CMD="node index.js"
  elif [ -f server.js ]; then START_CMD="node server.js"
  elif [ -f package.json ]; then START_CMD="npm start"
  elif [ -f main.go ]; then START_CMD="./app"
  elif [ -f app.rb ]; then START_CMD="ruby app.rb"
  elif [ -f index.php ]; then START_CMD="php -S 0.0.0.0:$PORT"
  elif [ -f index.html ]; then START_CMD="python3 -m http.server $PORT"
  fi
  [ -n "$START_CMD" ] && echo "Source: fallback file"
fi

if [ -z "$START_CMD" ]; then
  echo "ERROR: Tidak bisa menentukan start command"
  exit 1
fi

echo "=====> [5/5] Run: $START_CMD"
exec sh -c "$START_CMD"`;

  const scriptB64 = Buffer.from(deployScript, 'utf8').toString('base64');

  const cmd = `docker run -d --name=${appName} ` +
    `--restart on-failure:5 ` +
    `--label token=${token} ` +
    `-v ${row.volume}:/app ` +
    `${envFlags} ` +
    `-e PORT=3000 ` +
    `${BASE_IMAGE} ` +
    `bash -c "echo '${scriptB64}' | base64 -d | bash"`;

  const out = sh(cmd, 600000);

  if (out.toLowerCase().includes('error') && !out.includes(appName)) {
    console.error('[deploy]', sanitize(out));
    return res.status(500).json({ error: 'Deploy gagal. Cek log server.' });
  }

  db.prepare('UPDATE tokens SET container=? WHERE token=?').run(appName, token);
  res.json({ ok: true, container: appName });
});

app.get('/api/member/logs', auth, memberOnly, (req, res) => {
  const row = db.prepare('SELECT container FROM tokens WHERE token=?').get(req.userToken);
  if (!row || !row.container) return res.json({ logs: '(belum ada container)' });

  const logs = getCached(logsCache, row.container, LOGS_TTL, () => {
    const out = shSafe(`docker logs --tail 200 ${row.container} 2>&1`);
    return sanitize(out) || '(kosong)';
  });

  res.json({ logs });
});

app.post('/api/member/stop', auth, memberOnly, (req, res) => {
  const row = db.prepare('SELECT container FROM tokens WHERE token=?').get(req.userToken);
  if (row?.container) {
    shSafe(`docker rm -f ${row.container} 2>/dev/null`);
    logsCache.delete(row.container);
    statusCache.delete(row.container);
  }
  res.json({ ok: true });
});

const MAX_FILE_SIZE = 2 * 1024 * 1024;
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

function getVolMountpoint(volume) {
  if (volPathCache.has(volume)) return volPathCache.get(volume);
  const out = shSafe(`docker volume inspect ${volume} -f '{{.Mountpoint}}'`);
  const p = out || `/var/lib/docker/volumes/${volume}/_data`;
  volPathCache.set(volume, p);
  return p;
}

function safeRelPath(input) {
  let p = String(input || '').trim();
  try { p = decodeURIComponent(p); } catch {}
  p = p.replace(/^[\/\\]+/, '');
  const parts = p.split(/[\/\\]+/).filter(x => x && x !== '.' && x !== '..');
  return parts.join('/');
}

function getMemberVolume(token) {
  const row = db.prepare('SELECT volume, container FROM tokens WHERE token=?').get(token);
  if (!row || !row.volume) return null;
  return row;
}

app.get('/api/member/files/list', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy. Volume belum dibuat.' });

  try {
    const rel = safeRelPath(req.query.path);
    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);

    if (!full.startsWith(base)) {
      return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    }

    if (!fs.existsSync(full)) {
      return res.status(404).json({ ok: false, error: 'Folder tidak ditemukan' });
    }
    if (!fs.statSync(full).isDirectory()) {
      return res.status(400).json({ ok: false, error: 'Bukan folder' });
    }

    const items = fs.readdirSync(full).map(name => {
      const fp = path.join(full, name);
      try {
        const st = fs.lstatSync(fp);
        return {
          name,
          isDir: st.isDirectory(),
          isLink: st.isSymbolicLink(),
          size: st.size,
          date: st.mtime.toLocaleString('id-ID', { hour12: false }),
          mtime: st.mtimeMs
        };
      } catch {
        return { name, isDir: false, isLink: false, size: 0, date: '', mtime: 0 };
      }
    });

    items.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ ok: true, path: rel, container: row.container, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/member/files/read', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.query.path);
    if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base)) return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: 'File tidak ditemukan' });

    const st = fs.statSync(full);
    if (st.isDirectory()) return res.status(400).json({ ok: false, error: 'Ini folder' });
    if (st.size > MAX_FILE_SIZE) {
      return res.status(413).json({ ok: false, error: `File terlalu besar (${(st.size/1024).toFixed(0)} KB, max 2 MB)` });
    }

    const buf = fs.readFileSync(full);
    const isBinary = /[\x00-\x08\x0E-\x1F]/.test(buf.slice(0, 4096).toString('latin1'));

    res.json({
      ok: true,
      path: rel,
      size: st.size,
      content: isBinary ? null : buf.toString('utf8'),
      binary: isBinary
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/member/files/write', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.body?.path);
    const content = String(req.body?.content ?? '');
    if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });
    if (content.length > MAX_FILE_SIZE) return res.status(413).json({ ok: false, error: 'File terlalu besar' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base)) return res.status(400).json({ ok: false, error: 'Path tidak valid' });

    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/member/files/create', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.body?.path);
    const type = req.body?.type === 'folder' ? 'folder' : 'file';
    if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base)) return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    if (fs.existsSync(full)) return res.status(400).json({ ok: false, error: 'Sudah ada' });

    if (type === 'folder') {
      fs.mkdirSync(full, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, '', 'utf8');
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/member/files/delete', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.body?.path);
    if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base) || full === base) {
      return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    }
    if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: 'Tidak ditemukan' });

    fs.rmSync(full, { recursive: true, force: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/member/files/rename', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const from = safeRelPath(req.body?.from);
    const to = safeRelPath(req.body?.to);
    if (!from || !to) return res.status(400).json({ ok: false, error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const fullFrom = path.join(base, from);
    const fullTo = path.join(base, to);
    if (!fullFrom.startsWith(base) || !fullTo.startsWith(base)) {
      return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    }
    if (!fs.existsSync(fullFrom)) return res.status(404).json({ ok: false, error: 'Sumber tidak ada' });
    if (fs.existsSync(fullTo)) return res.status(400).json({ ok: false, error: 'Tujuan sudah ada' });

    fs.mkdirSync(path.dirname(fullTo), { recursive: true });
    fs.renameSync(fullFrom, fullTo);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/member/files/upload',
  auth, memberOnly,
  express.raw({ type: '*/*', limit: MAX_UPLOAD_SIZE }),
  (req, res) => {
    const row = getMemberVolume(req.userToken);
    if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

    try {
      const rel = safeRelPath(req.query.path);
      if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });

      const buf = req.body;
      if (!buf || !buf.length) return res.status(400).json({ ok: false, error: 'File kosong' });
      if (buf.length > MAX_UPLOAD_SIZE) return res.status(413).json({ ok: false, error: 'File terlalu besar' });

      const base = getVolMountpoint(row.volume);
      const full = path.join(base, rel);
      if (!full.startsWith(base)) return res.status(400).json({ ok: false, error: 'Path tidak valid' });

      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, buf);
      res.json({ ok: true, size: buf.length });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  }
);

app.get('/api/member/files/download', auth, memberOnly, (req, res) => {
  const row = getMemberVolume(req.userToken);
  if (!row) return res.status(400).json({ ok: false, error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.query.path);
    if (!rel) return res.status(400).json({ ok: false, error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base)) return res.status(400).json({ ok: false, error: 'Path tidak valid' });
    if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: 'File tidak ditemukan' });
    if (fs.statSync(full).isDirectory()) return res.status(400).json({ ok: false, error: 'Ini folder' });

    const filename = path.basename(full);
    res.setHeader('Content-Disposition', `attachment; filename="${filename.replace(/"/g, '')}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/member/files/raw', (req, res) => {
  let tk = null;
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(header.slice(7), JWT_SECRET, {
        issuer: 'raju-deploy', audience: 'panel'
      });
      if (decoded.role === 'member') tk = decoded.token;
    } catch {}
  }
  if (!tk && req.query.tk) {
    try {
      const decoded = jwt.verify(String(req.query.tk), JWT_SECRET, {
        issuer: 'raju-deploy', audience: 'panel'
      });
      if (decoded.role === 'member') tk = decoded.token;
    } catch {}
  }
  if (!tk) return res.status(401).json({ error: 'unauthorized' });

  const row = db.prepare('SELECT volume FROM tokens WHERE token=?').get(tk);
  if (!row || !row.volume) return res.status(400).json({ error: 'Belum deploy' });

  try {
    const rel = safeRelPath(req.query.path);
    if (!rel) return res.status(400).json({ error: 'Path kosong' });

    const base = getVolMountpoint(row.volume);
    const full = path.join(base, rel);
    if (!full.startsWith(base)) return res.status(400).json({ error: 'Path tidak valid' });
    if (!fs.existsSync(full)) return res.status(404).json({ error: 'File tidak ditemukan' });
    if (fs.statSync(full).isDirectory()) return res.status(400).json({ error: 'Ini folder' });

    const ext = path.extname(full).toLowerCase().slice(1);
    const mimeMap = {
      jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', gif:'image/gif',
      webp:'image/webp', svg:'image/svg+xml', bmp:'image/bmp', ico:'image/x-icon',
      mp4:'video/mp4', webm:'video/webm', ogg:'video/ogg', mov:'video/quicktime',
      mp3:'audio/mpeg', wav:'audio/wav', m4a:'audio/mp4', flac:'audio/flac',
      pdf:'application/pdf',
      txt:'text/plain; charset=utf-8',
      json:'application/json; charset=utf-8',
      html:'text/html; charset=utf-8',
      css:'text/css; charset=utf-8',
      js:'application/javascript; charset=utf-8'
    };
    const mime = mimeMap[ext] || 'application/octet-stream';

    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=60');
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', sanitize(err.message));
  res.status(500).json({ error: 'Terjadi kesalahan' });
});

setInterval(() => {
  try {
    const rows = db.prepare(
      "SELECT token, container, volume FROM tokens WHERE datetime(expired_at) < datetime('now')"
    ).all();
    for (const r of rows) {
      console.log(`[expired] ${r.token}`);
      if (r.container) {
        shSafe(`docker rm -f ${r.container} 2>/dev/null`);
        logsCache.delete(r.container);
        statusCache.delete(r.container);
      }
      if (r.volume) {
        shSafe(`docker volume rm ${r.volume} 2>/dev/null`);
        volPathCache.delete(r.volume);
      }
      db.prepare('DELETE FROM tokens WHERE token=?').run(r.token);
    }
  } catch (err) { console.error('[expired]', err.message); }
}, 60000);

setInterval(() => {
  try {
    const rows = db.prepare('SELECT token, container FROM tokens WHERE container IS NOT NULL').all();
    if (rows.length === 0) return;
    const names = rows.map(r => r.container).join(' ');
    const out = shSafe(
      `docker inspect --format '{{.Name}}|{{.State.Status}}|{{.RestartCount}}' ${names} 2>/dev/null`
    );
    const info = {};
    for (const line of out.split('\n')) {
      const [name, status, restarts] = line.split('|');
      if (name) info[name.replace(/^\//, '').trim()] = { status, restarts: parseInt(restarts) || 0 };
    }
    for (const r of rows) {
      const i = info[r.container];
      if (!i) continue;
      if (i.status === 'exited' && i.restarts < 5) {
        console.log(`[auto-restart] ${r.token} (restart #${i.restarts + 1})`);
        shSafe(`docker restart ${r.container} 2>/dev/null`);
      }
    }
  } catch {}
}, 60000);

function getServerIP() {
  const os = require('os');
  const nets = os.networkInterfaces();
  let fallback = null;
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        if (/^(eth|en|ens|wlan)/.test(name)) return net.address;
        if (!fallback) fallback = net.address;
      }
    }
  }
  return fallback || '127.0.0.1';
}

function getPublicIP() {
  const urls = [
    'https://api.ipify.org',
    'https://ifconfig.me/ip',
    'https://icanhazip.com',
    'https://ipinfo.io/ip'
  ];
  for (const url of urls) {
    try {
      const out = execSync(`curl -s --max-time 3 ${url}`, {
        encoding: 'utf8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'ignore']
      }).trim();
      if (/^\d+\.\d+\.\d+\.\d+$/.test(out)) return out;
    } catch {}
  }
  return null;
}

app.listen(PORT, '0.0.0.0', () => {
  const localIP = getServerIP();
  const publicIP = getPublicIP();
  const mainIP = publicIP || localIP;
  const line = '='.repeat(56);
  
  console.log('');
  console.log(line);
  console.log(`   ${APP_NAME}`);
  console.log(line);
  console.log(`   Status     : Online`);
  console.log(`   Akses Web  : http://${mainIP}:${PORT}`);
  console.log(`   Lokal      : http://127.0.0.1:${PORT}`);
  if (publicIP && localIP !== publicIP) {
    console.log(`   LAN        : http://${localIP}:${PORT}`);
  }
  console.log(`   Developer  : @${TELEGRAM_USER}`);
  console.log(line);
  console.log(`   Docker     : ${BASE_IMAGE} (terkunci)`);
  console.log(`   File Mgr   : ON   |   Multi-device : ON`);
  console.log(line);
  console.log('');
});
