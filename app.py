from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, subprocess, platform, re, uuid, socket
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

app = Flask(__name__)
app.secret_key = 'wifi-monitor-secret-key'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

DB = 'wifi_monitor.db'
DEVICES = []
SESSION_TIMEOUT = 5 * 60

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
    except Exception:
        pass
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            user_id      TEXT PRIMARY KEY,
            username     TEXT NOT NULL UNIQUE,
            password     TEXT NOT NULL,
            account_type TEXT NOT NULL DEFAULT 'admin',
            last_login   TEXT
        );
        CREATE TABLE IF NOT EXISTS blacklist_device (
            mac_address     TEXT PRIMARY KEY,
            device_name     TEXT,
            ip_address      TEXT,
            signal_strength TEXT
        );
        CREATE TABLE IF NOT EXISTS whitelist_device (
            mac_address     TEXT PRIMARY KEY,
            device_name     TEXT,
            ip_address      TEXT,
            signal_strength TEXT
        );
        CREATE TABLE IF NOT EXISTS device_notes (
            mac_address TEXT PRIMARY KEY,
            note        TEXT,
            updated_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at   TEXT NOT NULL,
            device_count INTEGER NOT NULL
        );

        DROP VIEW IF EXISTS v_device_status;
        CREATE VIEW v_device_status AS
            SELECT mac_address, device_name, ip_address, signal_strength, 'Blocked' AS status FROM blacklist_device
            UNION ALL
            SELECT mac_address, device_name, ip_address, signal_strength, 'Trusted' AS status FROM whitelist_device;

        DROP VIEW IF EXISTS v_device_counts;
        CREATE VIEW v_device_counts AS
            SELECT
                (SELECT COUNT(*) FROM blacklist_device) AS blocked,
                (SELECT COUNT(*) FROM whitelist_device) AS trusted;
    ''')
    # If the database was created by an older version, ensure `last_login` exists
    try:
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        cols = [r['name'] for r in cur]
        if 'last_login' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()

def has_admin():
    conn = get_db()
    row = conn.execute("SELECT 1 FROM users WHERE account_type='admin' LIMIT 1").fetchone()
    conn.close()
    return row is not None

# ── Network Detection ─────────────────────────────────────────────────────────

def get_default_gateway():
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output('ipconfig', shell=True).decode(errors='ignore')
            for line in out.splitlines():
                if 'Default Gateway' in line:
                    ip = line.split(':')[-1].strip()
                    if ip: return ip
        else:
            out = subprocess.check_output(['ip', 'route'], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if line.startswith('default'):
                    parts = line.split()
                    return parts[parts.index('via') + 1]
    except Exception:
        pass
    return '192.168.1.1'

def get_ssid():
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output('netsh wlan show interfaces', shell=True).decode(errors='ignore')
            for line in out.splitlines():
                if 'SSID' in line and 'BSSID' not in line:
                    return line.split(':')[-1].strip()
        elif platform.system() == 'Darwin':
            out = subprocess.check_output(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if ' SSID:' in line:
                    return line.split(':')[-1].strip()
        else:
            for cmd in [['iwgetid', '-r'], ['nmcli', '-t', '-f', 'active,ssid', 'dev', 'wifi']]:
                try:
                    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                    if out:
                        if 'yes:' in out: return out.split('yes:')[-1].strip()
                        return out.splitlines()[0].strip()
                except Exception:
                    continue
    except Exception:
        pass
    return 'Unknown'

def get_gateway_mac(gw):
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output(f'arp -a {gw}', shell=True).decode(errors='ignore')
        else:
            out = subprocess.check_output(['arp', '-n', gw], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            mac = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', line)
            if mac: return mac.group().upper().replace('-', ':')
    except Exception:
        pass
    return 'FF:FF:FF:FF:FF:FF'

def detect_network():
    gw   = get_default_gateway()
    ssid = get_ssid()
    mac  = get_gateway_mac(gw)
    name = f'Router-{gw.split(".")[-1]}'
    return {'gateway': gw, 'ssid': ssid, 'mac': mac, 'name': name,
            'SSID': ssid, 'router_ip': gw, 'MAC_address': mac, 'router_name': name}

# ── Device Name Resolution ────────────────────────────────────────────────────

def resolve_hostname(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host.split('.')[0]
    except Exception:
        pass
    return None

def get_vendor_hint(mac):
    oui_map = {
        '00:50:56': 'VMware VM',    '00:0C:29': 'VMware VM',
        '08:00:27': 'VirtualBox VM','52:54:00': 'QEMU VM',
        'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi', '00:1A:11': 'Google Device',
        'F4:F5:D8': 'Google Device','18:65:90': 'Apple Device',
        'AC:DE:48': 'Apple Device', 'F0:18:98': 'Apple Device',
        '3C:22:FB': 'Apple Device', 'A4:C3:F0': 'Apple Device',
        '00:17:F2': 'Apple Device', 'FC:FB:FB': 'Tenda Router',
        'C8:3A:35': 'Tenda Router', '00:50:F2': 'Microsoft Device',
        '28:D2:44': 'Samsung Device','F8:04:2E': 'Samsung Device',
        'CC:B2:55': 'Samsung Device','8C:79:F0': 'Huawei Device',
        '00:E0:4C': 'Realtek Device','00:1B:63': 'Apple Airport',
    }
    return oui_map.get(mac[:8].upper(), None)

def resolve_device_name(ip, mac):
    hostname = resolve_hostname(ip)
    if hostname and hostname != ip:
        return hostname
    vendor = get_vendor_hint(mac)
    if vendor:
        return vendor
    last_octet = ip.split('.')[-1] if ip else '?'
    return f'Device-{last_octet}'

# ── Auth ──────────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id           = row['user_id']
        self.username     = row['username']
        self.account_type = row['account_type']

@login_manager.user_loader
def load_user(uid):
    if not uid:
        return None
    try:
        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE user_id=?', (uid,)).fetchone()
        conn.close()
        return User(row) if row else None
    except Exception:
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    admin_exists = has_admin()
    if request.method == 'POST':
        username  = request.form['username'].strip()
        password  = request.form['password']
        confirm   = request.form['confirm']
        acct_type = request.form.get('account_type', 'guest')
        if acct_type == 'admin' and admin_exists:
            flash('An admin account already exists.', 'danger')
            return redirect(url_for('login'))
        if not username or not password:
            flash('All fields are required.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
        else:
            try:
                conn = get_db()
                conn.execute('INSERT INTO users (user_id, username, password, account_type) VALUES (?,?,?,?)',
                    (str(uuid.uuid4()), username, generate_password_hash(password), acct_type))
                conn.commit()
                conn.close()
                flash('Account created! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                try: conn.close()
                except Exception: pass
                flash('That username is already taken.', 'danger')
    return render_template('register.html', admin_exists=admin_exists)

@app.route('/login', methods=['GET', 'POST'])
def login():
    admin_exists = has_admin()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if row and check_password_hash(row['password'], password):
            conn.execute('UPDATE users SET last_login=? WHERE user_id=?',
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), row['user_id']))
            conn.commit()
            conn.close()
            login_user(User(row))
            session['last_active'] = time.time()
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        conn.close()
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', admin_exists=admin_exists)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('last_active', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.before_request
def enforce_idle_logout():
    if request.endpoint in (None, 'static', 'login', 'register', 'network_refresh', 'admin_reset'):
        return
    if current_user.is_authenticated:
        now  = time.time()
        last = session.get('last_active')
        if last and (now - last) > SESSION_TIMEOUT:
            logout_user()
            session.pop('last_active', None)
            flash('Logged out due to inactivity.', 'info')
            return redirect(url_for('login'))
        session['last_active'] = now

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    conn      = get_db()
    blacklist = conn.execute('SELECT * FROM blacklist_device').fetchall()
    whitelist = conn.execute('SELECT * FROM whitelist_device').fetchall()
    scan_logs = conn.execute('SELECT * FROM scan_log ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    network = detect_network()
    return render_template('dashboard.html',
        devices=DEVICES, blacklist=blacklist,
        whitelist=whitelist, network=network, scan_logs=scan_logs)

# ── Network ───────────────────────────────────────────────────────────────────

@app.route('/network')
@login_required
def network():
    return render_template('network.html', network=detect_network())

@app.route('/network/refresh')
@login_required
def network_refresh():
    flash('Network information refreshed.', 'success')
    return redirect(url_for('network'))

# ── Scan (parallel hostname resolution for speed) ─────────────────────────────

def is_valid_host_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4: return False
    last, first = int(parts[-1]), int(parts[0])
    if last in (0, 255): return False
    if first == 127 or (224 <= first <= 239): return False
    return True

def is_valid_mac(mac):
    mac = mac.upper()
    if mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'): return False
    return bool(re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac))

def arp_scan():
    devices = []
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output('arp -a', shell=True).decode(errors='ignore')
            for line in out.splitlines():
                m = re.match(r'\s+(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+', line)
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).upper().replace('-', ':')
                    if is_valid_host_ip(ip) and is_valid_mac(mac):
                        devices.append({'ip': ip, 'mac': mac})
        else:
            out = subprocess.check_output(['arp', '-n'], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[2] not in ['<incomplete>', '(incomplete)']:
                    ip, mac = parts[0], parts[2].upper()
                    if is_valid_host_ip(ip) and is_valid_mac(mac):
                        devices.append({'ip': ip, 'mac': mac})
    except Exception:
        pass
    return devices

def resolve_one(d):
    """Resolve a single device's name — used in parallel."""
    return {
        'mac_address':     d['mac'],
        'device_name':     resolve_device_name(d['ip'], d['mac']),
        'ip_address':      d['ip'],
        'signal_strength': 'N/A'
    }

@app.route('/scan')
@login_required
def scan():
    conn    = get_db()
    found   = arp_scan()
    bl_macs = {r['mac_address'] for r in conn.execute('SELECT mac_address FROM blacklist_device').fetchall()}
    wl_macs = {r['mac_address'] for r in conn.execute('SELECT mac_address FROM whitelist_device').fetchall()}
    notes   = {r['mac_address']: r['note'] for r in conn.execute('SELECT * FROM device_notes').fetchall()}

    # Parallel hostname resolution — much faster than sequential
    DEVICES.clear()
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(resolve_one, d): d for d in found}
        for future in as_completed(futures):
            try:
                DEVICES.append(future.result())
            except Exception:
                pass

    # Log the scan
    conn.execute('INSERT INTO scan_log (scanned_at, device_count) VALUES (?,?)',
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), len(found)))
    conn.commit()
    conn.close()

    flash(f'Scan complete. {len(found)} device(s) found.', 'success')
    return render_template('devices.html', devices=DEVICES, bl_macs=bl_macs, wl_macs=wl_macs, notes=notes)

# ── Devices ───────────────────────────────────────────────────────────────────

@app.route('/devices')
@login_required
def devices():
    conn    = get_db()
    bl_macs = {r['mac_address'] for r in conn.execute('SELECT mac_address FROM blacklist_device').fetchall()}
    wl_macs = {r['mac_address'] for r in conn.execute('SELECT mac_address FROM whitelist_device').fetchall()}
    notes   = {r['mac_address']: r['note'] for r in conn.execute('SELECT * FROM device_notes').fetchall()}
    conn.close()
    return render_template('devices.html', devices=DEVICES, bl_macs=bl_macs, wl_macs=wl_macs, notes=notes)

@app.route('/device/block/<mac>')
@login_required
def block_device(mac):
    dev  = next((d for d in DEVICES if d['mac_address'] == mac), None)
    ip   = request.args.get('ip',   dev['ip_address']  if dev else 'Unknown')
    name = request.args.get('name', dev['device_name'] if dev else 'Unknown')
    conn = get_db()
    conn.execute('INSERT OR IGNORE INTO blacklist_device VALUES (?,?,?,?)', (mac, name, ip, 'N/A'))
    conn.commit()
    conn.close()
    if dev:
        try: DEVICES.remove(dev)
        except ValueError: pass
    flash(f'{mac} has been blocked.', 'danger')
    return redirect(url_for('devices'))

@app.route('/device/trust/<mac>')
@login_required
def trust_device(mac):
    dev  = next((d for d in DEVICES if d['mac_address'] == mac), None)
    ip   = request.args.get('ip',   dev['ip_address']  if dev else 'Unknown')
    name = request.args.get('name', dev['device_name'] if dev else 'Unknown')
    conn = get_db()
    conn.execute('INSERT OR IGNORE INTO whitelist_device VALUES (?,?,?,?)', (mac, name, ip, 'N/A'))
    conn.commit()
    conn.close()
    if dev:
        try: DEVICES.remove(dev)
        except ValueError: pass
    flash(f'{mac} has been trusted.', 'success')
    return redirect(url_for('devices'))

@app.route('/device/unblock/<mac>')
@login_required
def unblock_device(mac):
    conn = get_db()
    dev  = conn.execute('SELECT * FROM blacklist_device WHERE mac_address=?', (mac,)).fetchone()
    conn.execute('DELETE FROM blacklist_device WHERE mac_address=?', (mac,))
    conn.commit()
    conn.close()
    if dev and not any(d['mac_address'] == mac for d in DEVICES):
        DEVICES.append({'mac_address': dev['mac_address'], 'device_name': dev['device_name'],
                        'ip_address': dev['ip_address'], 'signal_strength': dev['signal_strength'] or 'N/A'})
    flash(f'{mac} removed from blacklist.', 'info')
    # redirect back to devices page if came from there, else blacklist
    ref = request.args.get('from', 'blacklist')
    return redirect(url_for('devices') if ref == 'devices' else url_for('blacklist'))

@app.route('/device/untrust/<mac>')
@login_required
def untrust_device(mac):
    conn = get_db()
    dev  = conn.execute('SELECT * FROM whitelist_device WHERE mac_address=?', (mac,)).fetchone()
    conn.execute('DELETE FROM whitelist_device WHERE mac_address=?', (mac,))
    conn.commit()
    conn.close()
    if dev and not any(d['mac_address'] == mac for d in DEVICES):
        DEVICES.append({'mac_address': dev['mac_address'], 'device_name': dev['device_name'],
                        'ip_address': dev['ip_address'], 'signal_strength': dev['signal_strength'] or 'N/A'})
    flash(f'{mac} removed from whitelist.', 'info')
    ref = request.args.get('from', 'whitelist')
    return redirect(url_for('devices') if ref == 'devices' else url_for('whitelist'))

# ── Device Notes ──────────────────────────────────────────────────────────────

@app.route('/device/note/<mac>', methods=['POST'])
@login_required
def save_note(mac):
    note = request.form.get('note', '').strip()
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO device_notes (mac_address, note, updated_at) VALUES (?,?,?)',
        (mac, note, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Note saved.', 'success')
    return redirect(url_for('devices'))

# ── Bulk Block/Trust ──────────────────────────────────────────────────────────

@app.route('/device/bulk', methods=['POST'])
@login_required
def bulk_action():
    action = request.form.get('action')
    macs   = request.form.getlist('macs')
    if not macs:
        flash('No devices selected.', 'warning')
        return redirect(url_for('devices'))
    conn = get_db()
    for mac in macs:
        dev  = next((d for d in DEVICES if d['mac_address'] == mac), None)
        ip   = dev['ip_address']  if dev else 'Unknown'
        name = dev['device_name'] if dev else 'Unknown'
        if action == 'block':
            conn.execute('INSERT OR IGNORE INTO blacklist_device VALUES (?,?,?,?)', (mac, name, ip, 'N/A'))
            if dev:
                try: DEVICES.remove(dev)
                except ValueError: pass
        elif action == 'trust':
            conn.execute('INSERT OR IGNORE INTO whitelist_device VALUES (?,?,?,?)', (mac, name, ip, 'N/A'))
            if dev:
                try: DEVICES.remove(dev)
                except ValueError: pass
    conn.commit()
    conn.close()
    flash(f'{len(macs)} device(s) {action}ed.', 'success' if action == 'trust' else 'danger')
    return redirect(url_for('devices'))

# ── Blacklist / Whitelist ─────────────────────────────────────────────────────

@app.route('/blacklist')
@login_required
def blacklist():
    conn = get_db()
    devs = conn.execute('SELECT * FROM blacklist_device').fetchall()
    conn.close()
    return render_template('blacklist.html', devices=devs)

@app.route('/whitelist')
@login_required
def whitelist():
    conn = get_db()
    devs = conn.execute('SELECT * FROM whitelist_device').fetchall()
    conn.close()
    return render_template('whitelist.html', devices=devs)

# ── Scan History ──────────────────────────────────────────────────────────────

@app.route('/scan-history')
@login_required
def scan_history():
    conn  = get_db()
    logs  = conn.execute('SELECT * FROM scan_log ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('scan_history.html', logs=logs)

# ── Views ─────────────────────────────────────────────────────────────────────

@app.route('/views')
@login_required
def views_page():
    conn         = get_db()
    device_status = conn.execute('SELECT * FROM v_device_status').fetchall()
    device_counts = conn.execute('SELECT * FROM v_device_counts').fetchone()
    conn.close()
    return render_template('views.html', device_status=device_status, device_counts=device_counts)

# ── User Management (admin only) ──────────────────────────────────────────────

@app.route('/users')
@login_required
def user_management():
    if current_user.account_type != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    conn  = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY account_type, username').fetchall()
    conn.close()
    return render_template('users.html', users=users)

@app.route('/users/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.account_type != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    if user_id == current_user.id:
        flash('You cannot delete your own account from here. Use Account settings.', 'warning')
        return redirect(url_for('user_management'))
    conn = get_db()
    conn.execute('DELETE FROM users WHERE user_id=?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('user_management'))

# ── Admin Reset ───────────────────────────────────────────────────────────────

@app.route('/admin/reset', methods=['POST', 'GET'])
def admin_reset():
    if request.remote_addr not in ('127.0.0.1', '::1', 'localhost'):
        return "Forbidden", 403
    if request.method == 'POST':
        conn = get_db()
        cur  = conn.execute("DELETE FROM users WHERE account_type='admin'")
        conn.commit()
        conn.close()
        flash(f'Removed existing admin accounts. You can now create a new admin.', 'info')
        return redirect(url_for('register'))
    return '''<form method="post"><p>Reset admin accounts?</p><button type="submit">Confirm</button></form>'''

# ── Account ───────────────────────────────────────────────────────────────────

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE user_id=?', (current_user.id,)).fetchone()
    conn.close()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current_pw = request.form.get('current_password')
            new_pw     = request.form.get('new_password')
            confirm_pw = request.form.get('confirm_password')
            if not check_password_hash(user['password'], current_pw):
                flash('Current password is incorrect.', 'danger')
            elif new_pw != confirm_pw:
                flash('New passwords do not match.', 'danger')
            elif len(new_pw) < 6:
                flash('Password must be at least 6 characters.', 'danger')
            else:
                conn = get_db()
                conn.execute('UPDATE users SET password=? WHERE user_id=?',
                    (generate_password_hash(new_pw), current_user.id))
                conn.commit()
                conn.close()
                flash('Password updated successfully.', 'success')
        elif action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            if not new_username:
                flash('Username cannot be empty.', 'danger')
            else:
                conn = get_db()
                exists = conn.execute('SELECT 1 FROM users WHERE username=? AND user_id<>?',
                    (new_username, current_user.id)).fetchone()
                if exists:
                    conn.close()
                    flash('Username already taken.', 'danger')
                else:
                    try:
                        conn.execute('UPDATE users SET username=? WHERE user_id=?',
                            (new_username, current_user.id))
                        conn.commit()
                        conn.close()
                        flash('Username updated successfully.', 'success')
                    except Exception:
                        conn.close()
                        flash('Could not update username.', 'danger')
    conn  = get_db()
    user  = conn.execute('SELECT * FROM users WHERE user_id=?', (current_user.id,)).fetchone()
    conn.close()
    return render_template('account.html', user=user)

@app.route('/account/delete', methods=['POST'])
@login_required
def delete_account():
    confirm = (request.form.get('confirm_delete') or '').strip()
    if confirm.lower() != (current_user.username or '').lower():
        flash('Username did not match. Account not deleted.', 'danger')
        return redirect(url_for('account'))
    conn = get_db()
    try:
        conn.execute('DELETE FROM users WHERE user_id=?', (current_user.id,))
        conn.commit()
        conn.close()
        logout_user()
        flash('Your account has been deleted.', 'info')
    except Exception:
        try: conn.close()
        except Exception: pass
        flash('Could not delete account.', 'danger')
    return redirect(url_for('register'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
