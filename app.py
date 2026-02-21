import logging
import sys
import json
import os
import threading
import time
import queue
import requests
import ipaddress
import socket
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from collections import deque
import pytz

try:
    from pynostr.key import PrivateKey
    from pynostr.relay_manager import RelayManager
    from pynostr.encrypted_dm import EncryptedDirectMessage
    NOSTR_AVAILABLE = True
except ImportError:
    NOSTR_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

app = Flask(__name__)

DATA_FILE = "miners.json"
SETTINGS_FILE = "settings.json"
MY_TIMEZONE = "America/New_York"

CHECK_INTERVAL = 60         
DIFF_DROP_THRESHOLD = 0.15  
PROFIT_BUFFER = 1.05        
ZOMBIE_THRESHOLD_MINS = 10 

LOGIC_LOG = deque(maxlen=50)
LOOP_TRIGGER = threading.Event()
NOSTR_QUEUE = queue.Queue()

DEFAULT_SETTINGS = {
    "ntfy_server": "https://ntfy.sh",
    "ntfy_topic": f"openaxe_{os.urandom(4).hex()}",
    "notify_offline": True,
    "notify_switch": True,
    "notify_zombie": True,
    "notify_block_found": True,
    "auto_update_miners": True,
    "temp_limit": 75,
    "hash_threshold": 300,
    "risk_level": 50,
    "smart_hedge": False,
    "manual_mode": False,
    "manual_hunter": "BTC",
    "manual_farmer": "FB",
    "snipe_coin": "BC2",
    "tuning_mode": "stock",
    "power_cost_kwh": 0.12,
    "disabled_coins": [],
    "mining_dutch_api_key": "",
    "whatsonchain_api_key": "mainnet_4fd725c96c6791e70782e36e4cdf4d3c",
    "nostr_privkey": "",
    "nostr_recipient_pubkey": "",
    "pools": {
        "BC2": {"url": "", "user": "", "pass": "x"},
        "BTC": {"url": "", "user": "", "pass": "x"},
        "BCH": {"url": "", "user": "", "pass": "x"},
        "BSV": {"url": "", "user": "", "pass": "x"},
        "DGB": {"url": "", "user": "", "pass": "x"},
        "PPC": {"url": "", "user": "", "pass": "x"},
        "FB":  {"url": "", "user": "", "pass": "x"},
        "MD":  {"url": "stratum+tcp://sha256.mining-dutch.nl:9996", "user": "", "pass": "d=3156.4"}
    }
}

TUNING_PROFILES = {
    "BM1368": {"eco": {"frequency": 485, "coreVoltage": 1100}, "stock": {"frequency": 525, "coreVoltage": 1150}, "turbo": {"frequency": 575, "coreVoltage": 1250}},
    "BM1370": {"eco": {"frequency": 485, "coreVoltage": 1100}, "stock": {"frequency": 525, "coreVoltage": 1150}, "turbo": {"frequency": 625, "coreVoltage": 1250}},
    "default": {"eco": {"frequency": 485, "coreVoltage": 1100}, "stock": {"frequency": 525, "coreVoltage": 1150}, "turbo": {"frequency": 550, "coreVoltage": 1200}}
}

def deep_merge(base, update):
    for k, v in update.items():
        if isinstance(v, dict) and k in base and isinstance(base[k], dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def load_settings():
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f: 
                file_data = json.load(f)
                deep_merge(settings, file_data)
        except Exception as e: logger.error(f"Settings load error: {e}")
    return settings

def load_miners():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f: return json.load(f)
        except: pass
    return []

def save_json(file, data):
    try:
        with open(file, 'w') as f: json.dump(data, f, indent=2)
    except Exception as e: logger.error(f"Save failed: {e}")

DB = {
    "miners": load_miners(),
    "settings": load_settings()
}

POOLS_API = {
    "BC2": {"type": "bc2_explorer", "url_diff": "https://bc2explorer.com/api/v1/live-diff", "url_price": "https://bc2explorer.com/api/v1/lastprice"},
    "BTC": {"type": "blockchair", "url": "https://api.blockchair.com/bitcoin/stats", "cg_id": "bitcoin"},
    "BCH": {"type": "blockchair", "url": "https://api.blockchair.com/bitcoin-cash/stats", "cg_id": "bitcoin-cash"},
    "BSV": {"type": "whatsonchain", "url_diff": "https://api.whatsonchain.com/v1/bsv/main/chain/info", "url_price": "https://api.whatsonchain.com/v1/bsv/main/exchangerate", "cg_id": "bitcoin-sv"},
    "DGB": {"type": "mixed", "url_diff": "https://www.mining-dutch.nl/pools/digibyte_sha256.php?page=api&action=getdashboarddata&api_key=", "url_price": "https://chainz.cryptoid.info/dgb/api.dws?q=ticker.usd", "cg_id": "digibyte"},
    "PPC": {"type": "mixed_ppc", "url_diff": "https://www.mining-dutch.nl/pools/peercoin.php?page=api&action=getdashboarddata&api_key=", "url_price": "https://chainz.cryptoid.info/ppc/api.dws?q=ticker.usd", "cg_id": "peercoin"},
    "FB":  {"type": "md_dashboard", "url_diff": "https://www.mining-dutch.nl/pools/fractalbitcoin.php?page=api&action=getdashboarddata&api_key=", "cg_id": "fractal-bitcoin"},
    "MD":  {"type": "miningdutch", "url": "https://www.mining-dutch.nl/pools/sha256.php?page=api&action=getdashboarddata&api_key="}
}

state = {
    "current_coin": "BTC",
    "difficulty": "Pending...",
    "baseline_diff": None,
    "diff_change_pct": 0.0,
    "last_update": "Never",
    "reason": "Startup",
    "fleet_hash": 0,
    "fleet_best_share": "0",
    "fleet_power_cost": 0.0,
    "active_miners": 0,
    "market_stats": {},
    "blocks_found": 0,
    "alerts": [],
    "last_snipe_coin": "BC2"
}

def send_ntfy(message, title="Mining Alert", tags="warning", alert_type="general"):
    s = DB['settings']
    if alert_type == "offline" and not s.get("notify_offline", True): return
    if alert_type == "switch" and not s.get("notify_switch", True): return
    if alert_type == "zombie" and not s.get("notify_zombie", True): return
    if alert_type == "block" and not s.get("notify_block_found", True): return

    if s.get('ntfy_topic'):
        try:
            requests.post(f"{s['ntfy_server']}/{s['ntfy_topic']}", 
                          data=message.encode('utf-8'), 
                          headers={"Title": title.encode('utf-8'), "Tags": tags}, timeout=5)
        except: pass

def send_nostr(message):
    if not NOSTR_AVAILABLE: return
    s = DB['settings']
    if s.get('nostr_privkey') and s.get('nostr_recipient_pubkey'):
        NOSTR_QUEUE.put((message, s['nostr_privkey'], s['nostr_recipient_pubkey']))

def nostr_worker():
    while True:
        try:
            item = NOSTR_QUEUE.get()
            msg, priv, pub = item
            try:
                pk = PrivateKey.from_hex(priv)
                dm = EncryptedDirectMessage()
                dm.encrypt(pk.hex(), recipient_pubkey=pub, cleartext_content=msg)
                event = dm.to_event()
                event.sign(pk.hex())
                rm = RelayManager(timeout=5)
                rm.add_relay("wss://nostr.mom")
                rm.publish_event(event)
                rm.run_sync()
            except Exception as e: logger.error(f"Nostr Error: {e}")
            NOSTR_QUEUE.task_done()
        except: time.sleep(1)

def log_decision(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    LOGIC_LOG.appendleft(f"[{ts}] {msg}")

def human_readable_diff(num):
    if num is None or num == 0: return "0"
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E']:
        if abs(num) < 1000.0: return f"{num:3.2f} {unit}"
        num /= 1000.0
    return f"{num:.2f} Z"

def get_cg_price(cg_id):
    try:
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={cg_id}&vs_currencies=usd"
        r = requests.get(url, timeout=5).json()
        return float(r.get(cg_id, {}).get('usd', 0))
    except: return 0

def fetch_data(coin_key):
    config = POOLS_API[coin_key]
    headers = {'User-Agent': 'Mozilla/5.0'}
    diff = 0
    price = 0
    try:
        if config.get('type') == "blockchair":
            r = requests.get(config['url'], headers=headers, timeout=5).json()
            data = r.get('data', {})
            diff = float(data.get("difficulty", 0))
            price = float(data.get("market_price_usd", 0))
        elif coin_key == "BSV":
            woc_key = DB['settings'].get('whatsonchain_api_key', '')
            r_diff = requests.get(config['url_diff'], headers={'Authorization': woc_key}, timeout=5).json()
            r_price = requests.get(config['url_price'], headers={'Authorization': woc_key}, timeout=5).json()
            diff = float(r_diff.get("difficulty", 0))
            price = float(r_price.get("rate", 0))
        elif coin_key == "BC2":
            try:
                r_diff = requests.get(config['url_diff'], headers=headers, timeout=5).json()
                diff = float(r_diff.get("difficulty", 0))
            except: pass
            try:
                price = float(requests.get(config['url_price'], headers=headers, timeout=5).text)
            except: pass
        elif coin_key in ["DGB", "PPC", "FB"]:
            try:
                api_key = DB['settings'].get('mining_dutch_api_key', '')
                url = f"{config['url_diff']}{api_key}"
                md_r = requests.get(url, headers=headers, timeout=5).json()
                diff = float(md_r.get('getdashboarddata', {}).get('data', {}).get('network', {}).get('difficulty', 0))
            except: pass
            if 'url_price' in config:
                try:
                    price = float(requests.get(config['url_price'], headers=headers, timeout=5).text)
                except: pass
        elif coin_key == "MD":
            return 1, 0.00002

        if price == 0 and config.get('cg_id'):
            price = get_cg_price(config['cg_id'])

    except Exception as e: return 0, 0
    return diff, price

def fetch_md_user_stats():
    api_key = DB['settings'].get('mining_dutch_api_key')
    if not api_key: return
    url = f"{POOLS_API['MD']['url']}{api_key}"
    try:
        r = requests.get(url, timeout=5).json()
    except: pass

def scan_network_advanced(cidr):
    found = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05)
                if sock.connect_ex((ip_str, 80)) == 0:
                    try:
                        r = requests.get(f"http://{ip_str}/api/system/info", timeout=0.5)
                        if r.status_code == 200 and 'hashRate' in r.json():
                            found.append({"ip": ip_str, "type": "Bitaxe", "hostname": r.json().get("hostname", "Unknown")})
                    except: pass
                sock.close()
            except: pass
    except ValueError: return []
    return found

def push_config_to_miner(ip, pool_config):
    raw_url = pool_config.get('url', '')
    if not raw_url: return False

    target_host = raw_url
    target_port = 3333
    if ':' in raw_url:
        try:
            parts = raw_url.split(':')
            h = parts[-2] if '//' in raw_url else parts[0]
            target_host = h.replace('stratum+tcp://', '')
            target_port = int(parts[-1])
        except: pass
    else:
        target_host = raw_url.replace('stratum+tcp://', '')

    try:
        try:
            r = requests.get(f"http://{ip}/api/system/info", timeout=3).json()
            asic_model = r.get('ASICModel', 'default')
            hostname = r.get('hostname', 'worker')
            curr_url = str(r.get('stratumURL', '')).replace('stratum+tcp://', '').strip()
            curr_port = int(r.get('stratumPort', 3333))
            curr_user = str(r.get('stratumUser', '')).strip()
            curr_freq = int(r.get('frequency', 0))
            curr_volt = int(r.get('coreVoltage', 0))
        except: 
            return False

        user = pool_config.get('user', '')
        if hostname and not user.endswith(f".{hostname}"):
            user = f"{user}.{hostname}"
        
        mode = DB['settings'].get('tuning_mode', 'stock')
        device_profiles = TUNING_PROFILES.get(asic_model, TUNING_PROFILES['default'])
        profile = device_profiles.get(mode, device_profiles['stock'])
        
        target_freq = profile['frequency']
        target_volt = profile['coreVoltage']

        if (curr_url == target_host.strip() and 
            curr_port == target_port and 
            curr_user == user and
            curr_freq == target_freq and 
            curr_volt == target_volt):
            return False 

        logger.info(f"UPDATING {ip} -> {mode.upper()} mode on {user}")

        password = pool_config.get('pass', 'x')
        payload = {
            "stratumURL": target_host, 
            "stratumPort": target_port, 
            "stratumUser": user, 
            "stratumPass": password,
            "frequency": target_freq,
            "coreVoltage": target_volt
        }
        r = requests.patch(f"http://{ip}/api/system", json=payload, timeout=5)
        if r.status_code == 200:
            requests.post(f"http://{ip}/api/system/restart", timeout=5)
            return True
    except Exception as e: logger.error(f"Push Failed {ip}: {e}")
    return False

def update_market_stats():
    stats = {}
    coins = ["BTC", "BCH", "BSV", "BC2", "DGB", "PPC", "FB"]
    disabled = DB['settings'].get('disabled_coins', [])
    
    for c in coins:
        if c in disabled:
            stats[c] = {"diff": 0, "price": 0, "score": 0, "disabled": True}
        else:
            d, p = fetch_data(c)
            score = (p/d)*1e12 if d > 0 else 0
            stats[c] = {"diff": d, "price": p, "score": score, "disabled": False}
    
    if "MD" in disabled:
        stats["MD"] = {"diff": 0, "price": 0, "score": 0, "disabled": True}
    else:
        stats["MD"] = {"diff": 0, "price": 0, "score": 0.00002, "disabled": False}

    state['market_stats'] = stats
    
    hunter_candidates = [c for c in ["BTC", "BCH", "BSV", "BC2"] if not stats[c].get("disabled")]
    best_hunter = "BTC"
    high_score = -1
    if hunter_candidates:
        best_hunter = hunter_candidates[0]
        high_score = stats[best_hunter]["score"]
        for coin in hunter_candidates:
            if stats[coin]["score"] > high_score * PROFIT_BUFFER:
                high_score = stats[coin]["score"]
                best_hunter = coin
                
    farmer_candidates = [c for c in ["DGB", "PPC", "FB"] if not stats[c].get("disabled")]
    best_farmer = "FB"
    high_f_score = -1
    if farmer_candidates:
        best_farmer = farmer_candidates[0]
        high_f_score = stats[best_farmer]["score"]
        for coin in farmer_candidates:
            if stats[coin]["score"] > high_f_score:
                high_f_score = stats[coin]["score"]
                best_farmer = coin

    return best_hunter, best_farmer

def logic_loop():
    global state
    while True:
        try:
            tz = pytz.timezone(MY_TIMEZONE)
            
            snipe_target = DB['settings'].get('snipe_coin', 'BC2')
            if snipe_target != state.get('last_snipe_coin'):
                state['baseline_diff'] = None
                state['last_snipe_coin'] = snipe_target

            curr_diff, _ = fetch_data(snipe_target)
            if curr_diff > 0:
                if state["baseline_diff"] is None: state["baseline_diff"] = curr_diff
                diff_change = (curr_diff - state["baseline_diff"]) / state["baseline_diff"]
                state["diff_change_pct"] = diff_change * 100
            else: diff_change = 0

            auto_hunter, auto_farmer = update_market_stats()
            fetch_md_user_stats()
            
            if DB['settings'].get('manual_mode'):
                hunter_coin = DB['settings'].get('manual_hunter', 'BTC')
                farmer_coin = DB['settings'].get('manual_farmer', 'FB')
                reason = "MANUAL OVERRIDE"
                current_risk = int(DB['settings'].get('risk_level', 50))
            else:
                hunter_coin = auto_hunter
                farmer_coin = auto_farmer
                current_risk = int(DB['settings'].get('risk_level', 50))
                
                if diff_change <= -DIFF_DROP_THRESHOLD and snipe_target not in DB['settings'].get('disabled_coins', []):
                    hunter_coin = snipe_target
                    farmer_coin = snipe_target
                    reason = f"SNIPE! {snipe_target} Drop: {abs(state['diff_change_pct']):.1f}%"
                    current_risk = 100
                elif DB['settings'].get('smart_hedge'):
                     reason = f"Auto ({hunter_coin} + {farmer_coin})"
                else:
                    reason = f"Auto ({hunter_coin} + {farmer_coin})"
                    if curr_diff > 0: state["baseline_diff"] = (state["baseline_diff"] * 0.95) + (curr_diff * 0.05)

            last_hunter = state.get("hunter_coin")
            last_farmer = state.get("farmer_coin")
            last_risk = state.get("last_risk")
            last_manual = state.get("last_manual_state")
            last_tuning = state.get("last_tuning")
            current_tuning = DB['settings'].get('tuning_mode', 'stock')
            is_manual = DB['settings'].get('manual_mode')

            needs_update = False
            if hunter_coin != last_hunter: needs_update = True
            if farmer_coin != last_farmer: needs_update = True
            if current_risk != last_risk: needs_update = True
            if is_manual != last_manual: needs_update = True
            if current_tuning != last_tuning: needs_update = True

            if needs_update:
                log_decision(f"UPDATE: {reason} (Risk: {current_risk}%, Tune: {current_tuning})")
                miners = sorted(DB['miners'], key=lambda x: x['ip'])
                split_index = int(len(miners) * (current_risk / 100))
                
                for i, m in enumerate(miners):
                    target_cfg = DB['settings']['pools'].get(hunter_coin if i < split_index else farmer_coin)
                    push_config_to_miner(m['ip'], target_cfg)
                
                send_ntfy(f"Switch: {hunter_coin}/{farmer_coin} @ {current_risk}%", "STRATEGY CHANGE", "rocket", "switch")

            state["current_coin"] = f"{hunter_coin} / {farmer_coin}"
            state["hunter_coin"] = hunter_coin
            state["farmer_coin"] = farmer_coin
            state["last_risk"] = current_risk
            state["last_manual_state"] = is_manual
            state["last_tuning"] = current_tuning
            state["reason"] = reason

            active_diff = state['market_stats'].get(hunter_coin, {}).get('diff', 0)
            state["difficulty"] = human_readable_diff(active_diff)
            state["last_update"] = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
            
        except Exception as e: logger.error(f"Logic Error: {e}")
        LOOP_TRIGGER.wait(CHECK_INTERVAL)
        LOOP_TRIGGER.clear()

def fleet_monitor():
    while True:
        total_hash = 0
        total_watts = 0
        total_blocks = 0
        active = 0
        global_best_share = 0
        alerts = []
        temp_limit = int(DB['settings'].get('temp_limit', 75))
        hash_threshold = int(DB['settings'].get('hash_threshold', 300))
        power_cost = float(DB['settings'].get('power_cost_kwh', 0.12))

        for m in DB['miners']:
            try:
                r = requests.get(f"http://{m['ip']}/api/system/info", timeout=2).json()
                curr_temp = r.get('temp', 0); curr_hash = r.get('hashRate', 0)
                curr_power = r.get('power', 15) 
                curr_shares = r.get('sharesAccepted', 0)
                curr_blocks = r.get('blockFound', 0)
                asic_model = r.get('ASICModel', 'Unknown')
                
                last_shares = m.get('last_shares', 0)
                last_time = m.get('last_time', time.time())
                is_zombie = False
                
                if curr_hash > 500 and curr_shares == last_shares:
                    if (time.time() - last_time) > (ZOMBIE_THRESHOLD_MINS * 60):
                        is_zombie = True
                        alerts.append(f"ZOMBIE: {m['ip']} - No shares for 10m!")
                        if not m.get('zombie_alert_sent'):
                            send_ntfy(f"ZOMBIE DETECTED: {m['ip']}", "ZOMBIE ALERT", "zombie", "zombie")
                            m['zombie_alert_sent'] = True
                else:
                    m['last_shares'] = curr_shares
                    m['last_time'] = time.time()
                    m['zombie_alert_sent'] = False

                curr_best = r.get('bestDiff', 0)
                if curr_best > global_best_share: global_best_share = curr_best

                if curr_temp > temp_limit: alerts.append(f"OVERHEAT: {m['ip']} at {curr_temp}°C")
                if hash_threshold > 0 and curr_hash < hash_threshold: alerts.append(f"RUNT: {m['ip']} low hash")

                if m.get('offline_alert_sent'): m['offline_alert_sent'] = False

                m['stats'] = {
                    'connected': True, 
                    'hashRate': curr_hash, 
                    'temp': curr_temp, 
                    'power': curr_power,
                    'zombie': is_zombie,
                    'stratumUser': r.get('stratumUser', ''),
                    'sharesAccepted': curr_shares,
                    'asicModel': asic_model
                }
                total_hash += curr_hash
                total_watts += curr_power
                total_blocks += curr_blocks
                active += 1
            except: 
                if not m.get('offline_alert_sent', False):
                    send_ntfy(f"{m['ip']} went OFFLINE", "MINER DOWN", "skull", "offline")
                    m['offline_alert_sent'] = True
                m['stats'] = {'connected': False}
        
        daily_cost = (total_watts * 24 / 1000) * power_cost
        state['fleet_power_cost'] = daily_cost
        state['fleet_hash'] = total_hash
        state['fleet_best_share'] = human_readable_diff(global_best_share)
        state['active_miners'] = active
        state['alerts'] = alerts
        state['blocks_found'] = total_blocks
        save_json(DATA_FILE, DB['miners'])
        time.sleep(15)

@app.route('/')
def index(): return render_template('dashboard.html', state=state, settings=DB['settings'])

@app.route('/public')
def public_page():
    ctx = state.copy()
    ctx['miners_public'] = [{"id": f"Worker-{i+1}", "status": "ONLINE" if m.get('stats', {}).get('connected') else "OFFLINE", "hashrate": m.get('stats', {}).get('hashRate', 0)} for i, m in enumerate(DB['miners'])]
    return render_template('public.html', state=ctx)

@app.route('/api/miners')
def api_miners(): return jsonify({"miners": DB['miners'], "fleet_stats": state})

@app.route('/api/logic')
def api_logic(): return jsonify({"logs": list(LOGIC_LOG)})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    subnet = request.json.get('subnet', '192.168.1.0/24')
    found = scan_network_advanced(subnet)
    existing_ips = {m['ip'] for m in DB['miners']}
    new_count = 0
    for d in found:
        if d['ip'] not in existing_ips: DB['miners'].append(d); new_count += 1
    save_json(DATA_FILE, DB['miners'])
    return jsonify({"status": "ok", "found": new_count})

@app.route('/api/reboot', methods=['POST'])
def api_reboot():
    ip = request.json.get('ip')
    try: requests.post(f"http://{ip}/api/system/reboot", timeout=3); return jsonify({"status": "ok"})
    except: return jsonify({"status": "error"}), 500

@app.route('/api/settings', methods=['POST'])
def api_settings():
    new_data = request.json
    if 'pools' in new_data:
        DB['settings'].setdefault('pools', {})
        for coin, data in new_data['pools'].items():
            if coin not in DB['settings']['pools']: DB['settings']['pools'][coin] = {}
            DB['settings']['pools'][coin].update(data)
        del new_data['pools']
    DB['settings'].update(new_data)
    save_json(SETTINGS_FILE, DB['settings'])
    LOOP_TRIGGER.set() 
    return jsonify({"status": "ok"})

@app.route('/api/reset_settings', methods=['POST'])
def api_reset_settings():
    if os.path.exists(SETTINGS_FILE): os.remove(SETTINGS_FILE)
    DB['settings'] = json.loads(json.dumps(DEFAULT_SETTINGS))
    save_json(SETTINGS_FILE, DB['settings'])
    LOOP_TRIGGER.set()
    return jsonify({"status": "ok"})

@app.route('/api/update_fleet', methods=['POST'])
def api_update_fleet():
    hunter = state.get("hunter_coin", "BTC")
    farmer = state.get("farmer_coin", "MD")
    current_risk = DB['settings'].get('risk_level', 50)
    miners = sorted(DB['miners'], key=lambda x: x['ip'])
    split_index = int(len(miners) * (current_risk / 100))
    count = 0
    for i, m in enumerate(miners):
        target_cfg = DB['settings']['pools'].get(hunter if i < split_index else farmer)
        if push_config_to_miner(m['ip'], target_cfg): count += 1
    return jsonify({"status": "ok", "updated": count})

@app.context_processor
def inject_db(): return dict(context=DB)

if __name__ == '__main__':
    if NOSTR_AVAILABLE: threading.Thread(target=nostr_worker, daemon=True).start()
    threading.Thread(target=fleet_monitor, daemon=True).start()
    threading.Thread(target=logic_loop, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
