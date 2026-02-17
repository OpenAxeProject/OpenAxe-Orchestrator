window.lastShareCount = -1;

function showToast(msg, isError=false) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast' + (isError ? ' error' : '');
    toast.innerHTML = (isError ? '❌ ' : '✅ ') + msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function spawnStar() {
    const container = document.getElementById('star-layer');
    const star = document.createElement('div');
    star.classList.add('star');
    star.innerHTML = Math.random() > 0.5 ? '🪙' : '💰';
    star.style.left = (Math.random() * window.innerWidth) + 'px';
    star.style.animationDuration = (Math.random() * 1 + 1.5) + 's';
    container.appendChild(star);
    setTimeout(() => star.remove(), 2500);
}

function checkShares(miners) {
    let total = 0;
    if(miners && miners.length > 0) {
        miners.forEach(m => { if(m.stats && m.stats.sharesAccepted) total += m.stats.sharesAccepted; });
    }
    if (window.lastShareCount !== -1 && total > window.lastShareCount) {
        const diff = total - window.lastShareCount;
        const stars = Math.min(diff, 10);
        for(let i=0; i<stars; i++) setTimeout(spawnStar, i * 300);
    }
    window.lastShareCount = total;
}

function updateLogic() {
    fetch('/api/miners')
        .then(r=>r.json())
        .then(d=>{ 
            checkShares(d.miners); 
            if(d.fleet_stats && d.fleet_stats.fleet_best_share) {
                document.getElementById('bestShareVal').innerText = d.fleet_stats.fleet_best_share;
            }
            if(d.fleet_stats && d.fleet_stats.fleet_power_cost) {
                document.getElementById('powerCostVal').innerText = '$' + d.fleet_stats.fleet_power_cost.toFixed(2);
            }
        })
        .catch(err => console.log("Miner fetch error", err));

    fetch('/api/logic')
        .then(r=>r.json())
        .then(d=>{
            document.getElementById('logic-log').innerHTML = d.logs.map(l => `<div class="log-entry">${l}</div>`).join('');
        });
}

function reboot(ip) { 
    if(confirm('Reboot ' + ip + '?')) 
        fetch('/api/reboot', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip:ip})})
        .then(r=>showToast('Reboot Sent')); 
}

function scan() { 
    showToast('Scanning network...', false); 
    const btn = document.getElementById('scanBtn');
    const spinner = document.getElementById('scanSpinner');
    const originalText = document.getElementById('scanText');
    spinner.classList.remove('hidden'); originalText.innerText = "SCANNING..."; btn.disabled = true;
    fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({subnet:document.getElementById('subnetInput').value})})
    .then(r=>r.json()).then(d=>{ showToast('Found ' + d.found + ' miners.'); spinner.classList.add('hidden'); originalText.innerText = "SCAN"; btn.disabled = false; })
    .catch(e=>{ showToast('Error scanning', true); spinner.classList.add('hidden'); originalText.innerText = "SCAN"; btn.disabled = false; });
}

function applyToFleet() {
    if(confirm("Force update ALL miners to current strategy?")) {
        fetch('/api/update_fleet', {method:'POST'}).then(r=>r.json()).then(d=>showToast('Updated ' + d.updated + ' miners.'));
    }
}

function toggleCoin(coin) {
    const el = document.getElementById('chip-' + coin);
    el.classList.toggle('active');
    saveSettings();
}

function handleManualToggle() {
    const isManual = document.getElementById('manualMode').checked;
    const controls = document.getElementById('manualControls');
    controls.style.display = isManual ? 'block' : 'none';
    saveSettings();
}

function handleSliderChange(val) {
    document.getElementById('riskVal').innerText = val + '% Hunters';
    saveSettings();
}

function saveSettings() {
    const getVal = (id) => document.getElementById(id).value;
    const getChk = (id) => document.getElementById(id).checked;
    
    const disabled = [];
    document.querySelectorAll('.chip').forEach(c => {
        if(!c.classList.contains('active')) disabled.push(c.dataset.coin);
    });

    const payload = {
        ntfy_topic: getVal('ntfyTopic'), nostr_privkey: getVal('nostrPriv'), nostr_recipient_pubkey: getVal('nostrPub'),
        mining_dutch_api_key: getVal('mdApiKey'),
        temp_limit: parseInt(getVal('tempLimit')),
        hash_threshold: parseInt(getVal('hashThreshold')),
        risk_level: parseInt(getVal('riskSlider')),
        smart_hedge: getChk('smartHedge'),
        manual_mode: getChk('manualMode'),
        manual_hunter: getVal('manualHunter'),
        manual_farmer: getVal('manualFarmer'),
        snipe_coin: getVal('snipeCoin'),
        disabled_coins: disabled,
        power_cost_kwh: parseFloat(getVal('powerCostInput')),
        tuning_mode: getVal('tuningMode'),
        notify_offline: getChk('notifOffline'),
        notify_switch: getChk('notifSwitch'),
        notify_zombie: getChk('notifZombie'),
        notify_block_found: getChk('notifBlock'),
        pools: {
            BTC: { url: getVal('btcUrl'), user: getVal('btcUser') },
            BC2: { url: getVal('bc2Url'), user: getVal('bc2User') },
            BCH: { url: getVal('bchUrl'), user: getVal('bchUser') },
            BSV: { url: getVal('bsvUrl'), user: getVal('bsvUser') },
            DGB: { url: getVal('dgbUrl'), user: getVal('dgbUser') },
            PPC: { url: getVal('ppcUrl'), user: getVal('ppcUser') },
            FB:  { url: getVal('fbUrl'),  user: getVal('fbUser')  },
            MD:  { url: getVal('mdUrl'),  user: getVal('mdUser'), pass: getVal('mdPass') } 
        }
    };
    fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)})
        .then(r => showToast("Settings Saved"));
}

document.addEventListener("DOMContentLoaded", function() {
    const slider = document.getElementById('riskSlider');
    if(slider) document.getElementById('riskVal').innerText = slider.value + '% Hunters';

    const manualToggle = document.getElementById('manualMode');
    const manualControls = document.getElementById('manualControls');
    if(manualToggle && manualControls) {
        manualControls.style.display = manualToggle.checked ? 'block' : 'none';
    }
});

setInterval(updateLogic, 2000);
setInterval(() => location.reload(), 60000);
