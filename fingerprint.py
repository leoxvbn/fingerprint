#!/usr/bin/env python3
import os

"""
Network & Browser Fingerprint Server — Extended Edition
Зависимости: только стандартная библиотека Python 3
"""

import json
import socket
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# ── Утилиты ──────────────────────────────────────────────────────────────────

def _fetch(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return {}

def get_ip_info(ip):
    return _fetch(f'https://ipinfo.io/{ip}/json')

def get_proxycheck(ip):
    return _fetch(f'https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7')

def get_ipqualityscore(ip):
    # Публичный endpoint без ключа (ограниченный)
    return _fetch(f'https://ipqualityscore.com/api/json/ip/YOUR_KEY/{ip}')

def tcp_fingerprint(handler):
    """
    Грубая оценка ОС по TTL из заголовков (точный TCP fingerprint требует
    raw sockets / libpcap — здесь даём то, что видно на уровне HTTP).
    """
    ttl_hint = None
    via = handler.headers.get('Via', '')
    # Некоторые прокси/VPN добавляют Via или X-Forwarded-For цепочку
    forwarded_for = handler.headers.get('X-Forwarded-For', '')
    return {
        "via": via or None,
        "forwarded_for_chain": forwarded_for or None,
        "note": "Full TCP/TTL fingerprint requires raw socket capture (e.g. p0f/nmap)"
    }

def http2_header_order(handler):
    """
    HTTP/2 fingerprint: порядок псевдо-заголовков виден только при HTTP/2.
    В стандартном HTTPServer мы получаем уже распакованные заголовки —
    реальный h2 fingerprint (HPACK order) нужен через asyncio+h2 или nginx log.
    """
    order = list(handler.headers.keys())
    return {
        "header_order": order,
        "note": "Full HTTP/2 HPACK fingerprint requires h2-aware proxy (e.g. nginx + nghttp2)"
    }

# ── Определение VPN по заголовкам ────────────────────────────────────────────

VPN_HEADERS = [
    # Туннельные / прокси заголовки
    'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
    'X-ProxyUser-Ip', 'X-Remote-IP', 'X-Remote-Addr',
    'X-Client-IP', 'CF-Connecting-IP', 'True-Client-IP',
    'Forwarded', 'Via', 'X-Via', 'Proxy-Connection',
    # WireGuard / OpenVPN клиенты иногда добавляют
    'X-Tunnel-Type', 'X-Vpn-Client',
    # Tor exit nodes
    'X-Tor-Exit',
]

UTUN_HINT_HEADERS = [
    # macOS utun интерфейс — WireGuard/OpenVPN на маке иногда протекает через эти
    'X-Apple-Utun', 'X-Utun-Interface',
]

def detect_vpn_headers(headers):
    found = {}
    for h in VPN_HEADERS + UTUN_HINT_HEADERS:
        val = headers.get(h)
        if val:
            found[h] = val
    return found


# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fingerprint</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace;padding:16px}
h1{color:#00ff88;margin-bottom:10px;font-size:1.3em}
h2{color:#00aaff;margin:0 0 8px;font-size:.9em;border-bottom:1px solid #333;padding-bottom:4px}
.section{background:#111;border:1px solid #222;border-radius:6px;padding:12px;margin-bottom:12px}
.row{display:flex;padding:3px 0;border-bottom:1px solid #1a1a1a;gap:8px}
.row:last-child{border-bottom:none}
.label{color:#888;width:200px;flex-shrink:0;font-size:.78em}
.value{color:#fff;font-size:.78em;word-break:break-all}
.green{color:#00ff88}.red{color:#ff4444}.yellow{color:#ffaa00}.blue{color:#00aaff}
#status{color:#888;margin-bottom:10px;font-size:.85em}
.sub{color:#00aaff;font-size:.78em;margin:8px 0 4px;font-weight:bold}
.toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.btn{background:#1a1a1a;border:1px solid #333;color:#e0e0e0;padding:7px 14px;border-radius:5px;cursor:pointer;font-family:'Courier New',monospace;font-size:.8em;transition:background .2s}
.btn:hover{background:#252525;border-color:#555}
.btn.green-btn{border-color:#00ff88;color:#00ff88}
.btn.blue-btn{border-color:#00aaff;color:#00aaff}
.btn.yellow-btn{border-color:#ffaa00;color:#ffaa00}
.toast{position:fixed;bottom:20px;right:20px;background:#1a1a1a;border:1px solid #00ff88;color:#00ff88;padding:10px 18px;border-radius:6px;font-size:.8em;opacity:0;transition:opacity .3s;pointer-events:none;z-index:999}
@media print{.toolbar{display:none}body{background:#fff;color:#000}h1,h2{color:#000}.section{border:1px solid #ccc}.label{color:#555}.value{color:#000}.sub{color:#333}}
</style>
</head>
<body>
<h1>🔍 Fingerprint — Extended</h1>
<div id="status">⏳ Collecting...</div>

<div class="toolbar">
  <button class="btn green-btn" onclick="exportJSON()">⬇ Export JSON</button>
  <button class="btn blue-btn"  onclick="copyAll()">📋 Copy All</button>
  <button class="btn yellow-btn" onclick="window.print()">🖨 Print / PDF</button>
</div>
<div class="toast" id="toast"></div>

<div class="section" id="s_server"><h2>📡 Server Side + VPN Detection</h2><div style="color:#888;font-size:.8em">Loading...</div></div>
<div class="section" id="s_browser"><h2>🌐 Browser / Device</h2><div style="color:#888;font-size:.8em">Loading...</div></div>
<div class="section" id="s_features"><h2>🔌 API Features</h2><div style="color:#888;font-size:.8em">Loading...</div></div>
<div class="section" id="s_permissions"><h2>🔒 Permissions & Media Devices</h2><div style="color:#888;font-size:.8em">Checking...</div></div>
<div class="section" id="s_webrtc"><h2>📹 WebRTC / IP Leak</h2><div style="color:#888;font-size:.8em">Checking...</div></div>
<div class="section" id="s_canvas"><h2>🎨 Canvas / WebGL / Audio</h2><div style="color:#888;font-size:.8em">Rendering...</div></div>
<div class="section" id="s_css"><h2>🎭 CSS / Display Features</h2><div style="color:#888;font-size:.8em">Loading...</div></div>
<div class="section" id="s_fonts"><h2>🔤 Font Fingerprint</h2><div style="color:#888;font-size:.8em">Probing...</div></div>
<div class="section" id="s_advanced"><h2>⚡ Advanced / Incognito / Sandbox</h2><div style="color:#888;font-size:.8em">Probing...</div></div>
<div class="section" id="s_battery"><h2>🔋 Battery</h2><div style="color:#888;font-size:.8em">Checking...</div></div>

<script>
const R=(l,v,c)=>`<div class="row"><div class="label">${l}</div><div class="value ${c||''}">${v===undefined||v===null||v===''?'—':v}</div></div>`;
const SUB=(t)=>`<div class="sub">${t}</div>`;

// ── 1. Server Side ────────────────────────────────────────────────────────
fetch('/api').then(r=>r.json()).then(d=>{
    let h='';
    const pc = d.proxycheck && d.proxycheck[d.ip];
    const iqs = d.ipqualityscore || {};

    h+=SUB('🌍 IP Info');
    h+=R('IP', d.ip, 'green');
    h+=R('Country', d.ipinfo.country);
    h+=R('Region', d.ipinfo.region);
    h+=R('City', d.ipinfo.city);
    h+=R('Org / ASN', d.ipinfo.org);
    h+=R('Hostname', d.ipinfo.hostname);
    h+=R('Timezone', d.ipinfo.timezone);

    h+=SUB('🛡️ VPN / Proxy (proxycheck.io)');
    if(pc){
        const isVpn = pc.proxy==='yes';
        h+=R('VPN / Proxy', isVpn ? `⚠️ YES — ${pc.type}` : '✓ Clean', isVpn?'red':'green');
        h+=R('Risk Score', pc.risk!==undefined ? pc.risk+'%' : '', pc.risk>50?'red':pc.risk>20?'yellow':'green');
        h+=R('Provider', pc.provider);
        h+=R('Country (PC)', pc.country);
        h+=R('Port', pc.port);
        h+=R('Last Seen', pc.last_seen_human);
    } else {
        h+=R('ProxyCheck', 'No data');
    }

    h+=SUB('🔍 VPN Headers (server-detected)');
    const vpnH = d.vpn_headers;
    if(Object.keys(vpnH).length===0){
        h+=R('Tunnel headers','✓ None detected','green');
    } else {
        for(const [k,v] of Object.entries(vpnH)) h+=R(k, v, 'red');
    }

    h+=SUB('🌐 HTTP');
    h+=R('HTTP Version', d.http_version, d.http_version==='HTTP/2'?'green':'yellow');
    h+=R('Header order', (d.http2_fp.header_order||[]).slice(0,8).join(' → '));

    h+=SUB('📨 Request Headers');
    for(const[k,v] of Object.entries(d.headers)) h+=R(k,v);

    document.getElementById('s_server').innerHTML='<h2>📡 Server Side + VPN Detection</h2>'+h;
    document.getElementById('status').textContent='✓ Server data loaded';
});

// ── 2. Browser / Device ───────────────────────────────────────────────────
(()=>{
    const conn=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
    const ua = navigator.userAgent;
    const isMobile = /Mobi|Android|iPhone|iPad/i.test(ua);
    const isIOS = /iPhone|iPad|iPod/i.test(ua);
    const isAndroid = /Android/i.test(ua);

    let h='';
    h+=SUB('📱 Device Type');
    h+=R('Type', isMobile ? (isIOS?'📱 iOS':'📱 Android') : '🖥️ Desktop');
    h+=R('UA', ua);
    h+=R('Platform', navigator.platform);
    h+=R('Vendor', navigator.vendor);
    h+=R('App Version', navigator.appVersion);

    h+=SUB('🌏 Locale');
    h+=R('Language', navigator.language);
    h+=R('Languages', (navigator.languages||[]).join(', '));
    h+=R('Timezone', Intl.DateTimeFormat().resolvedOptions().timeZone);
    h+=R('TZ Offset', new Date().getTimezoneOffset()+' min');
    h+=R('Locale (number)', (1234567.89).toLocaleString());

    h+=SUB('🖥️ Screen');
    h+=R('Screen', screen.width+'×'+screen.height);
    h+=R('Avail', screen.availWidth+'×'+screen.availHeight);
    h+=R('Color Depth', screen.colorDepth+' bit');
    h+=R('Pixel Ratio', window.devicePixelRatio);
    h+=R('Window', window.innerWidth+'×'+window.innerHeight);
    h+=R('Orientation', screen.orientation ? screen.orientation.type : 'n/a');

    h+=SUB('💻 Hardware');
    h+=R('CPU Cores', navigator.hardwareConcurrency);
    h+=R('Device Memory', (navigator.deviceMemory||'n/a')+' GB');
    h+=R('Touch Points', navigator.maxTouchPoints);
    h+=R('Pointer', window.matchMedia('(pointer:coarse)').matches?'Coarse (touch)':'Fine (mouse)');

    h+=SUB('🔧 Misc');
    h+=R('Cookies', navigator.cookieEnabled?'✓ Yes':'✗ No');
    h+=R('DNT', navigator.doNotTrack||'null');
    h+=R('Plugins', Array.from(navigator.plugins||[]).map(p=>p.name).join(', ')||'none');
    h+=R('PDF Viewer', navigator.pdfViewerEnabled!==undefined ? (navigator.pdfViewerEnabled?'Yes':'No') : 'n/a');

    if(conn){
        h+=SUB('📶 Network');
        h+=R('Type', conn.effectiveType||conn.type);
        h+=R('Downlink', (conn.downlink||'n/a')+' Mbps');
        h+=R('RTT', (conn.rtt||'n/a')+' ms');
        h+=R('Save Data', conn.saveData?'Yes':'No');
    }
    document.getElementById('s_browser').innerHTML='<h2>🌐 Browser / Device</h2>'+h;
})();

// ── 3. API Features ───────────────────────────────────────────────────────
(()=>{
    const yn = v => v ? '✓ Yes' : '✗ No';
    let h='';
    h+=R('WebSocket',   yn(typeof WebSocket!=='undefined'));
    h+=R('WebRTC',      yn(typeof RTCPeerConnection!=='undefined'));
    h+=R('ServiceWorker', yn('serviceWorker' in navigator));
    h+=R('Geolocation', yn('geolocation' in navigator));
    h+=R('Notifications', yn('Notification' in window));
    h+=R('Battery',     yn('getBattery' in navigator));
    h+=R('Vibration',   yn('vibrate' in navigator));
    h+=R('Bluetooth',   yn('bluetooth' in navigator));
    h+=R('USB',         yn('usb' in navigator));
    h+=R('NFC',         yn('nfc' in navigator));
    h+=R('Serial',      yn('serial' in navigator));
    h+=R('Clipboard',   yn('clipboard' in navigator));
    h+=R('Wake Lock',   yn('wakeLock' in navigator));
    h+=R('Presentation',yn('presentation' in navigator));
    h+=R('XR (AR/VR)',  yn('xr' in navigator));
    h+=R('Accelerometer', yn(typeof DeviceMotionEvent!=='undefined'));
    h+=R('Gyroscope',   yn(typeof DeviceOrientationEvent!=='undefined'));
    h+=R('localStorage',yn(typeof localStorage!=='undefined'));
    h+=R('IndexedDB',   yn(typeof indexedDB!=='undefined'));
    h+=R('SharedWorker',yn(typeof SharedWorker!=='undefined'));
    h+=R('WebAssembly', yn(typeof WebAssembly!=='undefined'));
    h+=R('Crypto',      yn(typeof crypto!=='undefined'));
    h+=R('CredMgmt',    yn('credentials' in navigator));
    document.getElementById('s_features').innerHTML='<h2>🔌 API Features</h2>'+h;
})();

// ── 4. Permissions & Media Devices ───────────────────────────────────────
(async()=>{
    let h='';

    // Permissions API
    const perms = ['camera','microphone','notifications','geolocation',
                   'clipboard-read','clipboard-write','accelerometer',
                   'gyroscope','magnetometer','ambient-light-sensor'];
    h+=SUB('🔒 Permission States');
    for(const p of perms){
        try{
            const s = await navigator.permissions.query({name:p});
            const c = s.state==='granted'?'green':s.state==='denied'?'red':'yellow';
            h+=R(p, s.state, c);
        } catch(e){ h+=R(p,'n/a'); }
    }

    // Media devices (без запроса реального доступа — только enumeration)
    h+=SUB('🎥 Media Devices');
    try{
        const devices = await navigator.mediaDevices.enumerateDevices();
        const cams  = devices.filter(d=>d.kind==='videoinput');
        const mics  = devices.filter(d=>d.kind==='audioinput');
        const spkrs = devices.filter(d=>d.kind==='audiooutput');
        h+=R('Cameras',    cams.length);
        h+=R('Microphones',mics.length);
        h+=R('Speakers',   spkrs.length);
        // Без разрешения label пустой, но count виден
        cams.forEach((d,i)=>  h+=R(`Camera ${i+1}`, d.label||'(label hidden)'));
        mics.forEach((d,i)=>  h+=R(`Mic ${i+1}`,    d.label||'(label hidden)'));
    } catch(e){ h+=R('Media Devices', '✗ '+e.message, 'red'); }

    document.getElementById('s_permissions').innerHTML='<h2>🔒 Permissions & Media Devices</h2>'+h;
})();

// ── 5. WebRTC / IP Leak ───────────────────────────────────────────────────
(()=>{
    if(typeof RTCPeerConnection==='undefined'){
        document.getElementById('s_webrtc').innerHTML='<h2>📹 WebRTC</h2>'+R('WebRTC','✗ Not supported','red');
        return;
    }
    const pc=new RTCPeerConnection({iceServers:[
        {urls:'stun:stun.l.google.com:19302'},
        {urls:'stun:stun.cloudflare.com:3478'},
        {urls:'stun:stun1.l.google.com:19302'},
        {urls:'stun:stun.ekiga.net'},
    ]});
    const ips=new Map(); // ip → type
    pc.createDataChannel('fp');
    pc.createOffer().then(o=>pc.setLocalDescription(o));
    pc.onicecandidate=e=>{
        if(!e||!e.candidate)return;
        const c=e.candidate.candidate;
        const m4=c.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
        const m6=c.match(/([a-f0-9]{0,4}:){2,}[a-f0-9]{0,4}/gi);
        const typ = c.includes('typ host')?'host':c.includes('typ srflx')?'srflx':c.includes('typ relay')?'relay':'?';
        if(m4) m4.forEach(ip=>ips.set(ip,typ));
        if(m6) m6.forEach(ip=>ips.set(ip,typ));
    };
    setTimeout(()=>{
        let h='';
        if(ips.size===0){
            h+=R('Result','✓ No leak / Blocked','green');
        } else {
            ips.forEach((typ,ip)=>{
                const local=ip.startsWith('10.')||ip.startsWith('192.168.')||
                            ip.startsWith('172.')||ip.startsWith('100.')||
                            ip.startsWith('169.254.')||ip==='127.0.0.1';
                const label = local?'Local IP':'⚠️ Public IP (leak!)';
                const cls   = local?'yellow':'red';
                h+=R(label+` [${typ}]`, ip, cls);
            });
            // Если srflx IP != server IP → VPN leak
            h+=R('Note','srflx = STUN-reflected (real IP). relay = TURN (masked).','blue');
        }
        try{pc.close();}catch(e){}
        document.getElementById('s_webrtc').innerHTML='<h2>📹 WebRTC / IP Leak</h2>'+h;
    },6000);
})();

// ── 6. Canvas / WebGL / Audio ─────────────────────────────────────────────
(()=>{
    let h='';

    // Canvas 2D
    try{
        const c=document.createElement('canvas');
        c.width=320;c.height=60;
        const x=c.getContext('2d');
        x.fillStyle='#1a1a2e';x.fillRect(0,0,320,60);
        x.fillStyle='#ff6b6b';x.font='bold 16px Arial';
        x.fillText('Fingerprint 🔍 αβγδ ñ ü',10,25);
        x.fillStyle='#4ecdc4';x.font='12px Helvetica';
        x.fillText('Canvas2D render — 日本語テスト',10,45);
        x.strokeStyle='#f7dc6f';x.lineWidth=2;
        x.beginPath();x.arc(295,30,18,0,Math.PI*2);x.stroke();
        const data=c.toDataURL('image/png');
        const hash=data.split('').reduce((a,b)=>{a=((a<<5)-a)+b.charCodeAt(0);return a&a},0);
        h+=R('Canvas 2D','✓ Supported','green');
        h+=R('Canvas Hash',hash.toString(16).toUpperCase().padStart(8,'0'));
    }catch(e){h+=R('Canvas','✗ '+e.message,'red');}

    // WebGL
    try{
        const c2=document.createElement('canvas');
        const gl=c2.getContext('webgl')||c2.getContext('experimental-webgl');
        if(gl){
            const ext=gl.getExtension('WEBGL_debug_renderer_info');
            h+=R('WebGL','✓ Supported','green');
            h+=R('GL Vendor',ext?gl.getParameter(ext.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR));
            h+=R('GL Renderer',ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER));
            h+=R('GL Version',gl.getParameter(gl.VERSION));
            h+=R('GLSL',gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
            h+=R('Max Texture',gl.getParameter(gl.MAX_TEXTURE_SIZE));
            const exts = gl.getSupportedExtensions()||[];
            h+=R('Extensions count', exts.length);
        }else{h+=R('WebGL','✗ Not supported','red');}
    }catch(e){h+=R('WebGL','✗ '+e.message,'red');}

    // WebGL2
    try{
        const c3=document.createElement('canvas');
        const gl2=c3.getContext('webgl2');
        h+=R('WebGL2', gl2?'✓ Supported':'✗ No', gl2?'green':'yellow');
    }catch(e){}

    // AudioContext fingerprint
    try{
        const A=window.AudioContext||window.webkitAudioContext;
        if(A){
            const ac=new A();
            const osc=ac.createOscillator();
            const analyser=ac.createAnalyser();
            const gain=ac.createGain();
            gain.gain.value=0;
            osc.connect(analyser);analyser.connect(gain);gain.connect(ac.destination);
            osc.start(0);
            const buf=new Float32Array(analyser.frequencyBinCount);
            analyser.getFloatFrequencyData(buf);
            const audioHash=buf.slice(0,32).reduce((a,b)=>a+b,0).toFixed(8);
            h+=R('AudioContext','✓ Supported','green');
            h+=R('Audio Hash', audioHash);
            h+=R('Sample Rate', ac.sampleRate+' Hz');
            h+=R('Channel Count', ac.destination.channelCount);
            osc.stop();ac.close();
        }
    }catch(e){h+=R('AudioContext','✗ '+e.message,'red');}

    document.getElementById('s_canvas').innerHTML='<h2>🎨 Canvas / WebGL / Audio</h2>'+h;
})();

// ── 7. CSS / Display Features ─────────────────────────────────────────────
(()=>{
    const mq = q => window.matchMedia(q).matches;
    let h='';
    h+=R('Color Scheme', mq('(prefers-color-scheme:dark)')?'dark':'light');
    h+=R('Reduced Motion', mq('(prefers-reduced-motion:reduce)')?'reduce':'no-preference');
    h+=R('Reduced Data',   mq('(prefers-reduced-data:reduce)')?'reduce':'no-preference');
    h+=R('Color Gamut P3', mq('(color-gamut:p3)')?'✓ P3':'sRGB');
    h+=R('HDR',            mq('(dynamic-range:high)')?'✓ HDR':'SDR');
    h+=R('Forced Colors',  mq('(forced-colors:active)')?'Active':'None');
    h+=R('Hover',          mq('(hover:hover)')?'hover':'none');
    h+=R('Pointer',        mq('(pointer:coarse)')?'coarse':mq('(pointer:fine)')?'fine':'none');
    h+=R('Display Mode',   mq('(display-mode:standalone)')?'standalone':'browser');
    h+=R('Overflow Scrollbar', mq('(overflow:scrollbar)')?'Yes':'No');
    h+=R('Prefers Contrast', mq('(prefers-contrast:more)')?'more':mq('(prefers-contrast:less)')?'less':'no-preference');
    document.getElementById('s_css').innerHTML='<h2>🎭 CSS / Display Features</h2>'+h;
})();

// ── 8. Font Fingerprint ───────────────────────────────────────────────────
(()=>{
    // Метод: измеряем ширину текста на canvas с фолбек-шрифтом и целевым
    const baseFonts = ['monospace','sans-serif','serif'];
    const testFonts = [
        'Arial','Arial Black','Arial Narrow','Calibri','Cambria','Candara',
        'Century Gothic','Comic Sans MS','Consolas','Constantia','Corbel',
        'Courier New','Franklin Gothic Medium','Futura','Garamond','Geneva',
        'Georgia','Gill Sans','Helvetica','Impact','Lucida Console',
        'Lucida Grande','Lucida Sans Unicode','Microsoft Sans Serif','Monaco',
        'Palatino','Segoe UI','Tahoma','Times New Roman','Trebuchet MS',
        'Verdana','Webdings','Wingdings',
        // Системные мобильные
        'San Francisco','SF Pro','SF UI','Roboto','Noto Sans',
        'Droid Sans','Droid Serif','Ubuntu','Oxygen',
        // CJK
        'MS Gothic','MS Mincho','Hiragino Kaku Gothic Pro','Yu Gothic',
        'Malgun Gothic','Apple SD Gothic Neo','PingFang SC','STHeiti',
    ];

    const canvas=document.createElement('canvas');
    const ctx=canvas.getContext('2d');
    const testStr='mmmmmmmmmmlli';
    const testSize='72px';

    const getW=(font)=>{ctx.font=`${testSize} ${font}`;return ctx.measureText(testStr).width;};
    const baseW={};
    baseFonts.forEach(b=>baseW[b]=getW(b));

    const available=[];
    testFonts.forEach(font=>{
        const detected=baseFonts.some(base=>{
            ctx.font=`${testSize} '${font}',${base}`;
            return ctx.measureText(testStr).width!==baseW[base];
        });
        if(detected) available.push(font);
    });

    let h='';
    h+=R('Fonts found', available.length+' / '+testFonts.length, available.length>20?'green':'yellow');
    h+=R('List', available.join(', ')||'none detected');
    document.getElementById('s_fonts').innerHTML='<h2>🔤 Font Fingerprint</h2>'+h;
})();

// ── 9. Advanced: Incognito, iframe sandbox, timing ────────────────────────
(async()=>{
    let h='';

    // Incognito detection (через Storage Quota — в инкогнито квота намного меньше)
    h+=SUB('🕵️ Incognito Detection');
    try{
        const est = await navigator.storage.estimate();
        const quota = est.quota||0;
        const isInc = quota < 120*1024*1024; // <120MB → likely incognito
        h+=R('Storage Quota', (quota/(1024*1024)).toFixed(0)+' MB');
        h+=R('Likely Incognito', isInc?'⚠️ Possibly YES':'✓ Probably NO', isInc?'yellow':'green');
    }catch(e){ h+=R('Incognito Check','✗ '+e.message); }

    // FileSystem API (заблокирован в инкогнито в старых Chrome)
    try{
        window.RequestFileSystem = window.RequestFileSystem||window.webkitRequestFileSystem;
        if(window.RequestFileSystem){
            await new Promise((res,rej)=>{
                window.RequestFileSystem(window.TEMPORARY,1,()=>{h+=R('FileSystem API','✓ Available','green');res()},()=>{h+=R('FileSystem API','✗ Blocked (Incognito?)','red');res()});
            });
        }
    }catch(e){}

    // Automation / WebDriver detection
    h+=SUB('🤖 Automation / Bot');
    h+=R('navigator.webdriver', navigator.webdriver?'⚠️ YES (automated)':'✓ NO', navigator.webdriver?'red':'green');
    h+=R('__nightmare',        typeof window.__nightmare!=='undefined'?'⚠️ Nightmare.js':'NO', typeof window.__nightmare!=='undefined'?'red':'');
    h+=R('callPhantom',        typeof window.callPhantom!=='undefined'?'⚠️ PhantomJS':'NO', typeof window.callPhantom!=='undefined'?'red':'');
    h+=R('_phantom',           typeof window._phantom!=='undefined'?'⚠️ PhantomJS':'NO');
    h+=R('domAutomation',      typeof window.domAutomation!=='undefined'?'⚠️ Chrome automation':'NO');

    // iframe sandbox detection
    h+=SUB('🖼️ iframe / Sandbox');
    try{
        const inFrame = window.self !== window.top;
        h+=R('In iframe',inFrame?'⚠️ YES':'✓ NO', inFrame?'yellow':'green');
    }catch(e){h+=R('In iframe','⚠️ YES (sandboxed — cannot access top)','yellow');}

    // Performance timing entropy (anti-bot)
    h+=SUB('⏱️ Timing');
    const t0=performance.now();
    let x=0; for(let i=0;i<1e6;i++) x+=Math.sqrt(i);
    const elapsed=(performance.now()-t0).toFixed(3);
    h+=R('JS bench (1M sqrt)', elapsed+' ms');
    h+=R('performance.now res', performance.now().toString().split('.')[1]?.length+' decimals');

    // JA3 / TLS note
    h+=SUB('🔐 TLS / JA3');
    h+=R('Note','JA3 fingerprint is server-side only. Use Wireshark / ja3er.com API to get your JA3.','blue');

    document.getElementById('s_advanced').innerHTML='<h2>⚡ Advanced / Incognito / Sandbox</h2>'+h;
})();

// ── 10. Battery ───────────────────────────────────────────────────────────
(async()=>{
    let h='';
    try{
        if('getBattery' in navigator){
            const b = await navigator.getBattery();
            h+=R('Level',   Math.round(b.level*100)+'%', b.level<0.2?'red':'green');
            h+=R('Charging',b.charging?'⚡ Yes':'No', b.charging?'green':'');
            h+=R('Charge Time', b.chargingTime===Infinity?'∞ / N/A':b.chargingTime+'s');
            h+=R('Discharge Time',b.dischargingTime===Infinity?'∞ / Not discharging':b.dischargingTime+'s');
        } else {
            h+=R('Battery API','✗ Not supported (iOS / Firefox)','yellow');
        }
    }catch(e){h+=R('Battery','✗ '+e.message,'red');}
    document.getElementById('s_battery').innerHTML='<h2>🔋 Battery</h2>'+h;
})();

// ── Export / Copy helpers ─────────────────────────────────────────────────
function showToast(msg){
    const t=document.getElementById('toast');
    t.textContent=msg;t.style.opacity=1;
    setTimeout(()=>t.style.opacity=0,2200);
}

function collectData(){
    const out={};
    document.querySelectorAll('.section').forEach(sec=>{
        const title=sec.querySelector('h2')?.textContent||'section';
        const rows={};
        sec.querySelectorAll('.row').forEach(row=>{
            const k=row.querySelector('.label')?.textContent||'';
            const v=row.querySelector('.value')?.textContent||'';
            if(k) rows[k.trim()]=v.trim();
        });
        out[title.trim()]=rows;
    });
    return out;
}

function exportJSON(){
    const data=collectData();
    data['_exported_at']=new Date().toISOString();
    const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='fingerprint_'+Date.now()+'.json';
    a.click();
    showToast('✓ JSON downloaded');
}

function copyAll(){
    const data=collectData();
    let txt='FINGERPRINT REPORT — '+new Date().toLocaleString()+'\n\n';
    for(const [section,rows] of Object.entries(data)){
        txt+=`── ${section} ──\n`;
        for(const [k,v] of Object.entries(rows)) txt+=`  ${k.padEnd(28)} ${v}\n`;
        txt+='\n';
    }
    navigator.clipboard.writeText(txt).then(()=>showToast('✓ Copied to clipboard!')).catch(()=>{
        // fallback
        const ta=document.createElement('textarea');
        ta.value=txt;document.body.appendChild(ta);ta.select();
        document.execCommand('copy');document.body.removeChild(ta);
        showToast('✓ Copied (fallback)');
    });
}

</script>
</body>
</html>"""


# ── HTTP Handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ts = datetime.now().strftime('%H:%M:%S')
        ip = self.client_address[0]
        print(f"[{ts}] {ip} {fmt % args}")

    def do_GET(self):
        if self.path == '/api' or self.path.startswith('/api?'):
            self._api()
        else:
            self._html()

    def _html(self):
        body = HTML.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api(self):
        ip = (
            self.headers.get('X-Real-IP') or
            self.headers.get('CF-Connecting-IP') or
            self.headers.get('True-Client-IP') or
            self.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            self.client_address[0]
        )

        http_ver = (
            f"HTTP/{self.request_version.split('/')[1]}"
            if '/' in self.request_version else self.request_version
        )

        # Попытка reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns = None

        ipinfo     = get_ip_info(ip)
        proxycheck = get_proxycheck(ip)
        vpn_hdrs   = detect_vpn_headers(self.headers)
        tcp_fp     = tcp_fingerprint(self)
        h2_fp      = http2_header_order(self)

        data = {
            "timestamp":    datetime.now().isoformat(),
            "ip":           ip,
            "rdns":         rdns,
            "http_version": http_ver,
            "headers":      dict(self.headers),
            "vpn_headers":  vpn_hdrs,
            "tcp_fp":       tcp_fp,
            "http2_fp":     h2_fp,
            "ipinfo":       ipinfo,
            "proxycheck":   proxycheck,
        }

        print(json.dumps(data, indent=2, ensure_ascii=False))

        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', int(os.environ.get('PORT', 8888))
    server = HTTPServer((HOST, PORT), Handler)
    print(f"[*] Fingerprint server running on http://{HOST}:{PORT}")
    print(f"[*] Open in browser: http://YOUR_IP:{PORT}")
    print(f"[*] Notes:")
    print(f"    - JA3 TLS fingerprint: requires raw socket capture (p0f, ja3er, or nginx with lua)")
    print(f"    - TCP TTL/MSS fingerprint: requires libpcap/nmap (p0f daemon)")
    print(f"    - For full HTTP/2 HPACK order: put nginx in front and log $http2_* vars")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
        server.server_close()
