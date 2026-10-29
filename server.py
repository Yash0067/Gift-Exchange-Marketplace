#!/usr/bin/env python3
"""Gift Exchange Marketplace: small, multi-user SQLite demo server.
Run: python3 server.py  (environment: PORT, DB_PATH)
"""
import hashlib, hmac, json, os, re, secrets, sqlite3, time, threading, base64, binascii, io
from PIL import Image, ImageOps, UnidentifiedImageError
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB = os.environ.get('DB_PATH', str(ROOT / 'marketplace.sqlite3'))
PORT = int(os.environ.get('PORT', '8000'))
LIMITS = {}
LIMIT_LOCK = threading.Lock()

# In-process sliding-window limits: supplement with shared proxy/WAF limits in production.
def allowed(key, maximum, window):
    now=time.monotonic()
    with LIMIT_LOCK:
        if len(LIMITS)>10000:
            for k in list(LIMITS):
                LIMITS[k]=[t for t in LIMITS[k] if now-t<3600]
                if not LIMITS[k]: del LIMITS[k]
        history=[t for t in LIMITS.get(key,[]) if now-t<window]
        if len(history)>=maximum:
            LIMITS[key]=history; return False
        history.append(now); LIMITS[key]=history; return True

CATEGORIES = {'Home & decor', 'Food & sweets', 'Electronics', 'Beauty', 'Apparel', 'Books & stationery', 'Games', 'Other'}

def connect():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def setup():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, pw TEXT NOT NULL, area TEXT NOT NULL, city TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL, category TEXT NOT NULL, quantity INTEGER NOT NULL, price INTEGER, area TEXT NOT NULL, city TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', expiry TEXT, status TEXT NOT NULL DEFAULT 'available', created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id), sender_id INTEGER NOT NULL REFERENCES users(id), receiver_id INTEGER NOT NULL REFERENCES users(id), type TEXT NOT NULL, offered_id INTEGER REFERENCES listings(id), message TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', place TEXT, pickup_time TEXT, pickup_by INTEGER REFERENCES users(id), pickup_status TEXT, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS listing_photos(listing_id INTEGER PRIMARY KEY REFERENCES listings(id) ON DELETE CASCADE, data BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id), buyer_id INTEGER NOT NULL REFERENCES users(id), seller_id INTEGER NOT NULL REFERENCES users(id), created INTEGER NOT NULL, UNIQUE(listing_id,buyer_id));
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations(id), sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks(blocker_id INTEGER NOT NULL REFERENCES users(id), blocked_id INTEGER NOT NULL REFERENCES users(id), created INTEGER NOT NULL, PRIMARY KEY(blocker_id,blocked_id), CHECK(blocker_id != blocked_id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id), listing_id INTEGER REFERENCES listings(id), conversation_id INTEGER REFERENCES conversations(id), reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status,created);
        CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id,id);
        CREATE INDEX IF NOT EXISTS idx_listings_city ON listings(city,status);
        CREATE INDEX IF NOT EXISTS idx_requests_users ON requests(sender_id,receiver_id);
        ''')
    try: os.chmod(DB, 0o600)
    except OSError: pass

def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 260000).hex()

def new_pw_hash(password, salt):
    return 'scrypt$'+hashlib.scrypt(password.encode('utf-8'),salt=bytes.fromhex(salt),n=32768,r=8,p=1,maxmem=64*1024*1024,dklen=32).hex()

def password_matches(password, salt, stored):
    candidate = new_pw_hash(password,salt) if stored.startswith('scrypt$') else pw_hash(password,salt)
    return hmac.compare_digest(stored,candidate)

def blocked(c, one, two):
    return bool(c.execute('SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)',(one,two,two,one)).fetchone())

def decode_photo(value):
    if not value: return None
    if not isinstance(value,str) or not value.startswith('data:image/jpeg;base64,') or len(value)>1600000:
        raise ValueError('Photo must be a JPEG image below the size limit')
    try:
        raw=base64.b64decode(value.split(',',1)[1],validate=True)
        if not raw or len(raw)>1200000: raise ValueError('Photo exceeds the size limit')
        with Image.open(io.BytesIO(raw)) as image:
            if image.format!='JPEG' or image.width<1 or image.height<1 or image.width>1600 or image.height>1600 or image.width*image.height>2560000:
                raise ValueError('Invalid photo dimensions or format')
            image.load()
            clean=ImageOps.exif_transpose(image).convert('RGB')
            out=io.BytesIO()
            clean.save(out,format='JPEG',quality=85,optimize=True)
            if out.tell()>1200000: raise ValueError('Photo exceeds the size limit')
            return out.getvalue()
    except (UnidentifiedImageError, binascii.Error, OSError, Image.DecompressionBombError):
        raise ValueError('Invalid or unsupported photo')

def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
def svalue(data, field, minimum=1, maximum=120):
    v = data.get(field)
    if not isinstance(v, str): raise ValueError(f'{field} must be text')
    v = v.strip()
    if not minimum <= len(v) <= maximum: raise ValueError(f'{field} must be {minimum}–{maximum} characters')
    return v

def get_int(value):
    if isinstance(value, bool): raise ValueError('Invalid number')
    try:
        n=int(value)
        if str(value).strip() != str(n): raise ValueError()
        return n
    except (ValueError, TypeError): raise ValueError('Please enter a whole number')

class Handler(BaseHTTPRequestHandler):
    server_version='GiftMarket/1.0'
    def log_message(self, fmt, *args):
        print('%s - %s' % (self.address_string(), fmt % args), flush=True)
    def security_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
        if os.environ.get('SECURE_COOKIE')=='1': self.send_header('Strict-Transport-Security','max-age=31536000')
    def send_json(self, status, obj, cookie=None):
        data=json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.security_headers()
        if cookie: self.send_header('Set-Cookie', cookie)
        self.end_headers(); self.wfile.write(data)
    def cookie(self):
        c=SimpleCookie()
        try: c.load(self.headers.get('Cookie',''))
        except Exception: return ''
        return c['session'].value if 'session' in c else ''
    def session_token(self):
        if os.environ.get('ALLOW_PREVIEW_TOKEN')=='1':
            body_token=getattr(self,'preview_body_token','')
            if body_token:
                return body_token if re.fullmatch(r'[A-Za-z0-9_-]{32,100}',body_token) else ''
            # The preview proxy may consume Authorization for its own authentication.
            # Use a dedicated header to avoid colliding with the proxy's credentials.
            token=self.headers.get('X-Gift-Session','').strip()
            if token:
                if re.fullmatch(r'[A-Za-z0-9_-]{32,100}',token): return token
                return ''
            authorization=self.headers.get('Authorization','')
            if authorization.startswith('Bearer '):
                token=authorization[7:].strip()
                if re.fullmatch(r'[A-Za-z0-9_-]{32,100}',token): return token
                return ''
        return self.cookie()
    def user(self, c):
        t=self.session_token()
        if not t:
            if os.environ.get('PREVIEW_DIAGNOSTICS')=='1' and urlparse(self.path).path=='/api/requests':
                print('Preview auth: session header present=%s, authorization present=%s, cookie present=%s' % (bool(self.headers.get('X-Gift-Session')),bool(self.headers.get('Authorization')),bool(self.cookie())),flush=True)
            return None
        row=c.execute('SELECT u.id,u.name,u.email,u.area,u.city FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires>?', (token_hash(t),int(time.time()))).fetchone()
        if not row and os.environ.get('PREVIEW_DIAGNOSTICS')=='1' and urlparse(self.path).path=='/api/requests': print('Preview auth: supplied session was not valid',flush=True)
        return row
    def body(self):
        if 'application/json' not in self.headers.get('Content-Type','').lower(): raise ValueError('JSON content type required')
        n=int(self.headers.get('Content-Length','0'))
        limit=2000000 if urlparse(self.path).path=='/api/listings' else 20000
        if n <= 0 or n > limit: raise ValueError('Invalid request size')
        try: d=json.loads(self.rfile.read(n))
        except Exception: raise ValueError('Invalid JSON')
        if not isinstance(d,dict): raise ValueError('Invalid request')
        return d
    def issue(self,c,user):
        token=secrets.token_urlsafe(32)
        c.execute('DELETE FROM sessions WHERE expires<=?',(int(time.time()),))
        c.execute('INSERT INTO sessions VALUES(?,?,?)',(token_hash(token),user['id'],int(time.time())+30*86400))
        # Preview may run in a third-party iframe. Partitioned cookies supplement the
        # preview-only token fallback; production keeps the stricter Lax cookie.
        secure=os.environ.get('SECURE_COOKIE')=='1'
        preview=os.environ.get('ALLOW_PREVIEW_TOKEN')=='1'
        attrs='; SameSite=None; Secure; Partitioned' if secure and preview else '; SameSite=Lax'+('; Secure' if secure else '')
        return token, 'session='+token+'; HttpOnly; Path=/; Max-Age=2592000'+attrs
    def do_GET(self):
        path=urlparse(self.path).path
        if path=='/app.js':
            data=(ROOT/'app.js').read_bytes()
            self.send_response(200); self.send_header('Content-Type','text/javascript; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store, max-age=0'); self.security_headers(); self.end_headers(); self.wfile.write(data); return
        if path in ('/','/index.html'):
            data=(ROOT/'index.html').read_bytes()
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store, max-age=0'); self.security_headers(); self.end_headers(); self.wfile.write(data); return
        try:
            with connect() as c:
                u=self.user(c)
                if path=='/api/session': return self.send_json(200,{'user':dict(u) if u else None})
                photo=re.fullmatch(r'/api/listings/(\d+)/photo',path)
                if photo:
                    row=c.execute("SELECT p.data FROM listing_photos p JOIN listings l ON l.id=p.listing_id WHERE l.id=? AND l.status='available' AND (l.expiry IS NULL OR l.expiry>=?)",(int(photo.group(1)),date.today().isoformat())).fetchone()
                    if not row: return self.send_json(404,{'error':'Photo not found'})
                    data=bytes(row['data'])
                    self.send_response(200);self.send_header('Content-Type','image/jpeg');self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.security_headers();self.end_headers();self.wfile.write(data);return
                if path=='/api/listings':
                    rows=c.execute('''SELECT l.*,u.name owner_name,EXISTS(SELECT 1 FROM listing_photos p WHERE p.listing_id=l.id) has_photo FROM listings l JOIN users u ON u.id=l.owner_id WHERE l.status='available' AND (l.expiry IS NULL OR l.expiry>=?) ORDER BY l.created DESC,l.id DESC LIMIT 250''',(date.today().isoformat(),)).fetchall()
                    return self.send_json(200,{'listings':[dict(r) for r in rows]})
                if path=='/api/conversations':
                    if not u: return self.send_json(401,{'error':'Please sign in first'})
                    rows=c.execute('''SELECT cv.id,cv.listing_id,cv.buyer_id,cv.seller_id,cv.created,l.name listing_name,
                        CASE WHEN cv.buyer_id=? THEN seller.name ELSE buyer.name END other_name,
                        EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=? AND b.blocked_id=CASE WHEN cv.buyer_id=? THEN cv.seller_id ELSE cv.buyer_id END) blocked_by_me,
                        EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=CASE WHEN cv.buyer_id=? THEN cv.seller_id ELSE cv.buyer_id END AND b.blocked_id=?) blocked_by_other,
                        (SELECT body FROM messages WHERE conversation_id=cv.id ORDER BY id DESC LIMIT 1) last_message,
                        (SELECT created FROM messages WHERE conversation_id=cv.id ORDER BY id DESC LIMIT 1) last_time
                        FROM conversations cv JOIN listings l ON l.id=cv.listing_id
                        JOIN users buyer ON buyer.id=cv.buyer_id JOIN users seller ON seller.id=cv.seller_id
                        WHERE cv.buyer_id=? OR cv.seller_id=? ORDER BY COALESCE(last_time,cv.created) DESC,cv.id DESC LIMIT 200''',(u['id'],u['id'],u['id'],u['id'],u['id'],u['id'],u['id'])).fetchall()
                    return self.send_json(200,{'conversations':[dict(r) for r in rows]})
                chat=re.fullmatch(r'/api/conversations/(\d+)/messages',path)
                if chat:
                    if not u: return self.send_json(401,{'error':'Please sign in first'})
                    cid=int(chat.group(1))
                    if not c.execute('SELECT id FROM conversations WHERE id=? AND (buyer_id=? OR seller_id=?)',(cid,u['id'],u['id'])).fetchone(): return self.send_json(404,{'error':'Conversation not found'})
                    rows=c.execute('SELECT id,sender_id,body,created FROM (SELECT id,sender_id,body,created FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 500) ORDER BY id',(cid,)).fetchall()
                    return self.send_json(200,{'messages':[dict(r) for r in rows]})
                if path=='/api/requests':
                    if not u: return self.send_json(401,{'error':'Please sign in first'})
                    rows=c.execute('''SELECT r.*,l.name listing_name,l.price listing_price,l.status listing_status,
                        offer.name offered_name,s.name sender_name,rc.name receiver_name FROM requests r
                        JOIN listings l ON l.id=r.listing_id JOIN users s ON s.id=r.sender_id JOIN users rc ON rc.id=r.receiver_id
                        LEFT JOIN listings offer ON offer.id=r.offered_id
                        WHERE r.sender_id=? OR r.receiver_id=? ORDER BY r.created DESC,r.id DESC LIMIT 200''',(u['id'],u['id'])).fetchall()
                    return self.send_json(200,{'requests':[dict(r) for r in rows]})
                self.send_json(404,{'error':'Not found'})
        except Exception as e:
            print('GET error:',repr(e),flush=True); self.send_json(500,{'error':'Server error'})
    def do_POST(self):
        path=urlparse(self.path).path
        try:
            # Browsers provide Origin on cross-origin POSTs. Do not trust forwarded-host headers here.
            origin=self.headers.get('Origin')
            if origin:
                o=urlparse(origin)
                configured=os.environ.get('APP_ORIGIN','').rstrip('/').lower()
                matches_host=o.netloc.lower()==self.headers.get('Host','').lower()
                matches_public=bool(configured) and origin.rstrip('/').lower()==configured
                if o.scheme not in ('http','https') or not o.netloc or not (matches_host or matches_public):
                    return self.send_json(403,{'error':'Cross-origin request rejected'})
            # Network-peer limits are deliberately not keyed on spoofable forwarded headers.
            ip=self.client_address[0]
            if path in ('/api/login','/api/register') and not allowed('auth:'+ip,20,600):
                return self.send_json(429,{'error':'Too many attempts. Please try again later.'})
            d=self.body()
            if os.environ.get('ALLOW_PREVIEW_TOKEN')=='1':
                body_token=d.pop('_preview_session','')
                if isinstance(body_token,str): self.preview_body_token=body_token
                if path=='/api/query':
                    target=d.get('path','')
                    if not isinstance(target,str) or not (target in ('session','listings','requests','conversations') or re.fullmatch(r'conversations/\d+/messages',target)):
                        return self.send_json(400,{'error':'Invalid query'})
                    self.path='/api/'+target
                    return self.do_GET()
            with connect() as c:
                if path=='/api/register':
                    name=svalue(d,'name',2,60); email=svalue(d,'email',5,120).lower(); password=svalue(d,'password',10,200); area=svalue(d,'area',2,80); city=svalue(d,'city',2,80)
                    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email): raise ValueError('Enter a valid email address')
                    salt=secrets.token_hex(16)
                    try: cur=c.execute('INSERT INTO users(name,email,salt,pw,area,city,created) VALUES(?,?,?,?,?,?,?)',(name,email,salt,new_pw_hash(password,salt),area,city,int(time.time())))
                    except sqlite3.IntegrityError: raise ValueError('An account with that email already exists')
                    u=c.execute('SELECT id,name,email,area,city FROM users WHERE id=?',(cur.lastrowid,)).fetchone()
                    token,cookie=self.issue(c,u); c.commit(); return self.send_json(201,{'user':dict(u), **({'preview_token':token} if os.environ.get('ALLOW_PREVIEW_TOKEN')=='1' else {})},cookie)
                if path=='/api/login':
                    email=svalue(d,'email',1,120).lower(); password=svalue(d,'password',1,200)
                    u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                    if u:
                        valid=password_matches(password,u['salt'],u['pw'])
                    else:
                        new_pw_hash(password,'00000000000000000000000000000000'); valid=False
                    if not valid: return self.send_json(401,{'error':'Incorrect email or password'})
                    if not u['pw'].startswith('scrypt$'):
                        salt=secrets.token_hex(16)
                        c.execute('UPDATE users SET salt=?,pw=? WHERE id=?',(salt,new_pw_hash(password,salt),u['id']))
                    safe={k:u[k] for k in ('id','name','email','area','city')}; token,cookie=self.issue(c,u); c.commit(); return self.send_json(200,{'user':safe, **({'preview_token':token} if os.environ.get('ALLOW_PREVIEW_TOKEN')=='1' else {})},cookie)
                u=self.user(c)
                if not u: return self.send_json(401,{'error':'Please sign in first'})
                if path=='/api/logout':
                    c.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash(self.session_token()),)); c.commit()
                    preview=os.environ.get('ALLOW_PREVIEW_TOKEN')=='1' and os.environ.get('SECURE_COOKIE')=='1'
                    attrs='; SameSite=None; Secure; Partitioned' if preview else '; SameSite=Lax'+('; Secure' if os.environ.get('SECURE_COOKIE')=='1' else '')
                    return self.send_json(200,{'ok':True},'session=; HttpOnly; Path=/; Max-Age=0'+attrs)
                if path=='/api/reports':
                    if not allowed('report:'+str(u['id']),10,3600): return self.send_json(429,{'error':'Too many reports. Try again later.'})
                    kind=svalue(d,'kind',4,20); reason=svalue(d,'reason',5,500); target=get_int(d.get('id'))
                    if kind=='listing':
                        l=c.execute('SELECT owner_id FROM listings WHERE id=?',(target,)).fetchone()
                        if not l or l['owner_id']==u['id']: return self.send_json(404,{'error':'Listing not found'})
                        c.execute('INSERT INTO reports(reporter_id,listing_id,reason,created) VALUES(?,?,?,?)',(u['id'],target,reason,int(time.time())))
                    elif kind=='conversation':
                        cv=c.execute('SELECT id FROM conversations WHERE id=? AND (buyer_id=? OR seller_id=?)',(target,u['id'],u['id'])).fetchone()
                        if not cv: return self.send_json(404,{'error':'Conversation not found'})
                        c.execute('INSERT INTO reports(reporter_id,conversation_id,reason,created) VALUES(?,?,?,?)',(u['id'],target,reason,int(time.time())))
                    else: raise ValueError('Invalid report type')
                    c.commit(); return self.send_json(201,{'ok':True})
                if path=='/api/block':
                    cid=get_int(d.get('conversation_id'))
                    cv=c.execute('SELECT * FROM conversations WHERE id=? AND (buyer_id=? OR seller_id=?)',(cid,u['id'],u['id'])).fetchone()
                    if not cv: return self.send_json(404,{'error':'Conversation not found'})
                    other=cv['seller_id'] if cv['buyer_id']==u['id'] else cv['buyer_id']
                    action=svalue(d,'action',5,7)
                    if action=='block': c.execute('INSERT OR IGNORE INTO blocks VALUES(?,?,?)',(u['id'],other,int(time.time())))
                    elif action=='unblock': c.execute('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?',(u['id'],other))
                    else: raise ValueError('Invalid action')
                    c.commit(); return self.send_json(200,{'ok':True})
                if path=='/api/conversations':
                    if not allowed('conversations:'+str(u['id']),40,3600): return self.send_json(429,{'error':'Too many conversation attempts. Please try again later.'})
                    lid=get_int(d.get('listing_id'))
                    l=c.execute('SELECT * FROM listings WHERE id=?',(lid,)).fetchone()
                    if not l: return self.send_json(404,{'error':'Listing not found'})
                    if l['owner_id']!=u['id']:
                        buyer=u['id']
                        # A previous request or chat keeps the connection accessible after reservation.
                        prior=c.execute('SELECT id FROM conversations WHERE listing_id=? AND buyer_id=?',(lid,buyer)).fetchone()
                        requested=c.execute('SELECT id FROM requests WHERE listing_id=? AND sender_id=?',(lid,buyer)).fetchone()
                        available=l['status']=='available' and (not l['expiry'] or l['expiry']>=date.today().isoformat())
                        if not available and not prior and not requested: return self.send_json(404,{'error':'Listing not available'})
                    else:
                        buyer=get_int(d.get('buyer_id'))
                        if buyer==u['id']: raise ValueError('You cannot message yourself')
                        prior=c.execute('SELECT id FROM conversations WHERE listing_id=? AND buyer_id=?',(lid,buyer)).fetchone()
                        requested=c.execute('SELECT id FROM requests WHERE listing_id=? AND sender_id=? AND receiver_id=?',(lid,buyer,u['id'])).fetchone()
                        if not prior and not requested: return self.send_json(404,{'error':'Conversation not found'})
                    if blocked(c,buyer,l['owner_id']): raise ValueError('This conversation is unavailable')
                    c.execute('INSERT OR IGNORE INTO conversations(listing_id,buyer_id,seller_id,created) VALUES(?,?,?,?)',(lid,buyer,l['owner_id'],int(time.time())))
                    row=c.execute('SELECT id FROM conversations WHERE listing_id=? AND buyer_id=?',(lid,buyer)).fetchone()
                    c.commit(); return self.send_json(200,{'id':row['id']})
                chat=re.fullmatch(r'/api/conversations/(\d+)/messages',path)
                if chat:
                    cid=int(chat.group(1))
                    cv=c.execute('SELECT * FROM conversations WHERE id=? AND (buyer_id=? OR seller_id=?)',(cid,u['id'],u['id'])).fetchone()
                    if not cv: return self.send_json(404,{'error':'Conversation not found'})
                    if blocked(c,cv['buyer_id'],cv['seller_id']): return self.send_json(403,{'error':'Messaging is unavailable for this conversation'})
                    if not allowed('message:'+str(u['id']),60,60): return self.send_json(429,{'error':'Too many messages. Please try again shortly.'})
                    body=svalue(d,'body',1,2000)
                    cur=c.execute('INSERT INTO messages(conversation_id,sender_id,body,created) VALUES(?,?,?,?)',(cid,u['id'],body,int(time.time())))
                    c.commit(); return self.send_json(201,{'id':cur.lastrowid})
                if path=='/api/listings':
                    if not allowed('listings:'+str(u['id']),30,3600): return self.send_json(429,{'error':'Too many listings. Please try again later.'})
                    name=svalue(d,'name',2,80); cat=svalue(d,'category',2,40); area=svalue(d,'area',2,80); city=svalue(d,'city',2,80)
                    note=svalue(d,'note',0,500); qty=get_int(d.get('quantity'))
                    if not 1<=qty<=99: raise ValueError('Quantity must be between 1 and 99')
                    if cat not in CATEGORIES: raise ValueError('Choose a valid category')
                    raw=d.get('price'); price=None if raw in ('',None) else get_int(raw)
                    if price is not None and not 1<=price<=10000000: raise ValueError('Price must be a positive whole amount in rupees')
                    checks=d.get('checks')
                    if not isinstance(checks,list) or len(checks)!=4 or any(v is not True for v in checks): raise ValueError('Confirm all four eligibility checks')
                    expiry=svalue(d,'expiry',0,10)
                    if cat=='Food & sweets':
                        try: exp=date.fromisoformat(expiry)
                        except ValueError: raise ValueError('Enter a valid expiry or best-before date for food')
                        if exp<=date.today(): raise ValueError('Food must not be past its labelled date')
                    else: expiry=None
                    photo=decode_photo(d.get('photo_data',''))
                    cur=c.execute('INSERT INTO listings(owner_id,name,category,quantity,price,area,city,note,expiry,created) VALUES(?,?,?,?,?,?,?,?,?,?)',(u['id'],name,cat,qty,price,area,city,note,expiry,int(time.time())))
                    listing_id=cur.lastrowid
                    if photo: c.execute('INSERT INTO listing_photos(listing_id,data) VALUES(?,?)',(listing_id,photo))
                    c.commit(); return self.send_json(201,{'id':listing_id})
                if path=='/api/requests':
                    listing_id=get_int(d.get('listing_id')); kind=svalue(d,'type',3,4); message=svalue(d,'message',0,300)
                    if kind not in ('swap','buy'): raise ValueError('Invalid request type')
                    l=c.execute('SELECT * FROM listings WHERE id=? AND status=\'available\'',(listing_id,)).fetchone()
                    if not l or (l['expiry'] and l['expiry'] < date.today().isoformat()): raise ValueError('This listing is no longer available')
                    if l['owner_id']==u['id']: raise ValueError('You cannot request your own gift')
                    if blocked(c,u['id'],l['owner_id']): raise ValueError('This request is unavailable')
                    if not allowed('request:'+str(u['id']),30,3600): return self.send_json(429,{'error':'Too many requests. Please try again later.'})
                    if kind=='buy' and l['price'] is None: raise ValueError('This gift is only available for swaps')
                    offered=None
                    if kind=='swap':
                        offered=get_int(d.get('offered_id'))
                        if not c.execute("SELECT id FROM listings WHERE id=? AND owner_id=? AND status='available' AND (expiry IS NULL OR expiry>=?)",(offered,u['id'],date.today().isoformat())).fetchone(): raise ValueError('Select one of your available listings to offer')
                    if c.execute("SELECT 1 FROM requests WHERE listing_id=? AND sender_id=? AND status='pending'",(listing_id,u['id'])).fetchone(): raise ValueError('You already have a pending request for this item')
                    cur=c.execute('INSERT INTO requests(listing_id,sender_id,receiver_id,type,offered_id,message,created) VALUES(?,?,?,?,?,?,?)',(listing_id,u['id'],l['owner_id'],kind,offered,message,int(time.time())))
                    c.commit(); return self.send_json(201,{'id':cur.lastrowid})
                m=re.fullmatch(r'/api/requests/(\d+)/(accept|decline|pickup|confirm-pickup)',path)
                if m:
                    rid=int(m.group(1)); action=m.group(2)
                    c.execute('BEGIN IMMEDIATE')
                    r=c.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
                    if not r or u['id'] not in (r['sender_id'],r['receiver_id']): return self.send_json(404,{'error':'Request not found'})
                    if action in ('accept','decline'):
                        if u['id']!=r['receiver_id'] or r['status']!='pending': raise ValueError('Only the recipient can respond to a pending request')
                        if action=='accept':
                            ids=[r['listing_id']]+([r['offered_id']] if r['offered_id'] else [])
                            for lid in ids:
                                if not c.execute("SELECT id FROM listings WHERE id=? AND status='available' AND (expiry IS NULL OR expiry>=?)",(lid,date.today().isoformat())).fetchone(): raise ValueError('One of the gifts is no longer available')
                            for lid in ids: c.execute("UPDATE listings SET status='reserved' WHERE id=?",(lid,))
                            placeholders=','.join('?'*len(ids))
                            c.execute(f"UPDATE requests SET status='declined' WHERE status='pending' AND id<>? AND (listing_id IN ({placeholders}) OR offered_id IN ({placeholders}))", [rid]+ids+ids)
                        c.execute('UPDATE requests SET status=? WHERE id=?',('accepted' if action=='accept' else 'declined',rid))
                    elif action=='pickup':
                        if r['status']!='accepted': raise ValueError('Accept the request first')
                        place=svalue(d,'place',3,160); pickup_time=svalue(d,'pickup_time',3,100)
                        c.execute("UPDATE requests SET place=?,pickup_time=?,pickup_by=?,pickup_status='proposed' WHERE id=?",(place,pickup_time,u['id'],rid))
                    else:
                        if r['status']!='accepted' or r['pickup_status']!='proposed' or r['pickup_by']==u['id']: raise ValueError('Only the other person can confirm a pickup proposal')
                        c.execute("UPDATE requests SET pickup_status='confirmed' WHERE id=?",(rid,))
                    c.commit(); return self.send_json(200,{'ok':True})
                if path=='/api/listings/delete':
                    lid=get_int(d.get('id'))
                    row=c.execute('SELECT * FROM listings WHERE id=? AND owner_id=?',(lid,u['id'])).fetchone()
                    if not row: return self.send_json(404,{'error':'Listing not found'})
                    if row['status']!='available': raise ValueError('Reserved listings cannot be removed')
                    c.execute("UPDATE listings SET status='removed' WHERE id=?",(lid,))
                    c.execute("UPDATE requests SET status='declined' WHERE status='pending' AND (listing_id=? OR offered_id=?)",(lid,lid))
                    c.commit(); return self.send_json(200,{'ok':True})
                return self.send_json(404,{'error':'Not found'})
        except ValueError as e: self.send_json(400,{'error':str(e)})
        except Exception as e:
            print('POST error:',repr(e),flush=True); self.send_json(500,{'error':'Server error'})

if __name__=='__main__':
    setup(); print(f'Gift Exchange Marketplace running on http://0.0.0.0:{PORT}',flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
