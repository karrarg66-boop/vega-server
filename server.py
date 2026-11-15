"""VEGA proof-of-concept API. Run only behind HTTPS and a private MikroTik network."""
import os, sqlite3, secrets, hashlib, hmac, json, socket, ssl, struct, time, ipaddress
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import jwt
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel, Field

DB = os.getenv('VEGA_DB', '/tmp/vega.db')
SECRET = os.getenv('VEGA_JWT_SECRET', '')
FERNET_KEY = os.getenv('VEGA_ENCRYPTION_KEY', '')
if not SECRET or len(SECRET)<32 or not FERNET_KEY:
    raise RuntimeError('Set VEGA_JWT_SECRET (>=32 chars) and VEGA_ENCRYPTION_KEY')
crypt = Fernet(FERNET_KEY.encode())
app = FastAPI(title='VEGA Server', docs_url=None, redoc_url=None)

def db():
    c=sqlite3.connect(DB, timeout=10)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def setup():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','viewer')), enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, name TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 8729, router_user TEXT NOT NULL, router_password_enc TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS assignments(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, PRIMARY KEY(user_id,device_id));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, target TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS password_recovery (
            id INTEGER PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            username TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','resolved')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_recovery_username_time ON password_recovery(username, created_at);
        CREATE TABLE IF NOT EXISTS recovery_rate_limits (
            rate_key TEXT PRIMARY KEY,
            last_requested INTEGER NOT NULL
        );
        ''')
        admin=os.getenv('VEGA_INITIAL_ADMIN','')
        pw=os.getenv('VEGA_INITIAL_ADMIN_PASSWORD','')
        if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
            if not admin or len(pw)<12: raise RuntimeError('Set VEGA_INITIAL_ADMIN and VEGA_INITIAL_ADMIN_PASSWORD (>=12 chars) on first run')
            c.execute('INSERT INTO users(full_name,username,password_hash,role) VALUES(?,?,?,?)',('Administrator',admin,hash_password(pw),'admin'))

@app.on_event('startup')
def startup():
    setup()

@app.middleware('http')
async def initialize_database(request, call_next):
    setup()
    return await call_next(request)

def hash_password(password):
    salt=secrets.token_bytes(16)
    dk=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600_000)
    return salt.hex()+':'+dk.hex()

def check_password(password, encoded):
    try:
        salt,expected=encoded.split(':')
        actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600_000)
        return hmac.compare_digest(actual,bytes.fromhex(expected))
    except (ValueError,TypeError): return False

def audit(c, actor, action, target=''):
    c.execute('INSERT INTO audit(actor_id,action,target) VALUES(?,?,?)',(actor,action,str(target)))

def token_for(row):
    now=datetime.now(timezone.utc)
    return jwt.encode({'sub':str(row['id']),'role':row['role'],'iat':now,'exp':now+timedelta(hours=8)},SECRET,algorithm='HS256')

def current(authorization: str=Header(default='')):
    if not authorization.startswith('Bearer '): raise HTTPException(401,'Authentication required')
    try: claims=jwt.decode(authorization[7:],SECRET,algorithms=['HS256'])
    except jwt.PyJWTError: raise HTTPException(401,'Invalid or expired session')
    with db() as c: row=c.execute('SELECT id,username,full_name,role,enabled FROM users WHERE id=?',(claims['sub'],)).fetchone()
    if not row or not row['enabled'] or row['role']!=claims['role']: raise HTTPException(401,'Account disabled or invalid')
    return dict(row)

def admin(user=Depends(current)):
    if user['role']!='admin': raise HTTPException(403,'Admin only')
    return user

class Login(BaseModel):
    username:str
    password:str
class NewUser(BaseModel):
    full_name:str=Field(min_length=1,max_length=120)
    username:str=Field(min_length=3,max_length=64,pattern=r'^[a-zA-Z0-9_.-]+$')
    password:str=Field(min_length=10,max_length=128)
    device_ids:list[int]=Field(default_factory=list)
    enabled:bool=True
class UpdateAssignments(BaseModel):
    device_ids:list[int]
class PasswordChange(BaseModel):
    password:str=Field(min_length=10,max_length=128)
class NewDevice(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    model:str=Field(default='',max_length=100)
    host:str=Field(min_length=1,max_length=253)
    port:int=Field(default=8729,ge=1,le=65535)
    router_user:str=Field(min_length=1,max_length=100)
    router_password:str=Field(min_length=1,max_length=256)

@app.post('/api/login')
def login(body:Login):
    with db() as c: row=c.execute('SELECT * FROM users WHERE username=?',(body.username,)).fetchone()
    if not row or not row['enabled'] or not check_password(body.password,row['password_hash']):
        raise HTTPException(401,'Incorrect credentials')
    return {'access_token':token_for(row),'token_type':'bearer','role':row['role'],'full_name':row['full_name']}

@app.get('/api/me')
def me(u=Depends(current)): return u

@app.get('/api/admin/users')
def users(a=Depends(admin)):
    with db() as c:
        rows=c.execute("SELECT id,full_name,username,enabled FROM users WHERE role='viewer' ORDER BY id DESC").fetchall()
        return [{**dict(r),'device_ids':[x['device_id'] for x in c.execute('SELECT device_id FROM assignments WHERE user_id=?',(r['id'],))]} for r in rows]

def verify_devices(c, ids):
    if len(ids)!=len(set(ids)): raise HTTPException(400,'Duplicate devices')
    for device_id in ids:
        if not c.execute('SELECT 1 FROM devices WHERE id=?',(device_id,)).fetchone(): raise HTTPException(400,f'Unknown device {device_id}')

@app.post('/api/admin/users',status_code=201)
def add_user(body:NewUser,a=Depends(admin)):
    with db() as c:
        verify_devices(c,body.device_ids)
        try:
            cur=c.execute('INSERT INTO users(full_name,username,password_hash,role,enabled) VALUES(?,?,?,?,?)',(body.full_name,body.username,hash_password(body.password),'viewer',int(body.enabled)))
        except sqlite3.IntegrityError: raise HTTPException(409,'Username already exists')
        uid=cur.lastrowid
        c.executemany('INSERT INTO assignments(user_id,device_id) VALUES(?,?)',[(uid,x) for x in body.device_ids])
        audit(c,a['id'],'create_user',uid)
    return {'id':uid,'username':body.username,'device_ids':body.device_ids}

@app.put('/api/admin/users/{uid}/assignments')
def assign(uid:int,body:UpdateAssignments,a=Depends(admin)):
    with db() as c:
        if not c.execute("SELECT 1 FROM users WHERE id=? AND role='viewer'",(uid,)).fetchone(): raise HTTPException(404,'User not found')
        verify_devices(c,body.device_ids)
        c.execute('DELETE FROM assignments WHERE user_id=?',(uid,))
        c.executemany('INSERT INTO assignments(user_id,device_id) VALUES(?,?)',[(uid,x) for x in body.device_ids])
        audit(c,a['id'],'assign_devices',uid)
    return {'ok':True}

@app.put('/api/admin/users/{uid}/password')
def change_password(uid:int,body:PasswordChange,a=Depends(admin)):
    with db() as c:
        cur=c.execute("UPDATE users SET password_hash=? WHERE id=? AND role='viewer'",(hash_password(body.password),uid))
        if not cur.rowcount: raise HTTPException(404,'User not found')
        audit(c,a['id'],'change_password',uid)
    return {'ok':True}

@app.put('/api/admin/users/{uid}/enabled/{enabled}')
def set_enabled(uid:int,enabled:bool,a=Depends(admin)):
    with db() as c:
        cur=c.execute("UPDATE users SET enabled=? WHERE id=? AND role='viewer'",(int(enabled),uid))
        if not cur.rowcount: raise HTTPException(404,'User not found')
        audit(c,a['id'],'set_enabled',uid)
    return {'ok':True}

@app.get('/api/admin/devices')
def all_devices(a=Depends(admin)):
    with db() as c: return [dict(r) for r in c.execute('SELECT id,name,model,host,port,router_user,enabled FROM devices ORDER BY id DESC')]

@app.post('/api/admin/devices',status_code=201)
def add_device(body:NewDevice,a=Depends(admin)):
    # Host is server-controlled, never provided by viewer. Validate as IP or DNS hostname.
    if '://' in body.host or '/' in body.host or any(x.isspace() for x in body.host): raise HTTPException(400,'Invalid host')
    with db() as c:
        cur=c.execute('INSERT INTO devices(name,model,host,port,router_user,router_password_enc) VALUES(?,?,?,?,?,?)',(body.name,body.model,body.host,body.port,body.router_user,crypt.encrypt(body.router_password.encode()).decode()))
        audit(c,a['id'],'create_device',cur.lastrowid)
    return {'id':cur.lastrowid,'name':body.name}

@app.get('/api/devices')
def my_devices(u=Depends(current)):
    with db() as c:
        if u['role']=='admin': rows=c.execute('SELECT id,name,model,enabled FROM devices').fetchall()
        else: rows=c.execute('SELECT d.id,d.name,d.model,d.enabled FROM devices d JOIN assignments a ON d.id=a.device_id WHERE a.user_id=? AND d.enabled=1',(u['id'],)).fetchall()
    return [dict(r) for r in rows]

def routeros_len(n):
    if n<0x80:return bytes([n])
    if n<0x4000:return struct.pack('>H',n|0x8000)
    if n<0x200000:return bytes([(n>>16)|0xC0,(n>>8)&255,n&255])
    if n<0x10000000:return struct.pack('>I',n|0xE0000000)
    return b'\xF0'+struct.pack('>I',n)

def read_len(s):
    a=s.recv(1)
    if not a: raise ConnectionError('Connection closed')
    b=a[0]
    if b<0x80:return b
    if b<0xC0:return ((b&0x3f)<<8)|s.recv(1)[0]
    if b<0xE0:return ((b&0x1f)<<16)|int.from_bytes(read_exact(s,2),'big')
    if b<0xF0:return ((b&0x0f)<<24)|int.from_bytes(read_exact(s,3),'big')
    return int.from_bytes(read_exact(s,4),'big')

def read_exact(s,n):
    buf=b''
    while len(buf)<n:
        data=s.recv(n-len(buf))
        if not data: raise ConnectionError('Connection closed')
        buf+=data
    return buf

def sentence(s,words):
    s.sendall(b''.join(routeros_len(len(w.encode()))+w.encode() for w in words)+b'\0')

def response(s):
    result=[]
    for _ in range(1000):
        words=[]
        while True:
            n=read_len(s)
            if n==0:break
            if n>1024*1024:raise ValueError('Oversized API response')
            words.append(read_exact(s,n).decode(errors='replace'))
        if not words:continue
        if words[0]=='!done':return result
        if words[0] in ('!trap','!fatal'):raise ConnectionError('RouterOS rejected command')
        if words[0]=='!re':result.append({k[1:].split('=',1)[0]:k.split('=',2)[-1] for k in words[1:] if k.startswith('=')})
    raise ConnectionError('Too many API records')

def fetch_router(d):
    # TLS verification requires server trust of a certificate with matching hostname.
    context=ssl.create_default_context()
    with socket.create_connection((d['host'],d['port']),timeout=5) as raw:
        with context.wrap_socket(raw,server_hostname=d['host']) as s:
            s.settimeout(7)
            sentence(s,['/login','=name='+d['router_user'],'=password='+crypt.decrypt(d['router_password_enc'].encode()).decode()])
            response(s)
            sentence(s,['/system/resource/print'])
            resource=response(s)
            sentence(s,['/interface/print'])
            interfaces=response(s)
    return {'resource':resource[0] if resource else {},'interfaces':interfaces[:128]}

@app.get('/api/devices/{device_id}/status')
def status(device_id:int,u=Depends(current)):
    with db() as c:
        if u['role']=='admin': row=c.execute('SELECT * FROM devices WHERE id=? AND enabled=1',(device_id,)).fetchone()
        else: row=c.execute('SELECT d.* FROM devices d JOIN assignments a ON a.device_id=d.id WHERE d.id=? AND a.user_id=? AND d.enabled=1',(device_id,u['id'])).fetchone()
    if not row: raise HTTPException(404,'Device unavailable')
    try: return fetch_router(row)
    except Exception: raise HTTPException(502,'Router unreachable or TLS/API authentication failed')

@app.get('/api/admin/audit')
def logs(a=Depends(admin)):
    with db() as c: return [dict(r) for r in c.execute('SELECT id,actor_id,action,target,created_at FROM audit ORDER BY id DESC LIMIT 100')]

from fastapi.responses import FileResponse
from pathlib import Path

@app.get('/admin', include_in_schema=False)
def admin_page():
    return FileResponse(Path(__file__).resolve().parent / 'admin.html')

# VEGA V13: viewer password recovery requests
class RecoveryRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=20, pattern=r'^\+?[0-9\s()\-]{7,20}$')

class ResolveRecovery(BaseModel):
    password: str = Field(min_length=10, max_length=128)

@app.post('/api/password-recovery', status_code=200)
def request_recovery(body: RecoveryRequest):
    username = body.username.strip()
    name = body.full_name.strip()
    phone = body.phone.strip()
    if not name or not phone:
        raise HTTPException(400, 'Invalid request')
    now = int(time.time())
    # Shared DB throttling: a username may submit at most once per 15 minutes.
    # Generic responses avoid disclosing whether an account exists.
    rate_key = hmac.new(SECRET.encode(), ('recovery:'+username.lower()).encode(), hashlib.sha256).hexdigest()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        last = c.execute('SELECT last_requested FROM recovery_rate_limits WHERE rate_key=?', (rate_key,)).fetchone()
        if last is None or now - last['last_requested'] >= 900:
            c.execute('INSERT INTO recovery_rate_limits(rate_key,last_requested) VALUES(?,?) ON CONFLICT(rate_key) DO UPDATE SET last_requested=excluded.last_requested', (rate_key,now))
            user = c.execute("SELECT id FROM users WHERE username=? AND role='viewer' AND enabled=1", (username,)).fetchone()
            if user:
                pending = c.execute("SELECT 1 FROM password_recovery WHERE user_id=? AND status='pending' LIMIT 1", (user['id'],)).fetchone()
                if not pending:
                    c.execute('INSERT INTO password_recovery(user_id,username,full_name,phone) VALUES(?,?,?,?)', (user['id'],username,name,phone))
    return {'ok':True,'message':'If the account is eligible, the request has been received.'}

@app.get('/api/admin/password-recovery')
def list_recovery(a=Depends(admin)):
    with db() as c:
        rows=c.execute('SELECT id,username,full_name,phone,status,created_at,resolved_at FROM password_recovery ORDER BY id DESC LIMIT 100').fetchall()
        return [dict(r) for r in rows]

@app.post('/api/admin/password-recovery/{request_id}/resolve')
def resolve_recovery(request_id:int,body:ResolveRecovery,a=Depends(admin)):
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        request=c.execute("SELECT * FROM password_recovery WHERE id=? AND status='pending'",(request_id,)).fetchone()
        if not request: raise HTTPException(404,'Pending request not found')
        user=c.execute("SELECT id FROM users WHERE id=? AND role='viewer' AND enabled=1",(request['user_id'],)).fetchone()
        if not user: raise HTTPException(404,'User unavailable')
        # Administrator must verify the requester's identity outside this API before reset.
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(body.password),user['id']))
        c.execute("UPDATE password_recovery SET status='resolved',resolved_at=CURRENT_TIMESTAMP WHERE id=?",(request_id,))
        audit(c,a['id'],'resolve_password_recovery',request_id)
    return {'ok':True}


@app.get('/app', include_in_schema=False)
def viewer_app():
    return FileResponse(Path(__file__).resolve().parent / 'app.html', media_type='text/html', headers={'Cache-Control':'no-store'})
