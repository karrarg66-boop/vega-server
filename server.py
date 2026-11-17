"""VIGA MONITOR phase 1: PostgreSQL authentication and viewer provisioning.
Read-only monitoring endpoints will be added in a later phase.
"""
import os, secrets, hashlib, hmac
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import jwt
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Depends, Header, HTTPException
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SECRET = os.environ.get('VIGA_JWT_SECRET', '')
INITIAL_ADMIN = os.environ.get('VIGA_INITIAL_ADMIN', '')
INITIAL_PASSWORD = os.environ.get('VIGA_INITIAL_ADMIN_PASSWORD', '')
if not DATABASE_URL or len(SECRET) < 32 or not INITIAL_ADMIN or len(INITIAL_PASSWORD) < 12:
    raise RuntimeError('Set DATABASE_URL, VIGA_JWT_SECRET (32+ chars), VIGA_INITIAL_ADMIN and VIGA_INITIAL_ADMIN_PASSWORD (12+ chars)')
app = FastAPI(title='VIGA MONITOR API', docs_url=None, redoc_url=None)

@contextmanager
def db():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10) as conn:
        yield conn

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return salt.hex() + ':' + digest.hex()

def verify_password(password, encoded):
    try:
        salt, expected = encoded.split(':', 1)
        got = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000)
        return hmac.compare_digest(got, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False

@app.on_event('startup')
def setup():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin','viewer')),
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            must_change_password BOOLEAN NOT NULL DEFAULT FALSE
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS devices (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name TEXT NOT NULL, model TEXT NOT NULL DEFAULT '',
            enabled BOOLEAN NOT NULL DEFAULT TRUE
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS assignments (
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, device_id)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS audit (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            actor_id BIGINT, action TEXT NOT NULL, target TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )''')
        conn.execute('''INSERT INTO users(full_name,username,password_hash,role)
            SELECT %s,%s,%s,'admin' WHERE NOT EXISTS (SELECT 1 FROM users WHERE role='admin')''',
            ('Administrator', INITIAL_ADMIN, hash_password(INITIAL_PASSWORD)))

class Login(BaseModel):
    username: str
    password: str
class NewUser(BaseModel):
    full_name: str = Field(min_length=1,max_length=120)
    username: str = Field(min_length=3,max_length=64,pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=12,max_length=128)
    device_ids: list[int] = Field(default_factory=list)
class NewDevice(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    model: str = Field(default='',max_length=100)
class Assign(BaseModel):
    device_ids: list[int]
class ResetViewerPassword(BaseModel):
    password: str = Field(min_length=12,max_length=128)

@app.get('/api/health')
def health():
    with db() as conn:
        conn.execute('SELECT 1').fetchone()
    return {'ok': True, 'service': 'VIGA MONITOR'}

@app.post('/api/login')
def login(body: Login):
    with db() as conn:
        row = conn.execute('SELECT * FROM users WHERE username=%s', (body.username,)).fetchone()
    if not row or not row['enabled'] or not verify_password(body.password,row['password_hash']):
        raise HTTPException(401,'Incorrect credentials')
    now=datetime.now(timezone.utc)
    token=jwt.encode({'sub':str(row['id']),'role':row['role'],'iat':now,'exp':now+timedelta(hours=8)},SECRET,algorithm='HS256')
    return {'access_token':token,'token_type':'bearer','role':row['role'],'full_name':row['full_name'],'must_change_password':row['must_change_password']}

def current(authorization: str = Header(default='')):
    if not authorization.startswith('Bearer '):
        raise HTTPException(401,'Authentication required')
    try:
        claims=jwt.decode(authorization[7:],SECRET,algorithms=['HS256'])
        uid=int(claims['sub'])
    except (jwt.PyJWTError,KeyError,ValueError):
        raise HTTPException(401,'Invalid session')
    with db() as conn:
        user=conn.execute('SELECT id,username,full_name,role,enabled,must_change_password FROM users WHERE id=%s',(uid,)).fetchone()
    if not user or not user['enabled'] or user['role']!=claims.get('role'):
        raise HTTPException(401,'Account unavailable')
    return user

def admin(user=Depends(current)):
    if user['role']!='admin':
        raise HTTPException(403,'Admin only')
    return user

@app.get('/api/me')
def me(user=Depends(current)):
    return user

@app.get('/api/admin/users')
def list_users(user=Depends(admin)):
    with db() as conn:
        rows=conn.execute("SELECT id,full_name,username,enabled FROM users WHERE role='viewer' ORDER BY id DESC").fetchall()
        for row in rows:
            row['device_ids']=[r['device_id'] for r in conn.execute('SELECT device_id FROM assignments WHERE user_id=%s',(row['id'],)).fetchall()]
    return rows

def validate_devices(conn, ids):
    if len(ids)!=len(set(ids)):
        raise HTTPException(400,'Duplicate device IDs')
    for did in ids:
        if not conn.execute('SELECT 1 FROM devices WHERE id=%s',(did,)).fetchone():
            raise HTTPException(400,'Unknown device')

@app.post('/api/admin/users',status_code=201)
def add_user(body:NewUser,user=Depends(admin)):
    with db() as conn:
        validate_devices(conn,body.device_ids)
        try:
            row=conn.execute("INSERT INTO users(full_name,username,password_hash,role) VALUES(%s,%s,%s,'viewer') RETURNING id",(body.full_name,body.username,hash_password(body.password))).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409,'Username already exists')
        for did in body.device_ids:
            conn.execute('INSERT INTO assignments(user_id,device_id) VALUES(%s,%s)',(row['id'],did))
        conn.execute('INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',(user['id'],'create_user',str(row['id'])))
    return {'id':row['id'],'username':body.username}

@app.get('/api/admin/devices')
def all_devices(user=Depends(admin)):
    with db() as conn:
        return conn.execute('SELECT id,name,model,enabled FROM devices ORDER BY id DESC').fetchall()

@app.post('/api/admin/devices',status_code=201)
def add_device(body:NewDevice,user=Depends(admin)):
    with db() as conn:
        row=conn.execute('INSERT INTO devices(name,model) VALUES(%s,%s) RETURNING id',(body.name,body.model)).fetchone()
        conn.execute('INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',(user['id'],'create_device',str(row['id'])))
    return {'id':row['id'],'name':body.name}

@app.put('/api/admin/users/{uid}/assignments')
def assign(uid:int,body:Assign,user=Depends(admin)):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE id=%s AND role='viewer'",(uid,)).fetchone():
            raise HTTPException(404,'Viewer not found')
        validate_devices(conn,body.device_ids)
        conn.execute('DELETE FROM assignments WHERE user_id=%s',(uid,))
        for did in body.device_ids:
            conn.execute('INSERT INTO assignments(user_id,device_id) VALUES(%s,%s)',(uid,did))
        conn.execute('INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',(user['id'],'assign_devices',str(uid)))
    return {'ok':True}

@app.put('/api/admin/users/{uid}/password')
def reset_viewer_password(uid:int,body:ResetViewerPassword,user=Depends(admin)):
    with db() as conn:
        row=conn.execute("UPDATE users SET password_hash=%s,must_change_password=TRUE WHERE id=%s AND role='viewer' RETURNING id",(hash_password(body.password),uid)).fetchone()
        if not row:
            raise HTTPException(404,'Viewer not found')
        conn.execute('INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',(user['id'],'reset_viewer_password',str(uid)))
    return {'ok':True}

@app.get('/api/devices')
def my_devices(user=Depends(current)):
    with db() as conn:
        if user['role']=='admin':
            return conn.execute('SELECT id,name,model,enabled FROM devices').fetchall()
        return conn.execute('''SELECT d.id,d.name,d.model,d.enabled FROM devices d
            JOIN assignments a ON a.device_id=d.id WHERE a.user_id=%s AND d.enabled=TRUE''',(user['id'],)).fetchall()

from fastapi.responses import FileResponse
from pathlib import Path

@app.get("/", include_in_schema=False)
def viga_home():
    return FileResponse(
        Path(__file__).resolve().parent / "VIGA_V31_Real_Data_Phase2_1_Fixed.html",
        media_type="text/html"
    )
