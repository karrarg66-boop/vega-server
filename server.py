
"""VIGA MONITOR — By Karrar"""
import os, secrets, hashlib, hmac, base64, ipaddress
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import jwt
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SECRET = os.environ.get('VIGA_JWT_SECRET', '')
INITIAL_ADMIN = os.environ.get('VIGA_INITIAL_ADMIN', '')
INITIAL_PASSWORD = os.environ.get('VIGA_INITIAL_ADMIN_PASSWORD', '')
ENCRYPTION_KEY = os.environ.get('VIGA_ENCRYPTION_KEY', '')
VIGA_BRIDGE_TOKEN = os.environ.get('VIGA_BRIDGE_TOKEN', '')

if not ENCRYPTION_KEY:
    raise RuntimeError('Set VIGA_ENCRYPTION_KEY to a Fernet key')

CIPHER = Fernet(ENCRYPTION_KEY.encode())

if not DATABASE_URL or len(SECRET) < 32 or not INITIAL_ADMIN or len(INITIAL_PASSWORD) < 12:
    raise RuntimeError('Set DATABASE_URL, VIGA_JWT_SECRET, VIGA_INITIAL_ADMIN and VIGA_INITIAL_ADMIN_PASSWORD')

app = FastAPI(title='VIGA MONITOR API', docs_url=None, redoc_url=None)


@contextmanager
def db():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10) as conn:
        yield conn


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt, 600000
    )
    return salt.hex() + ':' + digest.hex()


def verify_password(password, encoded):
    try:
        salt, expected = encoded.split(':', 1)
        got = hashlib.pbkdf2_hmac(
            'sha256', password.encode(),
            bytes.fromhex(salt), 600000
        )
        return hmac.compare_digest(got, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


@app.on_event('startup')
def setup():
    with db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin','viewer')),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                must_change_password BOOLEAN NOT NULL DEFAULT FALSE
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name TEXT NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                enabled BOOLEAN NOT NULL DEFAULT TRUE
            )
        ''')

        conn.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS host TEXT NOT NULL DEFAULT ''")
        conn.execute('ALTER TABLE devices ADD COLUMN IF NOT EXISTS port INTEGER NOT NULL DEFAULT 8729')
        conn.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS router_user TEXT NOT NULL DEFAULT ''")
        conn.execute('ALTER TABLE devices ADD COLUMN IF NOT EXISTS router_password_encrypted TEXT')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS assignments (
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, device_id)
            )
        ''')

        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT")

        conn.execute('''
            CREATE TABLE IF NOT EXISTS recovery_requests (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                contact TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                actor_id BIGINT,
                action TEXT NOT NULL,
                target TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        ''')

        conn.execute("ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS full_name TEXT")

        conn.execute('''
            INSERT INTO users(full_name,username,password_hash,role)
            SELECT %s,%s,%s,'admin'
            WHERE NOT EXISTS (
                SELECT 1 FROM users WHERE role='admin'
            )
        ''', (
            'Administrator',
            INITIAL_ADMIN,
            hash_password(INITIAL_PASSWORD)
        ))

        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_metrics (
                device_id BIGINT PRIMARY KEY
                    REFERENCES devices(id) ON DELETE CASCADE,
                cpu DOUBLE PRECISION NOT NULL,
                free_memory BIGINT NOT NULL,
                total_memory BIGINT NOT NULL,
                uptime TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        ''')

        conn.execute('''
            ALTER TABLE device_metrics
            ADD COLUMN IF NOT EXISTS cpu_temperature DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS temperature DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS fan1 INTEGER,
            ADD COLUMN IF NOT EXISTS fan2 INTEGER,
            ADD COLUMN IF NOT EXISTS voltage DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS current DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS pppoe JSONB,
            ADD COLUMN IF NOT EXISTS interfaces JSONB
        ''')


class Login(BaseModel):
    username: str
    password: str


class NewUser(BaseModel):
    phone: str = Field(min_length=7, max_length=25, pattern=r'^[+0-9 ()-]+$')
    full_name: str = Field(min_length=1, max_length=120)
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=6, max_length=128)
    device_ids: list[int] = Field(default_factory=list)


class NewDevice(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    model: str = Field(default='', max_length=100)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=8729, ge=1, le=65535)
    router_user: str = Field(min_length=1, max_length=100)
    router_password: str = Field(min_length=1, max_length=256)


class Assign(BaseModel):
    device_ids: list[int]


class ResetViewerPassword(BaseModel):
    password: str = Field(min_length=6, max_length=128)


@app.get('/api/health')
def health():
    with db() as conn:
        conn.execute('SELECT 1').fetchone()
    return {'ok': True, 'service': 'VIGA MONITOR'}


@app.post('/api/login')
def login(body: Login):
    with db() as conn:
        row = conn.execute(
            'SELECT * FROM users WHERE username=%s',
            (body.username,)
        ).fetchone()

    if not row or not row['enabled'] or not verify_password(body.password, row['password_hash']):
        raise HTTPException(401, 'Incorrect credentials')

    now = datetime.now(timezone.utc)

    token = jwt.encode({
        'sub': str(row['id']),
        'role': row['role'],
        'iat': now,
        'exp': now + timedelta(hours=8)
    }, SECRET, algorithm='HS256')

    return {
        'access_token': token,
        'token_type': 'bearer',
        'role': row['role'],
        'full_name': row['full_name'],
        'must_change_password': row['must_change_password']
    }


def current(authorization: str = Header(default='')):
    if not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Authentication required')

    try:
        claims = jwt.decode(
            authorization[7:], SECRET,
            algorithms=['HS256']
        )
        uid = int(claims['sub'])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, 'Invalid session')

    with db() as conn:
        user = conn.execute(
            'SELECT id,username,full_name,role,enabled,must_change_password FROM users WHERE id=%s',
            (uid,)
        ).fetchone()

    if not user or not user['enabled'] or user['role'] != claims.get('role'):
        raise HTTPException(401, 'Account unavailable')

    return user


def admin(user=Depends(current)):
    if user['role'] != 'admin':
        raise HTTPException(403, 'Admin only')
    return user


@app.get('/api/me')
def me(user=Depends(current)):
    return user


@app.get('/api/admin/users')
def list_users(user=Depends(admin)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id,full_name,username,enabled,phone FROM users WHERE role='viewer' ORDER BY id DESC"
        ).fetchall()

        for row in rows:
            row['device_ids'] = [
                r['device_id'] for r in conn.execute(
                    'SELECT device_id FROM assignments WHERE user_id=%s',
                    (row['id'],)
                ).fetchall()
            ]

    return rows


def validate_devices(conn, ids):
    if len(ids) != len(set(ids)):
        raise HTTPException(400, 'Duplicate device IDs')

    for did in ids:
        if not conn.execute(
            'SELECT 1 FROM devices WHERE id=%s',
            (did,)
        ).fetchone():
            raise HTTPException(400, 'Unknown device')


@app.post('/api/admin/users', status_code=201)
def add_user(body: NewUser, user=Depends(admin)):
    with db() as conn:
        validate_devices(conn, body.device_ids)

        try:
            row = conn.execute(
                "INSERT INTO users(full_name,username,password_hash,role,phone) VALUES(%s,%s,%s,'viewer',%s) RETURNING id",
                (
                    body.full_name,
                    body.username,
                    hash_password(body.password),
                    body.phone
                )
            ).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Username already exists')

        for did in body.device_ids:
            conn.execute(
                'INSERT INTO assignments(user_id,device_id) VALUES(%s,%s)',
                (row['id'], did)
            )

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'create_user', str(row['id']))
        )

    return {'id': row['id'], 'username': body.username}


@app.get('/api/admin/devices')
def all_devices(user=Depends(admin)):
    with db() as conn:
        return conn.execute(
            'SELECT id,name,model,enabled,host,port,router_user FROM devices ORDER BY id DESC'
        ).fetchall()


@app.post('/api/admin/devices', status_code=201)
def add_device(body: NewDevice, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            'INSERT INTO devices(name,model,host,port,router_user,router_password_encrypted) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id',
            (
                body.name,
                body.model,
                body.host,
                body.port,
                body.router_user,
                CIPHER.encrypt(body.router_password.encode()).decode()
            )
        ).fetchone()

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'create_device', str(row['id']))
        )

    return {'id': row['id'], 'name': body.name}


@app.put('/api/admin/users/{uid}/assignments')
def assign(uid: int, body: Assign, user=Depends(admin)):
    with db() as conn:
        if not conn.execute(
            "SELECT 1 FROM users WHERE id=%s AND role='viewer'",
            (uid,)
        ).fetchone():
            raise HTTPException(404, 'Viewer not found')

        validate_devices(conn, body.device_ids)

        conn.execute(
            'DELETE FROM assignments WHERE user_id=%s',
            (uid,)
        )

        for did in body.device_ids:
            conn.execute(
                'INSERT INTO assignments(user_id,device_id) VALUES(%s,%s)',
                (uid, did)
            )

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'assign_devices', str(uid))
        )

    return {'ok': True}


@app.put('/api/admin/users/{uid}/password')
def reset_viewer_password(uid: int, body: ResetViewerPassword, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            "UPDATE users SET password_hash=%s,must_change_password=TRUE WHERE id=%s AND role='viewer' RETURNING id",
            (hash_password(body.password), uid)
        ).fetchone()

        if not row:
            raise HTTPException(404, 'Viewer not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'reset_viewer_password', str(uid))
        )

    return {'ok': True}


@app.get('/api/devices')
def my_devices(user=Depends(current)):
    with db() as conn:
        if user['role'] == 'admin':
            return conn.execute(
                'SELECT id,name,model,enabled FROM devices'
            ).fetchall()

        return conn.execute('''
            SELECT d.id,d.name,d.model,d.enabled,d.router_user
            FROM devices d
            JOIN assignments a ON a.device_id=d.id
            WHERE a.user_id=%s AND d.enabled=TRUE
        ''', (user['id'],)).fetchall()


class DeviceUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    model: str = Field(default='', max_length=100)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=8729, ge=1, le=65535)
    router_user: str = Field(min_length=1, max_length=100)
    router_password: str | None = Field(default=None, max_length=256)


@app.put('/api/admin/devices/{device_id}')
def update_device(device_id: int, body: DeviceUpdate, user=Depends(admin)):
    with db() as conn:
        if body.router_password:
            row = conn.execute(
                'UPDATE devices SET name=%s,model=%s,host=%s,port=%s,router_user=%s,router_password_encrypted=%s WHERE id=%s RETURNING id,name,model,enabled,host,port,router_user',
                (
                    body.name, body.model, body.host,
                    body.port, body.router_user,
                    CIPHER.encrypt(body.router_password.encode()).decode(),
                    device_id
                )
            ).fetchone()
        else:
            row = conn.execute(
                'UPDATE devices SET name=%s,model=%s,host=%s,port=%s,router_user=%s WHERE id=%s RETURNING id,name,model,enabled,host,port,router_user',
                (
                    body.name, body.model, body.host,
                    body.port, body.router_user, device_id
                )
            ).fetchone()

        if row is None:
            raise HTTPException(404, 'Device not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'update_device', str(device_id))
        )

    return row


@app.put('/api/admin/devices/{device_id}/enabled/{enabled}')
def set_device_enabled(device_id: int, enabled: bool, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            'UPDATE devices SET enabled=%s WHERE id=%s RETURNING id,enabled',
            (enabled, device_id)
        ).fetchone()

        if row is None:
            raise HTTPException(404, 'Device not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'set_device_enabled', str(device_id))
        )

    return row


@app.put('/api/admin/users/{uid}/enabled/{enabled}')
def set_viewer_enabled(uid: int, enabled: bool, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            "UPDATE users SET enabled=%s WHERE id=%s AND role='viewer' RETURNING id,enabled",
            (enabled, uid)
        ).fetchone()

        if row is None:
            raise HTTPException(404, 'Viewer not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'set_viewer_enabled', str(uid))
        )

    return row


@app.get('/api/admin/audit')
def list_audit(user=Depends(admin)):
    with db() as conn:
        return conn.execute(
            'SELECT id,actor_id,action,target,created_at FROM audit ORDER BY id DESC LIMIT 100'
        ).fetchall()


@app.get('/', include_in_schema=False)
def homepage():
    return FileResponse(
        Path(__file__).resolve().parent / 'index.html',
        media_type='text/html'
    )


class RecoveryRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=25, pattern=r'^[+0-9 ()-]+$')


@app.post('/api/recovery', status_code=202)
def recovery(body: RecoveryRequest):
    with db() as conn:
        conn.execute(
            "INSERT INTO recovery_requests(contact,full_name) SELECT %s,%s WHERE NOT EXISTS (SELECT 1 FROM recovery_requests WHERE contact=%s AND created_at > NOW()-INTERVAL '1 hour')",
            (body.phone, body.full_name, body.phone)
        )

    return {'ok': True}


@app.get('/api/admin/recovery')
def recovery_list(user=Depends(admin)):
    with db() as conn:
        return conn.execute(
            'SELECT id,contact,full_name,created_at,resolved FROM recovery_requests ORDER BY id DESC LIMIT 100'
        ).fetchall()


@app.put('/api/admin/recovery/{request_id}/resolve')
def resolve_recovery(request_id: int, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            'UPDATE recovery_requests SET resolved=TRUE WHERE id=%s RETURNING id,resolved',
            (request_id,)
        ).fetchone()

        if row is None:
            raise HTTPException(404, 'Recovery request not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'resolve_recovery', str(request_id))
        )

        return row


class ViewerUpdate(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    phone: str = Field(min_length=7, max_length=25, pattern=r'^[+0-9 ()-]+$')


@app.put('/api/admin/users/{uid}')
def edit_viewer(uid: int, body: ViewerUpdate, user=Depends(admin)):
    with db() as conn:
        try:
            row = conn.execute(
                "UPDATE users SET full_name=%s,username=%s,phone=%s WHERE id=%s AND role='viewer' RETURNING id",
                (body.full_name, body.username, body.phone, uid)
            ).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Username already exists')

        if not row:
            raise HTTPException(404, 'Viewer not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'edit_viewer', str(uid))
        )

    return row


@app.delete('/api/admin/users/{uid}')
def delete_viewer(uid: int, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            "DELETE FROM users WHERE id=%s AND role='viewer' RETURNING id",
            (uid,)
        ).fetchone()

        if not row:
            raise HTTPException(404, 'Viewer not found')

        conn.execute(
            'INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)',
            (user['id'], 'delete_viewer', str(uid))
        )

    return {'ok': True}


# Secure monitoring authentication

def verify_bridge_token(x_bridge_token: str = Header(default="")):
    if not VIGA_BRIDGE_TOKEN or not hmac.compare_digest(
        x_bridge_token, VIGA_BRIDGE_TOKEN
    ):
        raise HTTPException(401, "Unauthorized bridge")

    return True


# Monitoring metrics

class BridgeMetrics(BaseModel):
    device_id: int = Field(gt=0)
    cpu: float = Field(ge=0, le=100)
    free_memory: int = Field(ge=0)
    total_memory: int = Field(gt=0)
    uptime: str = Field(max_length=100)
    cpu_temperature: float | None = None
    temperature: float | None = None
    fan1: int | None = Field(default=None, ge=0)
    fan2: int | None = Field(default=None, ge=0)
    voltage: float | None = None
    current: float | None = None
    pppoe: list | None = Field(default=None, max_length=5000)
    interfaces: list | None = Field(default=None, max_length=1000)


@app.post("/api/bridge/metrics")
def receive_metrics(
    body: BridgeMetrics,
    authorized=Depends(verify_bridge_token)
):
    if body.free_memory > body.total_memory:
        raise HTTPException(422, "Invalid memory metrics")

    with db() as conn:
        device = conn.execute(
            "SELECT id FROM devices WHERE id=%s AND enabled=TRUE",
            (body.device_id,)
        ).fetchone()

        if not device:
            raise HTTPException(404, "Device not found")

        conn.execute("""
            INSERT INTO device_metrics (
                device_id,
                cpu,
                free_memory,
                total_memory,
                uptime,
                cpu_temperature,
                temperature,
                fan1,
                fan2,
                voltage,
                current,
                pppoe,
                interfaces
            )
            VALUES (
                %s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s
            )
            ON CONFLICT (device_id) DO UPDATE SET
                cpu=EXCLUDED.cpu,
                free_memory=EXCLUDED.free_memory,
                total_memory=EXCLUDED.total_memory,
                uptime=EXCLUDED.uptime,
                cpu_temperature=EXCLUDED.cpu_temperature,
                temperature=EXCLUDED.temperature,
                fan1=EXCLUDED.fan1,
                fan2=EXCLUDED.fan2,
                voltage=EXCLUDED.voltage,
                current=EXCLUDED.current,
                pppoe=EXCLUDED.pppoe,
                interfaces=EXCLUDED.interfaces,
                updated_at=NOW()
        """, (
            body.device_id,
            body.cpu,
            body.free_memory,
            body.total_memory,
            body.uptime,
            body.cpu_temperature,
            body.temperature,
            body.fan1,
            body.fan2,
            body.voltage,
            body.current,
            Jsonb(body.pppoe) if body.pppoe is not None else None,
            Jsonb(body.interfaces) if body.interfaces is not None else None
        ))

    return {"ok": True}


@app.get("/api/devices/{device_id}/metrics")
def get_device_metrics(device_id: int, user=Depends(current)):
    with db() as conn:
        if user["role"] != "admin":
            allowed = conn.execute("""
                SELECT 1
                FROM assignments a
                JOIN devices d ON d.id=a.device_id
                WHERE a.user_id=%s
                AND a.device_id=%s
                AND d.enabled=TRUE
            """, (user["id"], device_id)).fetchone()

            if not allowed:
                raise HTTPException(403, "Access denied")

        row = conn.execute("""
            SELECT
                cpu,
                free_memory,
                total_memory,
                uptime,
                cpu_temperature,
                temperature,
                fan1,
                fan2,
                voltage,
                current,
                pppoe,
                interfaces,
                updated_at
            FROM device_metrics
            WHERE device_id=%s
        """, (device_id,)).fetchone()

        if not row:
            raise HTTPException(404, "No monitoring data yet")

        return row


@app.delete("/api/admin/devices/{device_id}")
def delete_device(device_id: int, user=Depends(admin)):
    with db() as conn:
        row = conn.execute(
            "DELETE FROM devices WHERE id=%s RETURNING id",
            (device_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, "Device not found")

        conn.execute(
            "INSERT INTO audit(actor_id,action,target) VALUES(%s,%s,%s)",
            (user["id"], "delete_device", str(device_id))
        )

    return {"ok": True}

# Internal support; existing tables and routes are unchanged.
from typing import Literal

@app.on_event('startup')
def setup_support():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS support_requests (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            kind TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL,
            reply TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')

class SupportCreate(BaseModel):
    kind: Literal['problem','idea','feature']
    subject: str = Field(min_length=1,max_length=150)
    message: str = Field(min_length=1,max_length=4000)

class SupportReply(BaseModel):
    reply: str = Field(max_length=4000)
    status: Literal['new','processing','resolved']

@app.get('/api/support')
def support_list(user=Depends(current)):
    with db() as conn:
        sql = 'SELECT s.*,u.username,u.full_name FROM support_requests s JOIN users u ON u.id=s.user_id'
        if user['role']=='admin':
            return conn.execute(sql+' ORDER BY s.id DESC').fetchall()
        return conn.execute(sql+' WHERE s.user_id=%s ORDER BY s.id DESC',(user['id'],)).fetchall()

@app.post('/api/support',status_code=201)
def support_create(body: SupportCreate,user=Depends(current)):
    if user['role']!='viewer':
        raise HTTPException(403,'Viewer only')
    if not body.subject.strip() or not body.message.strip():
        raise HTTPException(422,'Empty request')
    with db() as conn:
        return conn.execute('INSERT INTO support_requests(user_id,kind,subject,message) VALUES(%s,%s,%s,%s) RETURNING id',(user['id'],body.kind,body.subject.strip(),body.message.strip())).fetchone()

@app.put('/api/admin/support/{rid}')
def support_reply(rid:int,body:SupportReply,user=Depends(admin)):
    with db() as conn:
        row=conn.execute('UPDATE support_requests SET reply=%s,status=%s,updated_at=NOW() WHERE id=%s RETURNING id',(body.reply,body.status,rid)).fetchone()
        if not row: raise HTTPException(404,'Request not found')
        return row

@app.delete('/api/admin/support/{rid}')
def support_delete(rid:int,user=Depends(admin)):
    with db() as conn:
        row=conn.execute('DELETE FROM support_requests WHERE id=%s RETURNING id',(rid,)).fetchone()
        if not row: raise HTTPException(404,'Request not found')
        return {'ok':True}
