import sqlite3, json, time

DB = "/data/licenses.db"  # pe Render vom monta un disk la /data

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
          email TEXT NOT NULL,
          license_key TEXT NOT NULL PRIMARY KEY,
          active INTEGER NOT NULL DEFAULT 1,
          expiry INTEGER NOT NULL DEFAULT 0,
          max_devices INTEGER NOT NULL DEFAULT 1,
          bound_devices TEXT NOT NULL DEFAULT '[]',
          updated_at INTEGER NOT NULL
        );
        """)
        con.commit()

def now(): return int(time.time())

def upsert_license(email, key, active, expiry, max_devices=1):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT license_key FROM licenses WHERE license_key=?", (key,))
        exists = cur.fetchone()
        if exists:
            cur.execute("""UPDATE licenses SET email=?, active=?, expiry=?, max_devices=?, updated_at=?
                           WHERE license_key=?""",
                        (email, int(active), int(expiry), int(max_devices), now(), key))
        else:
            cur.execute("""INSERT INTO licenses (email, license_key, active, expiry, max_devices, bound_devices, updated_at)
                           VALUES (?, ?, ?, ?, ?, '[]', ?)""",
                        (email, key, int(active), int(expiry), int(max_devices), now()))
        con.commit()

def get_license(key):
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM licenses WHERE license_key=?", (key,))
        row = cur.fetchone()
        return dict(row) if row else None

def bind_device(key, fp):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT bound_devices, max_devices FROM licenses WHERE license_key=?", (key,))
        row = cur.fetchone()
        if not row: return False, "no_license"
        devices = json.loads(row[0] or "[]")
        max_dev = int(row[1])
        if fp in devices:
            return True, "ok"
        if len(devices) >= max_dev:
            return False, "device_limit"
        devices.append(fp)
        cur.execute("UPDATE licenses SET bound_devices=?, updated_at=? WHERE license_key=?",
                    (json.dumps(devices), now(), key))
        con.commit()
        return True, "ok"
