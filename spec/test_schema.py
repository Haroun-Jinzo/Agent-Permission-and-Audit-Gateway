import sqlite3, hashlib, json, sys
sys.path.insert(0, '.')
from vectors import canon, call_hash, genesis, entry_hash

db = sqlite3.connect(':memory:')
db.execute("PRAGMA foreign_keys = ON")
db.executescript(open('schema.sql', encoding='utf-8').read())
print("schema loads")

now = "2026-11-10T09:00:00.000000Z"
later = "2026-11-10T09:30:00.000000Z"
db.execute("INSERT INTO principals VALUES ('p-admin','admin','alice','active',?)", (now,))
db.execute("INSERT INTO principals VALUES ('p-appr','approver','bob','active',?)", (now,))
db.execute("INSERT INTO roles VALUES ('r1','support','',60,4,5)")
db.execute("""INSERT INTO agents (agent_id,name,role_id,status,secret_hash,secret_created_at,created_by,created_at)
              VALUES ('a1','demo-agent','r1','active',?,?, 'p-admin', ?)""", ("0"*64, now, now))
db.execute("INSERT INTO tasks VALUES ('t1','a1','open','p-admin',?,?,NULL)", (now, later))
ch = "7f9b4913798426a3cca83230761db396c9e639704ed34ef677b541f7440b1764"

def expect_fail(sql, args=(), label=""):
    try:
        db.execute(sql, args); print("NOT BLOCKED:", label)
    except sqlite3.DatabaseError as e:
        print("blocked:", label, "->", str(e)[:60])

def pending(aid, h=ch):
    db.execute("""INSERT INTO approvals (approval_id,agent_id,task_id,call_hash,tool,risk,summary,status,created_at,decision_deadline)
                  VALUES (?,?,?,?,?,?,?,?,?,?)""", (aid,'a1','t1',h,'send_email','high','send mail','PENDING',now,later))
pending('ap1')
expect_fail("""INSERT INTO approvals (approval_id,agent_id,task_id,call_hash,tool,risk,summary,status,created_at,decision_deadline)
   VALUES ('ap2','a1','t1',?,'send_email','high','dup','PENDING',?,?)""", (ch, now, later), "duplicate open approval")

# decision transition: atomic conditional update
def decide(aid, decision, t):
    cur = db.execute("""UPDATE approvals SET status=?, decided_at=?, decided_by='p-appr', signature=?,
                        use_deadline=? WHERE approval_id=? AND status='PENDING' AND decision_deadline > ?""",
                     ('APPROVED' if decision=='approve' else 'REJECTED', t, 'f'*128,
                      "2026-11-10T09:40:00.000000Z", aid, t))
    return cur.rowcount
print("decide after deadline rowcount:", decide('ap1','approve',"2026-11-10T10:00:00.000000Z"))
print("decide in time rowcount:", decide('ap1','approve',"2026-11-10T09:05:00.000000Z"))
print("decide twice rowcount:", decide('ap1','approve',"2026-11-10T09:05:01.000000Z"))

def consume(aid, h, agent, t):
    cur = db.execute("""UPDATE approvals SET status='CONSUMED', consumed_at=?
                        WHERE approval_id=? AND status='APPROVED' AND call_hash=? AND agent_id=? AND use_deadline > ?""",
                     (t, aid, h, agent, t))
    return cur.rowcount
print("consume wrong hash:", consume('ap1', 'a'*64, 'a1', "2026-11-10T09:06:00.000000Z"))
print("consume ok:", consume('ap1', ch, 'a1', "2026-11-10T09:06:00.000000Z"))
print("consume again:", consume('ap1', ch, 'a1', "2026-11-10T09:06:01.000000Z"))
# after consume a new open approval for the same call is allowed
pending('ap3'); print("new approval after terminal state allowed")

# audit chain with stored canonical body
def append(chain, kind, body_fields, ts):
    row = db.execute("SELECT head_seq, head_hash FROM audit_heads WHERE chain_id=?", (chain,)).fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, genesis(chain))
    body = {"v":1,"chain_id":chain,"seq":seq,"ts":ts,"kind":kind, **body_fields}
    b = canon(body); h = entry_hash(prev, body)
    db.execute("INSERT INTO audit_entries (chain_id,seq,ts,kind,call_hash,approval_id,body,prev_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?,?)",
               (chain, seq, ts, kind, body_fields.get('call_hash'), body_fields.get('approval_id'), b.decode(), prev, h))
    db.execute("INSERT INTO audit_heads VALUES (?,?,?,?) ON CONFLICT(chain_id) DO UPDATE SET head_seq=excluded.head_seq, head_hash=excluded.head_hash, updated_at=excluded.updated_at",
               (chain, seq, h, ts))
    return h
h1 = append('demo-agent','INTENT',{"task_id":"task-1","tool":"send_email","call_hash":ch,"decision":"BLOCK","rule_ids":["R-EXFIL-1"],"policy_version":"default-policy@3:ab12cd34ef56"},"2026-11-10T09:00:00.000000Z")
print("entry 1 matches vector:", h1 == "053eb12b6acb1bb806add66a0b4e920d07abd200ea6078d3e086ffff45a21f82")
h2 = append('demo-agent','OUTCOME',{"task_id":"task-1","tool":"send_email","call_hash":ch,"outcome":"not_executed","reason":"blocked_by_policy"},"2026-11-10T09:00:01.000000Z")
print("entry 2 matches vector:", h2 == "28f7852f2bd2e42028cf102c313e3bb90c591d4e9b371c7f1b7170fc9f0c3dd8")

# verifier: walk the chain from stored bodies
def verify(chain):
    prev = genesis(chain); n = 0
    for seq, body, ph, eh in db.execute("SELECT seq, body, prev_hash, entry_hash FROM audit_entries WHERE chain_id=? ORDER BY seq", (chain,)):
        n += 1
        if seq != n or ph != prev: return f"break at {seq}: link"
        obj = json.loads(body)
        if canon(obj).decode() != body: return f"break at {seq}: not canonical"
        if entry_hash(prev, obj) != eh: return f"break at {seq}: hash"
        prev = eh
    return "chain ok"
print(verify('demo-agent'))
expect_fail("UPDATE audit_entries SET kind='REJECTED' WHERE seq=1", label="update audit entry")
expect_fail("DELETE FROM audit_entries WHERE seq=1", label="delete audit entry")
expect_fail("INSERT INTO audit_entries (chain_id,seq,ts,kind,body,prev_hash,entry_hash) VALUES ('demo-agent',2,'x','INTENT','{}',?,?)", ("0"*64,"0"*64), "duplicate seq")

# simulate tampering with triggers bypassed (someone with file access)
db.execute("DROP TRIGGER audit_entries_no_update")
db.execute("UPDATE audit_entries SET body=replace(body,'BLOCK','ALLOW') WHERE seq=1")
print("after tampering:", verify('demo-agent'))
