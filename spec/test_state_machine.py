"""Stateful property test of the approval state machine, run against schema.sql.
Time is a fake clock. Every transition uses the guarded UPDATE statements from the spec."""
import sqlite3
from datetime import datetime, timedelta, timezone
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize, precondition

DECISION_WINDOW = timedelta(minutes=30)
USE_WINDOW = timedelta(minutes=10)
T0 = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)

def fmt(d): return d.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
HASHES = ["a" * 64, "b" * 64, "c" * 64]

class Machine(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys = ON")
        with open("schema.sql", encoding="utf-8") as f:
            self.db.executescript(f.read())
        n = fmt(T0)
        self.db.execute("INSERT INTO principals VALUES ('p-admin','admin','alice','active',?)", (n,))
        self.db.execute("INSERT INTO principals VALUES ('p-appr','approver','bob','active',?)", (n,))
        self.db.execute("INSERT INTO roles VALUES ('r1','support','',60,4,5)")
        for a in ("a1", "a2"):
            self.db.execute("""INSERT INTO agents (agent_id,name,role_id,status,secret_hash,secret_created_at,created_by,created_at)
                               VALUES (?,?,?,?,?,?,?,?)""", (a, a, "r1", "active", "0" * 64, n, "p-admin", n))
            self.db.execute("INSERT INTO tasks VALUES (?,?, 'open','p-admin',?,?,NULL)", ("t-" + a, a, n, fmt(T0 + timedelta(days=1))))
        self.now = T0
        self.n = 0
        self.consumed = {}      # approval_id -> times consumed
        self.history = {}       # approval_id -> list of statuses seen

    def status(self, aid):
        return self.db.execute("SELECT status FROM approvals WHERE approval_id=?", (aid,)).fetchone()[0]

    def note(self, aid):
        s = self.status(aid)
        h = self.history.setdefault(aid, [])
        if not h or h[-1] != s: h.append(s)

    def ids(self):
        return [r[0] for r in self.db.execute("SELECT approval_id FROM approvals")]

    @rule(agent=st.sampled_from(["a1", "a2"]), h=st.sampled_from(HASHES))
    def create(self, agent, h):
        self.n += 1
        aid = f"ap{self.n}"
        try:
            self.db.execute("""INSERT INTO approvals (approval_id,agent_id,task_id,call_hash,tool,risk,summary,status,created_at,decision_deadline)
                               VALUES (?,?,?,?,?,?,?,?,?,?)""",
                            (aid, agent, "t-" + agent, h, "send_email", "high", "s", "PENDING", fmt(self.now), fmt(self.now + DECISION_WINDOW)))
            self.note(aid)
        except sqlite3.IntegrityError:
            pass  # an open approval already exists for this agent and call

    @precondition(lambda self: self.ids())
    @rule(data=st.data(), approve=st.booleans())
    def decide(self, data, approve):
        aid = data.draw(st.sampled_from(self.ids()))
        self.db.execute("""UPDATE approvals SET status=?, decided_at=?, decided_by='p-appr', signature=?, use_deadline=?
                           WHERE approval_id=? AND status='PENDING' AND decision_deadline > ?""",
                        ("APPROVED" if approve else "REJECTED", fmt(self.now), "f" * 128, fmt(self.now + USE_WINDOW), aid, fmt(self.now)))
        row = self.db.execute("SELECT decided_at, decision_deadline FROM approvals WHERE approval_id=?", (aid,)).fetchone()
        if row[0] is not None:
            assert row[0] < row[1], "decision recorded after its deadline"
        self.note(aid)

    @precondition(lambda self: self.ids())
    @rule(data=st.data(), variant=st.sampled_from(["exact", "exact", "exact", "wrong_agent", "wrong_hash"]))
    def consume(self, data, variant):
        aid = data.draw(st.sampled_from(self.ids()))
        real_hash, real_agent = self.db.execute("SELECT call_hash, agent_id FROM approvals WHERE approval_id=?", (aid,)).fetchone()
        h = real_hash if variant != "wrong_hash" else next(x for x in HASHES if x != real_hash)
        agent = real_agent if variant != "wrong_agent" else ("a2" if real_agent == "a1" else "a1")
        cur = self.db.execute("""UPDATE approvals SET status='CONSUMED', consumed_at=?
                                 WHERE approval_id=? AND status='APPROVED' AND call_hash=? AND agent_id=? AND use_deadline > ?""",
                              (fmt(self.now), aid, h, agent, fmt(self.now)))
        if cur.rowcount == 1:
            self.consumed[aid] = self.consumed.get(aid, 0) + 1
            row = self.db.execute("SELECT call_hash, agent_id, use_deadline FROM approvals WHERE approval_id=?", (aid,)).fetchone()
            assert variant == "exact", "consumed by the wrong call or agent"
            assert fmt(self.now) < row[2], "consumed after its use deadline"
        self.note(aid)

    def ids_in(self, status):
        return [r[0] for r in self.db.execute("SELECT approval_id FROM approvals WHERE status=?", (status,))]

    @precondition(lambda self: self.ids_in("PENDING"))
    @rule(data=st.data(), approve=st.booleans())
    def decide_pending(self, data, approve):
        """Targeted: decide an approval that is currently pending (the deadline guard still applies)."""
        aid = data.draw(st.sampled_from(self.ids_in("PENDING")))
        self.db.execute("""UPDATE approvals SET status=?, decided_at=?, decided_by='p-appr', signature=?, use_deadline=?
                           WHERE approval_id=? AND status='PENDING' AND decision_deadline > ?""",
                        ("APPROVED" if approve else "REJECTED", fmt(self.now), "f" * 128, fmt(self.now + USE_WINDOW), aid, fmt(self.now)))
        row = self.db.execute("SELECT decided_at, decision_deadline FROM approvals WHERE approval_id=?", (aid,)).fetchone()
        if row[0] is not None:
            assert row[0] < row[1], "decision recorded after its deadline"
        self.note(aid)

    @precondition(lambda self: self.ids_in("APPROVED"))
    @rule(data=st.data(), variant=st.sampled_from(["exact", "wrong_agent", "wrong_hash"]))
    def consume_approved(self, data, variant):
        """Targeted: try to consume an approval that is currently approved, exactly or with a wrong agent or hash."""
        aid = data.draw(st.sampled_from(self.ids_in("APPROVED")))
        real_hash, real_agent = self.db.execute("SELECT call_hash, agent_id FROM approvals WHERE approval_id=?", (aid,)).fetchone()
        h = real_hash if variant != "wrong_hash" else next(x for x in HASHES if x != real_hash)
        agent = real_agent if variant != "wrong_agent" else ("a2" if real_agent == "a1" else "a1")
        cur = self.db.execute("""UPDATE approvals SET status='CONSUMED', consumed_at=?
                                 WHERE approval_id=? AND status='APPROVED' AND call_hash=? AND agent_id=? AND use_deadline > ?""",
                              (fmt(self.now), aid, h, agent, fmt(self.now)))
        if cur.rowcount == 1:
            self.consumed[aid] = self.consumed.get(aid, 0) + 1
            row = self.db.execute("SELECT use_deadline FROM approvals WHERE approval_id=?", (aid,)).fetchone()
            assert variant == "exact", "consumed by the wrong call or agent"
            assert fmt(self.now) < row[0], "consumed after its use deadline"
        self.note(aid)

    @precondition(lambda self: self.ids())
    @rule(data=st.data())
    def cancel(self, data):
        aid = data.draw(st.sampled_from(self.ids()))
        self.db.execute("""UPDATE approvals SET status='CANCELLED', cancelled_reason='admin'
                           WHERE approval_id=? AND status IN ('PENDING','APPROVED')""", (aid,))
        self.note(aid)

    @rule(minutes=st.integers(min_value=1, max_value=45))
    def advance_clock(self, minutes):
        # The clock moves WITHOUT sweeping, so the deadline guards inside each UPDATE are what is tested.
        self.now += timedelta(minutes=minutes)

    @rule()
    def sweep(self):
        t = fmt(self.now)
        self.db.execute("UPDATE approvals SET status='EXPIRED' WHERE status='PENDING' AND decision_deadline <= ?", (t,))
        self.db.execute("UPDATE approvals SET status='EXPIRED' WHERE status='APPROVED' AND use_deadline <= ?", (t,))
        for aid in self.ids(): self.note(aid)

    LEGAL = {("PENDING","APPROVED"),("PENDING","REJECTED"),("PENDING","EXPIRED"),("PENDING","CANCELLED"),
             ("APPROVED","CONSUMED"),("APPROVED","EXPIRED"),("APPROVED","CANCELLED")}

    @invariant()
    def only_legal_transitions(self):
        for aid, h in self.history.items():
            assert h[0] == "PENDING"
            for a, b in zip(h, h[1:]):
                assert (a, b) in self.LEGAL, f"illegal transition {a} -> {b} for {aid}"

    @invariant()
    def at_most_one_consumption(self):
        assert all(v <= 1 for v in self.consumed.values())

    @invariant()
    def one_open_per_agent_and_call(self):
        rows = self.db.execute("""SELECT agent_id, call_hash, count(*) FROM approvals
                                  WHERE status IN ('PENDING','APPROVED') GROUP BY agent_id, call_hash HAVING count(*) > 1""").fetchall()
        assert not rows

    @invariant()
    def terminal_states_have_evidence(self):
        for aid, st_, c, d in self.db.execute("SELECT approval_id,status,consumed_at,decided_by FROM approvals"):
            if st_ == "CONSUMED": assert c is not None and d is not None

TestApprovals = Machine.TestCase
TestApprovals.settings = settings(max_examples=300, stateful_step_count=40, deadline=None)

if __name__ == "__main__":
    import unittest
    unittest.main(argv=["x"], verbosity=1)
