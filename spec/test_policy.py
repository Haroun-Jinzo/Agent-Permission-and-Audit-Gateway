import yaml
from policy_eval import validate, evaluate, PolicyError

with open("example-policy.yaml", encoding="utf-8") as f: policy = yaml.safe_load(f)
with open("example-manifests.yaml", encoding="utf-8") as f: manifests = {d["tool"]: d for d in yaml.safe_load_all(f)}
validate(policy, manifests)

def ev(**kw): return evaluate(policy, manifests, **kw)
def send(to, labels=(), role="support"):
    return ev(role=role, tool="send_email", arguments={"to": to, "subject": "s", "body": "b"}, task_labels=labels)

CASES = [
 # (name, result, expected decision, expected decisive rule)
 ("internal recipient, clean task",            send(["a@company.example"]),                                   "ALLOW", "R-EMAIL-INTERNAL"),
 ("internal recipient, confidential task",     send(["a@company.example"], {"CONFIDENTIAL"}),                 "ALLOW", "R-EMAIL-INTERNAL"),
 ("subdomain of an internal domain",           send(["a@mail.company.example"]),                              "ALLOW", "R-EMAIL-INTERNAL"),
 ("look-alike domain is external",             send(["a@evilcompany.example"]),                               "ASK",   "R-EMAIL-EXTERNAL-ASK"),
 ("external recipient, clean task",            send(["p@vendor.example"], {"UNTRUSTED"}),                     "ASK",   "R-EMAIL-EXTERNAL-ASK"),
 ("mixed recipients, clean task",              send(["a@company.example", "x@evil.example"]),                 "ASK",   "R-EMAIL-EXTERNAL-ASK"),
 ("external recipient, confidential task",     send(["x@evil.example"], {"UNTRUSTED", "CONFIDENTIAL"}),       "BLOCK", "R-EXFIL-1"),
 ("secret task blocks even internal email",    send(["a@company.example"], {"SECRET"}),                       "BLOCK", "R-SECRET-SINK-BLOCK"),
 ("unknown role gets default deny",            send(["a@company.example"], role="intern"),                    "BLOCK", "DEFAULT-DENY"),
 ("read inside the shared folder",             ev(role="support", tool="read_file", arguments={"path": "/data/shared/a.txt"}), "ALLOW", "R-FILE-READ"),
 ("path traversal is normalized and denied",   ev(role="support", tool="read_file", arguments={"path": "/data/shared/../secrets/k.txt"}), "BLOCK", "DEFAULT-DENY"),
 ("sibling folder with a similar prefix",      ev(role="support", tool="read_file", arguments={"path": "/data/shared-old/a.txt"}), "BLOCK", "DEFAULT-DENY"),
 ("delete needs approval",                     ev(role="support", tool="delete_file", arguments={"path": "/data/shared/a.txt"}), "ASK", "R-DELETE-ASK"),
 ("inbox read",                                ev(role="research", tool="read_inbox", arguments={"limit": 10}), "ALLOW", "R-INBOX-READ"),
 ("analyst SELECT on approved table",          ev(role="analyst", tool="db_query", arguments={"sql": "select 1", "max_rows": 10},
                                                  derived={"statement_type": "SELECT", "tables": ["sales_summary"]}), "ALLOW", "R-DB-SELECT"),
 ("analyst SELECT on a forbidden table",       ev(role="analyst", tool="db_query", arguments={"sql": "x", "max_rows": 10},
                                                  derived={"statement_type": "SELECT", "tables": ["sales_summary", "hr_salaries"]}), "BLOCK", "DEFAULT-DENY"),
 ("analyst UPDATE is blocked explicitly",      ev(role="analyst", tool="db_query", arguments={"sql": "x", "max_rows": 10},
                                                  derived={"statement_type": "UPDATE", "tables": ["sales_summary"]}), "BLOCK", "R-DB-WRITE-BLOCK"),
]
failed = 0
for name, res, want_dec, want_rule in CASES:
    ok = res["decision"] == want_dec and res["rule_ids"][0] == want_rule
    failed += not ok
    print(("ok   " if ok else "FAIL ") + f"{name:46s} -> {res['decision']:5s} {res['rule_ids']}")

# fail-closed behavior on evaluation errors
bad = ev(role="support", tool="send_email", arguments={"to": 5, "subject": "s", "body": "b"}, task_labels={"CONFIDENTIAL"})
print("ok   " if bad["decision"] == "BLOCK" and bad["errors"] else "FAIL ", "wrong argument type fails closed:", bad["decision"], bad["errors"][:1])
failed += not (bad["decision"] == "BLOCK" and bad["errors"])
none_ = evaluate(policy, manifests, role="support", tool="no_such_tool", arguments={})
print("ok   " if none_["rule_ids"] == ["ENGINE-ERROR"] else "FAIL ", "unknown tool fails closed:", none_["decision"], none_["rule_ids"])
failed += none_["rule_ids"] != ["ENGINE-ERROR"]

# an erroring ALLOW rule must not grant access
p2 = {**policy, "rules": [r for r in policy["rules"] if r["rule_id"] in ("R-FILE-READ",)]}
r = evaluate(p2, manifests, role="support", tool="read_file", arguments={"path": 5})
print("ok   " if r["decision"] == "BLOCK" and r["rule_ids"] == ["DEFAULT-DENY"] else "FAIL ", "erroring allow rule does not fire:", r["decision"], r["rule_ids"])
failed += not (r["decision"] == "BLOCK" and r["rule_ids"] == ["DEFAULT-DENY"])

# validation catches typos and ambiguity
def rejects(mutate, label):
    global failed
    import copy
    p = copy.deepcopy(policy); mutate(p)
    try: validate(p, manifests); print("FAIL ", label, "was accepted"); failed += 1
    except PolicyError as e: print("ok   ", label, "-> rejected:", str(e)[:70])
rejects(lambda p: p["rules"].append(dict(p["rules"][0])), "duplicate rule_id")
rejects(lambda p: p["rules"][1]["when"]["all"][0].update(arg="paht"), "typo in an argument name")
rejects(lambda p: p["rules"][2]["when"]["all"][0].pop("quantifier"), "array argument without a quantifier")
rejects(lambda p: p["rules"][1]["when"]["all"][0].update(list="no_such_list"), "unknown list")
rejects(lambda p: p["rules"][5]["when"]["all"].append({"arg": "to", "op": "equals", "value": "x"}), "arg condition under tools '*'")
rejects(lambda p: p["rules"][0].update(effect="permit"), "unknown effect")
print("FAILED:", failed)
raise SystemExit(1 if failed else 0)
