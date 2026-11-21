"""Reference policy loader and evaluator (version 1).

This is a specification you can run, not the production engine. It pins down precedence,
defaults, and failure behavior so the real engine can be tested against the same cases.
"""
import posixpath
from urllib.parse import urlparse

EFFECTS = ("allow", "ask", "block")
PRECEDENCE = {"block": 3, "ask": 2, "allow": 1}
OPS = {"equals", "not_equals", "in", "not_in", "path_within", "path_not_within",
       "domain_in", "domain_not_in", "lt", "lte", "gt", "gte"}
RISK_ORDER = ["low", "medium", "high", "critical"]
LABELS = {"PUBLIC", "CONFIDENTIAL", "SECRET", "UNTRUSTED"}


class EvalError(Exception):
    """A condition could not be evaluated (wrong type, bad value, unknown name)."""


class PolicyError(Exception):
    """The policy document is invalid and must not be activated."""


# ---------------------------------------------------------------- validation
def validate(policy, manifests):
    """Reject a policy document that is ambiguous or refers to things that do not exist."""
    if policy.get("schema_version") != 1:
        raise PolicyError("unsupported schema_version")
    allowed_top = {"schema_version", "name", "lists", "rules"}
    if set(policy) - allowed_top:
        raise PolicyError(f"unknown top-level keys: {set(policy) - allowed_top}")
    lists = policy.get("lists", {})
    seen = set()
    for r in policy["rules"]:
        rid = r.get("rule_id")
        if not rid or rid in seen:
            raise PolicyError(f"missing or duplicate rule_id: {rid}")
        seen.add(rid)
        if r.get("effect") not in EFFECTS:
            raise PolicyError(f"{rid}: bad effect")
        extra = set(r) - {"rule_id", "effect", "description", "applies_to", "when"}
        if extra:
            raise PolicyError(f"{rid}: unknown keys {extra}")
        roles, tools = r["applies_to"].get("roles"), r["applies_to"].get("tools")
        if not roles or not tools:
            raise PolicyError(f"{rid}: applies_to needs roles and tools")
        wildcard_tools = "*" in tools
        for t in tools:
            if t != "*" and t not in manifests:
                raise PolicyError(f"{rid}: unknown tool {t}")
        for leaf in _leaves(r.get("when", {"all": []})):
            if "arg" in leaf or "derived" in leaf:
                if wildcard_tools:
                    raise PolicyError(f"{rid}: arg/derived conditions need explicit tools, not '*'")
                for t in tools:
                    m = manifests[t]
                    if "arg" in leaf:
                        props = m["argument_schema"].get("properties", {})
                        top = leaf["arg"].split(".")[0]
                        if top not in props:
                            raise PolicyError(f"{rid}: {t} has no argument {leaf['arg']}")
                        if props[top].get("type") == "array" and "quantifier" not in leaf:
                            raise PolicyError(f"{rid}: array argument {leaf['arg']} needs a quantifier")
                    else:
                        if leaf["derived"] not in m.get("derived_facts", []):
                            raise PolicyError(f"{rid}: {t} does not declare derived fact {leaf['derived']}")
                if leaf.get("op") not in OPS:
                    raise PolicyError(f"{rid}: unknown op {leaf.get('op')}")
                if "list" in leaf and leaf["list"] not in lists:
                    raise PolicyError(f"{rid}: unknown list {leaf['list']}")
                if "list" not in leaf and "value" not in leaf:
                    raise PolicyError(f"{rid}: condition needs value or list")
            elif "task_labels" in leaf:
                for k, v in leaf["task_labels"].items():
                    if k not in ("any_of", "all_of", "none_of") or not set(v) <= LABELS:
                        raise PolicyError(f"{rid}: bad task_labels condition")
            elif "manifest" in leaf or "tool_risk" in leaf:
                pass
            else:
                raise PolicyError(f"{rid}: unknown condition {leaf}")


def _leaves(node):
    if "all" in node:
        for n in node["all"]: yield from _leaves(n)
    elif "any" in node:
        for n in node["any"]: yield from _leaves(n)
    elif "not" in node:
        yield from _leaves(node["not"])
    else:
        yield node


# ---------------------------------------------------------------- evaluation
def _resolve(call_args, path):
    cur = call_args
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return _ABSENT
        cur = cur[key]
    return cur

_ABSENT = object()


def _domain(value):
    if not isinstance(value, str):
        raise EvalError("domain operand must be a string")
    host = value.rsplit("@", 1)[1] if "@" in value else (urlparse(value).hostname or value)
    return host.strip().lower()


def _domain_match(host, entry):
    entry = entry.lower()
    return host == entry or host.endswith("." + entry)


def _norm_path(value):
    if not isinstance(value, str) or not value.startswith("/"):
        raise EvalError("path must be an absolute string")
    return posixpath.normpath(value)


def _within(path, base):
    base = posixpath.normpath(base)
    return path == base or path.startswith(base.rstrip("/") + "/")


def _apply(op, value, operand):
    """Apply one operator to one scalar value. operand is a scalar or, for in/not_in, a list."""
    if op == "equals":     return value == operand
    if op == "not_equals": return value != operand
    if op in ("in", "not_in"):
        if not isinstance(operand, list): operand = [operand]
        return (value in operand) if op == "in" else (value not in operand)
    if op in ("path_within", "path_not_within"):
        p = _norm_path(value)
        ops = operand if isinstance(operand, list) else [operand]
        inside = any(_within(p, b) for b in ops)
        return inside if op == "path_within" else not inside
    if op in ("domain_in", "domain_not_in"):
        h = _domain(value)
        ops = operand if isinstance(operand, list) else [operand]
        inside = any(_domain_match(h, e) for e in ops)
        return inside if op == "domain_in" else not inside
    if op in ("lt", "lte", "gt", "gte"):
        if isinstance(value, bool) or not isinstance(value, int) or isinstance(operand, bool) or not isinstance(operand, int):
            raise EvalError("numeric comparison needs integers")
        return {"lt": value < operand, "lte": value <= operand, "gt": value > operand, "gte": value >= operand}[op]
    raise EvalError(f"unknown op {op}")


def _leaf(leaf, ctx):
    if "task_labels" in leaf:
        labels = ctx["labels"]
        res = True
        for k, v in leaf["task_labels"].items():
            if k == "any_of":  res = res and bool(labels & set(v))
            if k == "all_of":  res = res and set(v) <= labels
            if k == "none_of": res = res and not (labels & set(v))
        return res
    if "manifest" in leaf:
        if leaf["manifest"] != "external_sink":
            raise EvalError("unknown manifest field")
        return ctx["manifest"].get("external_sink", False) == leaf["equals"]
    if "tool_risk" in leaf:
        at_least = leaf["tool_risk"]["at_least"]
        return RISK_ORDER.index(ctx["manifest"]["risk"]) >= RISK_ORDER.index(at_least)
    # arg or derived condition
    if "arg" in leaf:
        value = _resolve(ctx["arguments"], leaf["arg"])
    else:
        value = ctx["derived"].get(leaf["derived"], _ABSENT)
    if value is _ABSENT:
        return bool(leaf.get("if_absent", False))
    operand = ctx["lists"][leaf["list"]] if "list" in leaf else leaf["value"]
    if isinstance(value, list):
        q = leaf.get("quantifier")
        if q not in ("any", "all"):
            raise EvalError("list value needs a quantifier")
        results = [_apply(leaf["op"], v, operand) for v in value]
        return any(results) if q == "any" else all(results)   # all([]) is True, any([]) is False
    return _apply(leaf["op"], value, operand)


def _when(node, ctx):
    if "all" in node: return all(_when(n, ctx) for n in node["all"])
    if "any" in node: return any(_when(n, ctx) for n in node["any"])
    if "not" in node: return not _when(node["not"], ctx)
    return _leaf(node, ctx)


def evaluate(policy, manifests, *, role, tool, arguments, derived=None, task_labels=()):
    """Return {decision, rule_ids, errors}. Default deny. Most restrictive effect wins.
    On any evaluation error: allow rules do not fire; block and ask rules fire."""
    try:
        manifest = manifests[tool]
        ctx = {"arguments": arguments, "derived": derived or {}, "labels": set(task_labels),
               "manifest": manifest, "lists": policy.get("lists", {})}
        fired, errors = [], []
        for r in policy["rules"]:
            a = r["applies_to"]
            if ("*" not in a["roles"] and role not in a["roles"]) or ("*" not in a["tools"] and tool not in a["tools"]):
                continue
            try:
                hit = _when(r.get("when", {"all": []}), ctx)
            except EvalError as e:
                errors.append(f"{r['rule_id']}: {e}")
                hit = r["effect"] in ("block", "ask")      # fail closed
            if hit:
                fired.append(r)
        if not fired:
            return {"decision": "BLOCK", "rule_ids": ["DEFAULT-DENY"], "errors": errors}
        top = max(PRECEDENCE[r["effect"]] for r in fired)
        ordered = sorted(fired, key=lambda r: -PRECEDENCE[r["effect"]])   # stable: document order inside an effect
        return {"decision": {3: "BLOCK", 2: "ASK", 1: "ALLOW"}[top],
                "rule_ids": [r["rule_id"] for r in ordered], "errors": errors}
    except Exception as e:                                                # engine failure: fail closed
        return {"decision": "BLOCK", "rule_ids": ["ENGINE-ERROR"], "errors": [repr(e)]}
