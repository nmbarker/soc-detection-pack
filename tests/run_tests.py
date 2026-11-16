#!/usr/bin/env python3
"""Convert each rule to SQLite SQL, run it over tests/samples.json, assert match/nomatch.
Also converts to Splunk and Elasticsearch Lucene to prove multi-backend conversion."""
import json, os, sqlite3, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(ROOT, ".tools", "sigma")
samples = json.load(open(os.path.join(ROOT, "tests", "samples.json")))

def convert(rule, backend, pipeline=None):
    cmd = ["sh", SIGMA, "convert", "-t", backend, "--without-pipeline" if not pipeline else "-p", *( [pipeline] if pipeline else [] ), rule]
    cmd = [c for c in cmd if c]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode: raise SystemExit(f"convert failed {rule} {backend}: {r.stderr}")
    return r.stdout.strip().splitlines()[-1]

fails = 0
for name, s in sorted(samples.items()):
    rule = os.path.join(ROOT, "rules", name + ".yml")
    sql = convert(rule, "sqlite", None)
    rows = [(e, 1) for e in s["match"]] + [(e, 0) for e in s["nomatch"]]
    cols = sorted({k for e, _ in rows for k in e} | {"OriginalFileName", "ParentImage", "Image", "CommandLine"} - {"id"}) if "eventName" not in rows[0][0] else sorted({k for e, _ in rows for k in e})
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logs (id INTEGER, %s)" % ",".join(cols))
    for i, (e, _) in enumerate(rows):
        db.execute("INSERT INTO logs (id,%s) VALUES (?,%s)" % (",".join(e), ",".join("?" * len(e))), (i, *e.values()))
    hit = {r[0] for r in db.execute(sql.replace("SELECT *", "SELECT id", 1))}
    want = {i for i, (_, m) in enumerate(rows) if m}
    ok = hit == want
    fails += not ok
    print(("PASS" if ok else "FAIL"), name, f"hits={sorted(hit)} expected={sorted(want)}")
    for be, pl in (("splunk", "splunk_windows"), ("lucene", "ecs_windows")):
        if "win_" in name:
            convert(rule, be, pl)
        else:
            convert(rule, be, None)
sys.exit(1 if fails else 0)
