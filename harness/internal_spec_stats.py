"""Rank kept top specs by number of internal Funs.lean functions they transitively call
(each ~ one internal spec to write). Instance records (rust_trait_impl) filtered out;
FunsExternal functions excluded (bundle keeps their specs)."""
import json, collections, sys
man = json.load(open('dalek-top-spec-only/bundle_manifest.json'))
full = json.load(open('.verilib/probes/lean_Curve25519Dalek_0.1.0.json'))["data"]
def isfun(k):
    n = full.get(k, {})
    return ((n.get("code-path") or "").endswith("/Funs.lean") and n.get("kind") in ("def", "opaque")
            and "rust_trait_impl" not in (n.get("attributes") or []))
spec_of = collections.defaultdict(set)
for k, n in full.items():
    if n.get("kind") == "theorem" and "progress" in (n.get("attributes") or []):
        for dep in n.get("type-dependencies", []):
            if isfun(dep): spec_of[dep].add(k)
top_funs = {"probe:" + f for v in man["kept_spec_files"].values() for f in v}
def callees(f):
    seen, st = set(), [f]
    while st:
        for x in full[st.pop()]["dependencies"]:
            if isfun(x) and x not in seen and x != f:
                seen.add(x); st.append(x)
    return seen
rows = []
for funs in man["kept_spec_files"].values():
    for f in funs:
        cs = callees("probe:" + f)
        internal = sorted(c for c in cs if c not in top_funs)
        rows.append((len(internal), sum(c not in spec_of for c in internal), f, internal))
rows.sort()
short = lambda s: s.replace("probe:", "").replace("curve25519_dalek.", "")
lim = int(sys.argv[1]) if len(sys.argv) > 1 else 10**9
print(f"{'internal':>8} {'never_specd':>11}  function")
for n, ns, f, internal in rows:
    print(f"{n:>8} {ns:>11}  {short(f)}")
    if n <= lim:
        for c in internal: print(f"{'':>21}  - {short(c)}{'' if c in spec_of else '   [no spec in full repo]'}")
