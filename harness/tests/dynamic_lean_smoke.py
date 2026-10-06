"""Offline integration smoke: actual Lean gates with deterministic fake agents.

Run: python harness/tests/dynamic_lean_smoke.py
"""
import os, sys, subprocess, tempfile, json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
repo = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo / 'harness'))
import dynamic_proof as dag
import prove_top_spec as api
import driver
with tempfile.TemporaryDirectory(prefix='dynamic-e2e-') as d:
    run = Path(d)
    work = run / 'work'
    work.mkdir()
    (work/'lean-toolchain').write_bytes((repo/'lean-toolchain').read_bytes())
    (work/'lakefile.toml').write_text('name = "DynamicTest"\nversion = "0.1.0"\ndefaultTargets = ["Curve25519Dalek"]\n[[lean_lib]]\nname = "Curve25519Dalek"\nroots = ["Curve25519Dalek", "A"]\n')
    (work/'Curve25519Dalek.lean').write_text('import A\n')
    (work/'A.lean').write_text('import Lean\nnamespace Demo\ntheorem target : True := by\n  sorry\nend Demo\n')
    (work/'harness/gates').mkdir(parents=True)
    (work/'harness/gates/StmtCanon.lean').write_bytes((repo/'harness/gates/StmtCanon.lean').read_bytes())
    for cmd in [['git','init','-q'],['git','config','user.name','test'],['git','config','user.email','test@example']]:
        subprocess.run(cmd,cwd=work,check=True)
    (work/'.gitignore').write_text('.lake/\nlake-manifest.json\n')
    subprocess.run(['git','add','.'],cwd=work,check=True)
    subprocess.run(['git','commit','-qm','baseline'],cwd=work,check=True)
    rc,counts,_ = driver.build_sorry_counts(str(work),120)
    assert rc == 0, rc
    args = SimpleNamespace(resume_dynamic=False, max_node_attempts=10,max_refinements=2,
        max_proof_nodes=10,max_helpers_per_split=3,build_timeout=120,model='fake',max_turns=2,
        timeout=120,bundle='unused',rounds=1, quiet_turns=True, max_cost_usd=0,
        stall_rounds=2,bloat_threshold_tokens=200000,auto_reset=True,max_auto_resets=1,g2=False)
    sessions=[]
    def fake_model(prompt, transcript, **kw):
        sessions.append(kw['session_id'])
        if kw['allowed_tools']=='Read,Grep,Glob':
            result = json.dumps({'before':'theorem target', 'helpers':[{
                'name':'Demo.helper','type':'True','deps':[],'purpose':'proves target'}]})
        elif len(sessions)==1:
            result = json.dumps({'blocker':{'kind':'needs_split','reason':'test decomposition','evidence':'target goal True'}})
        else:
            text=(work/'A.lean').read_text()
            if len(sessions)==3:
                text=text.replace('theorem _root_.Demo.helper : True := by\n  sorry',
                                  'theorem _root_.Demo.helper : True := by\n  trivial')
            else:
                text=text.replace('theorem target : True := by\n  sorry',
                                  'theorem target : True := by\n  exact helper')
            (work/'A.lean').write_text(text)
            result='complete'
        event={'type':'result','result':result,'total_cost_usd':0,'num_turns':1}
        Path(transcript).parent.mkdir(parents=True,exist_ok=True)
        Path(transcript).write_text(json.dumps(event)+'\n')
        return 'ok',0,0,event,{}
    published=[]
    with patch.object(driver, 'TRANSCRIPTS', str(run / 'transcripts')), \
         patch.object(dag.agentproc,'run_round',side_effect=fake_model), \
         patch.object(api,'atomic_publish_joint',side_effect=lambda *a: published.append(a)):
        ok = dag.run(args,[dict(mode='fill',fn='Demo.target',path='A.lean')],str(work),str(run),counts,
            {},'',None,lambda *a:'Prove Demo.target in A.lean',{},[],print,api)
    assert ok, (run/'graph.json').read_text()
    assert len(set(sessions))==4, sessions
    assert len(published)==1
    print('PASS: real Lean gates; blocker -> fresh Refiner -> helper Worker -> fresh parent Worker -> final gate')
