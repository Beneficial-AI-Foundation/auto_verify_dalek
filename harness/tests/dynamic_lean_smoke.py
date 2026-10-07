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
    args = SimpleNamespace(resume_dynamic=False, max_node_attempts=10, max_node_retries=0,max_refinements=2,
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

    # Scenario 2: the Refiner first proposes a false helper (`False`); its
    # Worker reports invalid_contract; the placeholder is removed under real
    # Lean checks and a second Refiner proposes a true one.
    subprocess.run(['git','checkout','-q','--','A.lean'],cwd=work,check=True)
    subprocess.run(['git','reset','-q','--hard',subprocess.run(['git','rev-list','--max-parents=0','HEAD'],cwd=work,capture_output=True,text=True).stdout.strip()],cwd=work,check=True)
    run2 = run/'run2'; run2.mkdir()
    rc,counts,_ = driver.build_sorry_counts(str(work),120)
    assert rc == 0 and counts == {'A.lean': 1}, counts
    roles=[]
    def fake_model2(prompt, transcript, **kw):
        if kw['allowed_tools']=='Read,Grep,Glob':
            roles.append('refiner')
            name,ty = ('Demo.bad','False') if roles.count('refiner')==1 else ('Demo.helper','True')
            assert ('FALSE' in prompt) == (name=='Demo.helper'), prompt[-600:]
            result = json.dumps({'before':'theorem target','helpers':[{'name':name,'type':ty,'deps':[],'purpose':'proves target'}]})
        else:
            roles.append('worker')
            text=(work/'A.lean').read_text()
            if 'Prove ONLY the body of Demo.bad' in prompt:
                result = json.dumps({'blocker':{'kind':'invalid_contract','reason':'False is not provable','evidence':'goal False'}})
            elif 'Prove ONLY the body of Demo.helper' in prompt:
                (work/'A.lean').write_text(text.replace('theorem _root_.Demo.helper : True := by\n  sorry','theorem _root_.Demo.helper : True := by\n  trivial')); result='complete'
            elif 'Demo.helper : True' in prompt:   # parent after the good split: context lists the helper
                assert 'helper_invalid' in prompt and 'Demo.bad' in prompt
                (work/'A.lean').write_text(text.replace('theorem target : True := by\n  sorry','theorem target : True := by\n  exact helper')); result='complete'
            else:
                result = json.dumps({'blocker':{'kind':'needs_split','reason':'test decomposition','evidence':'target goal True'}})
        event={'type':'result','result':result,'total_cost_usd':0,'num_turns':1}
        Path(transcript).parent.mkdir(parents=True,exist_ok=True)
        Path(transcript).write_text(json.dumps(event)+'\n')
        return 'ok',0,0,event,{}
    published=[]
    with patch.object(driver, 'TRANSCRIPTS', str(run2 / 'transcripts')), \
         patch.object(dag.agentproc,'run_round',side_effect=fake_model2), \
         patch.object(api,'atomic_publish_joint',side_effect=lambda *a: published.append(a)):
        ok = dag.run(args,[dict(mode='fill',fn='Demo.target',path='A.lean')],str(work),str(run2),counts,
            {},'',None,lambda *a:'Prove Demo.target in A.lean',{},[],print,api)
    state=json.loads((run2/'graph.json').read_text())
    assert ok, state['events']
    assert roles==['worker','refiner','worker','refiner','worker','worker'], roles
    assert [c['kind'] for c in state['commits']]==['split','unsplit','split','accept','accept'], state['commits']
    assert 'Demo.bad' not in (work/'A.lean').read_text()
    assert len(published)==1
    print('PASS: real Lean gates; false helper -> unsplit -> Refiner re-asked -> true helper -> parent -> final gate')
