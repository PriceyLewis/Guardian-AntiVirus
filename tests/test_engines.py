import hashlib
import io
import os
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app

RULE='rule Guardian_Test_Marker { strings: $a = "GUARDIAN-YARA-TEST-MARKER" condition: $a }\n'
MARKED=b'a document containing GUARDIAN-YARA-TEST-MARKER somewhere'


@pytest.fixture
def threats(isolated,monkeypatch):
    """An empty threat-list folder; returns helpers to add a hash list and a rule file."""
    import core.paths as paths
    folder=isolated/'threat-lists';monkeypatch.setattr(paths,'THREATS',folder)
    (folder/'hashes').mkdir(parents=True);(folder/'yara').mkdir()
    def hashes(*contents,name='mine.txt'):
        (folder/'hashes'/name).write_text('# list\n'+'\n'.join(hashlib.sha256(c).hexdigest() for c in contents)+'\n')
    def rule(text=RULE,name='mine.yar'):
        (folder/'yara'/name).write_text(text)
    return SimpleNamespace(folder=folder,hashes=hashes,rule=rule)

def clean_engine(seen=None):
    def scan_files(paths,started=None):
        for path in paths:
            if seen is not None:seen.append(path)
            yield path,{'status':'clean','virus':None}
    engine=SimpleNamespace(scan_files=scan_files,scan_file=lambda path:{'status':'clean','virus':None})
    engine.engine_key=lambda:'ClamAV 1/1|test'
    return engine

def run_worker(monkeypatch,paths,engine=None,**options):
    import core.scan_worker as worker_module
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:engine or clean_engine())
    worker=worker_module.ScanWorker(paths,**options);summary={};results={}
    worker.summary.connect(summary.update);worker.result.connect(lambda path,status,virus:results.update({Path(path).name:(status,virus)}))
    worker.run()
    return summary,results

def test_hash_list_parses_formats_and_finds_exact_matches(threats):
    from core.engines import HashList
    known=[b'one',b'two',b'three']
    digests=[hashlib.sha256(c).hexdigest() for c in known]
    (threats.folder/'hashes'/'a.txt').write_text(f'# comment\n{digests[0].upper()}\n"{digests[1]}",2026-01-01,exe\nnot a hash\n{"z"*64}\n\n')
    (threats.folder/'hashes'/'b.txt').write_text(digests[2]+'\r\n'+digests[0]+'\n')
    (threats.folder/'hashes'/'ignored.csv').write_text(hashlib.sha256(b'other').hexdigest()+'\n')
    listing=HashList()
    assert listing.count==3
    assert all(hashlib.sha256(c).digest() in listing for c in known)
    assert hashlib.sha256(b'other').digest() not in listing and b'\0'*32 not in listing and b'\xff'*32 not in listing
    # The compiled store is reused until a list changes.
    store=threats.folder/'hashes.bin';built=store.stat().st_mtime_ns
    assert HashList().count==3 and store.stat().st_mtime_ns==built
    time.sleep(0.01);(threats.folder/'hashes'/'c.txt').write_text(hashlib.sha256(b'other').hexdigest()+'\n')
    assert HashList().count==4 and hashlib.sha256(b'other').digest() in HashList()

def test_empty_threat_folder_changes_nothing(threats,monkeypatch):
    from core.engines import SecondOpinion
    file=threats.folder.parent/'sample';file.write_bytes(MARKED)
    opinion=SecondOpinion()
    assert not opinion.active() and opinion.check(file) is None
    stream=[(file,{'status':'clean','virus':None})]
    assert list(opinion.review(iter(stream)))==stream

def test_hash_match_is_quarantined_by_a_scan(threats,monkeypatch):
    from database.database import GuardianDatabase
    folder=threats.folder.parent/'files';folder.mkdir()
    (folder/'known').write_bytes(b'listed malware');(folder/'fine').write_bytes(b'ordinary')
    threats.hashes(b'listed malware')
    summary,results=run_worker(monkeypatch,[folder])
    assert results=={'known':('found','Guardian.KnownMalware.SHA256'),'fine':('clean','')}
    assert summary['found']==1 and summary['quarantined']==1 and summary['flagged']==0 and not (folder/'known').exists()
    assert summary['detections']==[hashlib.sha256(b'listed malware').hexdigest()]
    db=GuardianDatabase();assert db.get_quarantined_files()[0][4]=='Guardian.KnownMalware.SHA256';db.close()

def test_yara_match_is_reported_and_left_in_place_unless_asked(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import config
    folder=threats.folder.parent/'files';folder.mkdir()
    (folder/'marked').write_bytes(MARKED);(folder/'fine').write_bytes(b'ordinary')
    threats.rule()
    summary,results=run_worker(monkeypatch,[folder])
    assert results['marked']==('suspicious','YARA.Guardian_Test_Marker') and results['fine']==('clean','')
    assert summary['found']==0 and summary['quarantined']==0 and summary['flagged']==1 and (folder/'marked').exists()
    assert summary['detections']==[hashlib.sha256(MARKED).hexdigest()]
    # Never remembered as clean: it is reported again next time.
    seen=[];summary,_=run_worker(monkeypatch,[folder],clean_engine(seen))
    assert [p.name for p in seen]==['marked'] and summary['unchanged']==1 and summary['flagged']==1
    config.save_config(dict(config.load_config(),yara_quarantine=True))
    summary,results=run_worker(monkeypatch,[folder])
    assert results['marked'][0]=='found' and summary['quarantined']==1 and summary['flagged']==0 and not (folder/'marked').exists()

def test_yara_skips_rule_files_that_do_not_compile(threats):
    pytest.importorskip('yara_x')
    from core.engines import YaraRules
    threats.rule();threats.rule('rule broken { condition: no_such_identifier }\n',name='broken.yar')
    threats.rule('rule Guardian_Test_Marker { strings: $a = "SECOND-MARKER" condition: $a }\n',name='same-name.yara')
    rules=YaraRules()
    assert len(rules.errors)==1 and rules.errors[0].startswith('broken.yar')
    assert rules.match(data=MARKED)=='YARA.Guardian_Test_Marker' and rules.match(data=b'has SECOND-MARKER')=='YARA.Guardian_Test_Marker'
    assert rules.match(data=MARKED+b' and SECOND-MARKER')=='YARA.Guardian_Test_Marker (+1 more)' and rules.match(data=b'nothing') is None
    # Compiled rules are cached, and rebuilt when a rule file changes.
    cache=threats.folder/'rules.compiled';built=cache.stat().st_mtime_ns
    assert YaraRules().match(data=MARKED) and cache.stat().st_mtime_ns==built
    time.sleep(0.01);threats.rule('rule Third { strings: $a = "THIRD-MARKER" condition: $a }\n',name='third.yar')
    assert YaraRules().match(data=b'THIRD-MARKER')=='YARA.Third'

def test_large_files_are_hashed_and_matched_from_disk(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import core.engines as engines
    monkeypatch.setattr(engines,'IN_MEMORY_LIMIT',16)
    listed=threats.folder.parent/'listed';listed.write_bytes(b'x'*5000)
    marked=threats.folder.parent/'marked';marked.write_bytes(b'y'*5000+MARKED)
    threats.hashes(b'x'*5000);threats.rule()
    opinion=engines.SecondOpinion()
    assert opinion.check(listed)['engine']=='hash' and opinion.check(marked)['virus']=='YARA.Guardian_Test_Marker'
    monkeypatch.setattr(engines,'YARA_SIZE_LIMIT',100)
    assert engines.SecondOpinion().check(marked) is None
    assert opinion.check(threats.folder.parent/'missing') is None

def test_switching_engines_off_and_changed_lists_invalidate_remembered_results(threats,monkeypatch):
    import config
    folder=threats.folder.parent/'files';folder.mkdir();(folder/'known').write_bytes(b'listed malware')
    seen=[];engine=clean_engine(seen)
    run_worker(monkeypatch,[folder],engine,quarantine=False);run_worker(monkeypatch,[folder],engine,quarantine=False)
    assert len(seen)==1
    # A newly downloaded list must be applied to files already remembered as clean.
    threats.hashes(b'listed malware')
    summary,_=run_worker(monkeypatch,[folder],engine,quarantine=False)
    assert len(seen)==2 and summary['found']==1 and summary['unchanged']==0
    config.save_config(dict(config.load_config(),hash_lookup=False))
    summary,_=run_worker(monkeypatch,[folder],engine,quarantine=False)
    assert len(seen)==3 and summary['found']==0

def test_review_keeps_order_passes_other_results_through_and_closes_its_source(threats):
    from core.engines import SecondOpinion
    threats.hashes(b'bad')
    files=[]
    for index in range(30):
        file=threats.folder.parent/f'f{index:02d}';file.write_bytes(b'bad' if index%7==0 else b'ok %d'%index);files.append(file)
    closed=[]
    def source():
        try:
            for index,file in enumerate(files):
                yield file,({'status':'error','virus':'denied'} if index==3 else {'status':'found','virus':'Clam.Sig'} if index==7 else {'status':'clean','virus':None})
        finally:
            closed.append(True)
    results=list(SecondOpinion().review(source()))
    assert [path for path,_ in results]==files
    assert results[3][1]=={'status':'error','virus':'denied'} and results[7][1]['virus']=='Clam.Sig'
    assert [index for index,(_,r) in enumerate(results) if r.get('engine')=='hash']==[0,14,21,28]
    stream=SecondOpinion().review(source());next(stream);stream.close()
    assert closed==[True,True]

def test_large_scans_use_worker_processes(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import core.engines as engines
    monkeypatch.setattr(engines,'PROCESS_THRESHOLD',1);monkeypatch.setattr(engines,'PROCESSES',2)
    threats.hashes(b'bad');threats.rule()
    files=[]
    for index,content in enumerate((b'ok',b'bad',MARKED,b'fine')):
        file=threats.folder.parent/f'f{index}';file.write_bytes(content);files.append(file)
    results=list(engines.SecondOpinion().review(((file,{'status':'clean','virus':None}) for file in files),expected=len(files)))
    assert [r.get('engine') for _,r in results]==[None,'hash','yara',None]

def test_scan_continues_when_worker_processes_cannot_start(threats,monkeypatch):
    import core.engines as engines
    monkeypatch.setattr(engines,'PROCESS_THRESHOLD',1);monkeypatch.setattr(engines,'PROCESSES',2)
    # Called with the wrong arguments in each child, so every worker dies at start-up.
    monkeypatch.setattr(engines,'_start_process',os._exit)
    threats.hashes(b'bad')
    files=[]
    for index in range(40):
        file=threats.folder.parent/f'f{index:02d}';file.write_bytes(b'bad' if index in (5,33) else b'ok %d'%index);files.append(file)
    results=list(engines.SecondOpinion().review(((file,{'status':'clean','virus':None}) for file in files),expected=len(files)))
    assert [path for path,_ in results]==files
    assert [index for index,(_,r) in enumerate(results) if r.get('engine')=='hash']==[5,33]

def test_real_time_monitoring_gets_a_second_opinion(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import config
    import core.watcher as watcher_module
    config.save_config(dict(config.load_config(),notifications=True))
    monkeypatch.setattr(watcher_module,'GuardianScanner',lambda:clean_engine())
    notes=[];monkeypatch.setattr(watcher_module.GuardianNotifier,'notify',lambda title,message:notes.append(message))
    threats.hashes(b'listed malware');threats.rule()
    folder=threats.folder.parent/'incoming';folder.mkdir()
    known=folder/'known.exe';known.write_bytes(b'listed malware');marked=folder/'marked.doc';marked.write_bytes(MARKED)
    watcher=watcher_module.GuardianWatcher()
    watcher.scan(known);watcher.scan(marked)
    assert not known.exists() and marked.exists()
    assert notes[0]=='Threat quarantined: known.exe' and notes[1].startswith('Suspicious file: marked.doc matches YARA.Guardian_Test_Marker')
    from database.database import GuardianDatabase
    db=GuardianDatabase();rows={Path(r[1]).name:(r[2],r[3]) for r in db.recent_scans(5)}
    assert rows=={'known.exe':('found','Guardian.KnownMalware.SHA256'),'marked.doc':('suspicious','YARA.Guardian_Test_Marker')}
    assert db.detection_hash(str(marked))==hashlib.sha256(MARKED).hexdigest();db.close()

def test_engines_notice_new_lists_and_settings(threats,monkeypatch):
    import config
    import core.engines as engines
    opinion=engines.SecondOpinion()
    assert not opinion.expired()
    monkeypatch.setattr(engines,'FRESH_SECONDS',0)
    assert not opinion.expired()
    threats.hashes(b'new');assert opinion.expired()
    opinion=engines.SecondOpinion();assert not opinion.expired()
    config.save_config(dict(config.load_config(),hash_lookup=False));assert opinion.expired()

def test_threat_list_update_downloads_merges_and_reports_failures(threats):
    import urllib.error
    from core import threatlists
    from core.engines import HashList
    first=[hashlib.sha256(b'a').hexdigest(),hashlib.sha256(b'b').hexdigest()]
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('full_sha256.txt','# MalwareBazaar\n'+'\n'.join(first)+'\n')
    rules=io.BytesIO()
    with zipfile.ZipFile(rules,'w') as bundle:
        bundle.writestr('packages/core/yara-rules-core.yar',RULE+'rule Another { condition: true }\n');bundle.writestr('../../evil.sh','rm -rf ~')
    served={threatlists.BAZAAR_FULL:archive.getvalue(),threatlists.FORGE_CORE:rules.getvalue(),
            threatlists.BAZAAR_RECENT:(hashlib.sha256(b'c').hexdigest()+'\n'+first[0]+'\n').encode()}
    asked=[]
    def fetch(url):
        asked.append(url);return served[url]
    outcome=threatlists.update(fetch)
    assert outcome==[('MalwareBazaar hash list',True,'2 fingerprints (2 new)'),('YARA Forge core rules',True,'2 rules')]
    assert asked==[threatlists.BAZAAR_FULL,threatlists.FORGE_CORE]
    assert sorted(p.name for p in threats.folder.rglob('*') if p.is_file())==['.last-update','malwarebazaar.txt','yara-forge-core.yar'] and not (threats.folder.parent/'evil.sh').exists()
    # Later updates fetch only the recent additions and merge them in.
    asked.clear();assert threatlists.update(fetch)[0]==('MalwareBazaar hash list',True,'3 fingerprints (1 new)')
    assert asked[0]==threatlists.BAZAAR_RECENT and HashList().count==3
    def refused(url):
        if 'bazaar' in url:raise urllib.error.HTTPError(url,403,'Forbidden',None,None)
        raise urllib.error.URLError('no route')
    outcome=threatlists.update(refused)
    assert outcome[0][1] is False and 'may now require an account' in outcome[0][2] and outcome[1]==('YARA Forge core rules',False,'could not connect (no route)')
    assert HashList().count==3
    served[threatlists.FORGE_CORE]=b'not a zip';assert threatlists.update(fetch)[1][1] is False

def test_settings_updates_threat_lists_in_the_background(threats,app,monkeypatch):
    import ui.settings as settings
    from config import load_config
    def update():
        threats.hashes(b'x');return [('MalwareBazaar hash list',True,'1 fingerprints (1 new)'),('YARA Forge core rules',False,'could not connect (offline)')]
    monkeypatch.setattr(settings.threatlists,'update',update)
    page=settings.SettingsPage()
    assert 'no lists downloaded yet' in page.threats_status.text()
    assert page.hash_lookup.isChecked() and page.yara_scan.isChecked() and not page.yara_quarantine.isChecked()
    page.update_threat_lists();page.threats_thread.join()
    deadline=time.monotonic()+5
    while not page.threats_button.isEnabled() and time.monotonic()<deadline:app.processEvents()
    assert page.threats_button.isEnabled() and 'could not update: could not connect (offline)' in page.threats_result.text()
    assert '1 known-malware fingerprints' in page.threats_status.text()
    page.yara_quarantine.setChecked(True);assert load_config()['yara_quarantine'] is True
    page.shutdown()

def test_threat_lists_are_never_scanned(threats,monkeypatch):
    pytest.importorskip('yara_x')
    threats.rule();threats.hashes(b'x')
    seen=[];summary,_=run_worker(monkeypatch,[threats.folder],clean_engine(seen))
    assert seen==[] and summary['scanned']==0

def test_cli_updates_threat_lists(threats,monkeypatch):
    from core import cli,threatlists
    monkeypatch.setattr(threatlists,'update',lambda:[('A',True,'3 rules'),('B',False,'offline')])
    out=io.StringIO();assert cli.update_threat_lists(out)==2
    assert out.getvalue()=='A: updated, 3 rules\nB: FAILED: offline\n'
    monkeypatch.setattr(threatlists,'update',lambda:[('A',True,'3 rules')])
    assert cli.update_threat_lists(io.StringIO())==0
