import hashlib
import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app
from test_features import fake_clamscan


def cached_engine(key='ClamAV 1/1|test',verdict=lambda path:{'status':'clean','virus':None}):
    """Scanner double that records what it was asked to scan and names its engine."""
    seen=[]
    def scan_files(paths,started=None):
        for path in paths:
            seen.append(path);yield path,verdict(path)
    engine=SimpleNamespace(scan_files=scan_files,seen=seen,key=key)
    engine.engine_key=lambda:engine.key
    return engine

def run_worker(monkeypatch,engine,paths,**options):
    import core.scan_worker as worker_module
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:engine)
    worker=worker_module.ScanWorker(paths,**options);summary={}
    worker.summary.connect(summary.update);worker.run()
    return summary

def test_unchanged_files_are_not_rescanned(isolated,monkeypatch):
    folder=isolated/'files';folder.mkdir()
    for name in ('a','b','c'):(folder/name).write_text(name)
    engine=cached_engine()
    first=run_worker(monkeypatch,engine,[folder])
    assert len(engine.seen)==3 and first['unchanged']==0 and first['scanned']==3
    second=run_worker(monkeypatch,engine,[folder])
    assert len(engine.seen)==3 and second['unchanged']==3 and second['clean']==3 and second['scanned']==3
    (folder/'b').write_text('edited');(folder/'new').write_text('new')
    third=run_worker(monkeypatch,engine,[folder])
    assert sorted(p.name for p in engine.seen[3:])==['b','new'] and third['unchanged']==2 and third['scanned']==4

def test_unchanged_cache_is_dropped_for_new_signatures_and_can_be_bypassed(isolated,monkeypatch):
    import config
    folder=isolated/'files';folder.mkdir();(folder/'a').write_text('a')
    engine=cached_engine()
    run_worker(monkeypatch,engine,[folder]);run_worker(monkeypatch,engine,[folder])
    assert len(engine.seen)==1
    run_worker(monkeypatch,engine,[folder],skip_unchanged=False)
    assert len(engine.seen)==2
    config.save_config(dict(config.load_config(),skip_unchanged=False))
    run_worker(monkeypatch,engine,[folder]);assert len(engine.seen)==3
    config.save_config(dict(config.load_config(),skip_unchanged=True))
    # Scans that recheck everything still record results for later ones.
    (folder/'late').write_text('late');run_worker(monkeypatch,engine,[folder],skip_unchanged=False)
    assert len(engine.seen)==5 and run_worker(monkeypatch,engine,[folder])['unchanged']==2 and len(engine.seen)==5
    (folder/'late').unlink()
    engine.key='ClamAV 1/2|test'
    assert run_worker(monkeypatch,engine,[folder])['unchanged']==0 and len(engine.seen)==6
    # An engine that cannot name its version never has results remembered.
    engine.key=None
    run_worker(monkeypatch,engine,[folder]);run_worker(monkeypatch,engine,[folder])
    assert len(engine.seen)==8

def test_swapped_file_with_restored_size_and_mtime_is_rescanned(isolated,monkeypatch):
    folder=isolated/'files';folder.mkdir();file=folder/'a';file.write_text('safe')
    os.utime(file,(1.6e9,1.6e9))
    engine=cached_engine()
    run_worker(monkeypatch,engine,[folder])
    time.sleep(0.02);file.write_text('evil');os.utime(file,(1.6e9,1.6e9))
    run_worker(monkeypatch,engine,[folder])
    assert len(engine.seen)==2

def test_detections_and_errors_are_never_remembered_as_clean(isolated,monkeypatch):
    from database.database import GuardianDatabase
    folder=isolated/'files';folder.mkdir()
    (folder/'bad').write_text('threat');(folder/'odd').write_text('unreadable')
    verdict=lambda path:{'status':'found','virus':'Test'} if path.name=='bad' else {'status':'error','virus':'denied'}
    engine=cached_engine(verdict=verdict)
    first=run_worker(monkeypatch,engine,[folder],quarantine=False)
    second=run_worker(monkeypatch,engine,[folder],quarantine=False)
    assert len(engine.seen)==4 and second['unchanged']==0 and second['found']==1
    assert first['detections']==[hashlib.sha256(b'threat').hexdigest()]
    db=GuardianDatabase();assert db.detection_hash(str(folder/'bad'))==first['detections'][0];db.close()

def test_engine_key_tracks_version_archives_and_signature_files(isolated,monkeypatch):
    import config
    import core.scanner as engine_module
    signatures=isolated/'signatures';signatures.mkdir();(signatures/'daily.cvd').write_text('one')
    monkeypatch.setattr(engine_module.clamav,'database_dirs',lambda:(str(signatures),))
    version=['ClamAV 1.5.4/27500/Tue Oct 21 08:23:45 2026\n']
    monkeypatch.setattr('core.scanner.subprocess.run',lambda *a,**k:SimpleNamespace(stdout=version[0]))
    scanner=engine_module.GuardianScanner.__new__(engine_module.GuardianScanner);scanner.clamd=None
    first=scanner.engine_key();assert first and first==scanner.engine_key()
    (signatures/'extra.ndb').write_text('added');second=scanner.engine_key();assert second!=first
    config.save_config(dict(config.load_config(),archives=False));third=scanner.engine_key();assert third!=second
    version[0]='ClamAV 1.5.4/27501/Wed Oct 22 08:23:45 2026\n';assert scanner.engine_key()!=third
    version[0]='clamscan: command not found';assert scanner.engine_key() is None
    # A daemon that refuses the version command falls back to clamscan's answer.
    config.save_config(dict(config.load_config(),archives=True))
    version[0]='ClamAV 1.5.4/27501/Wed Oct 22 08:23:45 2026\n'
    scanner.clamd=Mock();scanner.clamd.version.return_value='COMMAND UNAVAILABLE'
    assert scanner.engine_key().startswith('ClamAV 1.5.4/27501')

def test_history_database_gains_fingerprint_column(isolated):
    import database.database as database
    conn=sqlite3.connect(database.DATABASE)
    conn.execute('CREATE TABLE scans(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, filepath TEXT, status TEXT, virus TEXT)')
    conn.execute("INSERT INTO scans(timestamp,filepath,status,virus) VALUES ('2026-01-01T00:00:00','/old','found','Old')");conn.commit();conn.close()
    db=database.GuardianDatabase()
    assert db.recent_scans(5)[0][1]=='/old' and db.detection_hash('/old') is None
    db.add_scan('/new','found','Test',sha256='a'*64);assert db.detection_hash('/new')=='a'*64
    db.close()

def test_clamscan_progress_names_the_file_being_scanned(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/name for name in ('a','b','c')]
    for file in files:file.write_text('x')
    fake_clamscan(monkeypatch,0,''.join(f'{file}: OK\n' for file in files))
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=None
    started=[]
    assert len(list(scanner.scan_files(files,started=started.append)))==3
    assert started==[files,[files[1]],[files[2]]]

def test_daemon_setup_steps_match_the_distribution(tmp_path):
    from core import daemon
    release=tmp_path/'os-release'
    for text,expected,command in (('ID=ubuntu\nID_LIKE=debian\n','debian','sudo apt install clamav-daemon'),('ID="linuxmint"\nID_LIKE="ubuntu debian"\n','debian','sudo systemctl enable --now clamav-daemon'),
                                  ('ID=fedora\n','fedora','sudo systemctl enable --now clamd@scan'),('ID=manjaro\nID_LIKE=arch\n','arch','sudo pacman -S clamav')):
        release.write_text(text)
        assert daemon.family(release)==expected
        steps=daemon.setup_steps(expected);assert command in steps and steps.count('Run these in a terminal')==1
    release.write_text('ID=solus\n');assert daemon.family(release) is None and daemon.family(tmp_path/'missing') is None
    assert daemon.setup_steps(None).count('Run these in a terminal')==3

def test_dashboard_offers_daemon_setup_only_when_it_is_missing(isolated,app,monkeypatch):
    import ui.dashboard as dashboard
    found=[None];monkeypatch.setattr(dashboard,'daemon_socket',lambda timeout=5:found[0])
    page=dashboard.DashboardPage()
    assert not page.daemon_button.isHidden()
    from PySide6.QtWidgets import QPlainTextEdit
    page.show_daemon_steps();assert 'ClamAV daemon' in page.steps_dialog.findChild(QPlainTextEdit).toPlainText()
    page.steps_dialog.close()
    found[0]='/run/clamav/clamd.ctl';page.daemon_checked=-99;page.refresh_dashboard();assert page.daemon_button.isHidden()
    page.db.close()

def test_dashboard_reports_unchanged_files_and_looks_up_detections(isolated,app,monkeypatch):
    import ui.dashboard as dashboard
    opened=[];monkeypatch.setattr(dashboard,'open_in_browser',lambda url:opened.append(url) or True)
    page=dashboard.DashboardPage();page.scan_active=True
    digests=[format(i,'064x') for i in range(5)]
    page.receive_summary({'cancelled':False,'errors':0,'found':5,'clean':10,'quarantined':5,'unchanged':7,'duration':1,'detections':digests})
    page.scan_finished(15)
    assert 'Clean: 10 (7 unchanged, not rechecked)' in page.result_text.text() and not page.detections_button.isHidden()
    page.lookup_detections()
    assert opened==['https://www.virustotal.com/gui/file/'+d for d in digests[:3]] and 'other 2' in page.current_file.text()
    page.scan_active=True;page.receive_summary({'cancelled':False,'errors':0,'found':0,'clean':1,'quarantined':0,'unchanged':0,'duration':1,'detections':[]})
    page.scan_finished(1);assert page.detections_button.isHidden() and 'unchanged' not in page.result_text.text()
    page.db.close()

def test_history_looks_up_a_detection_by_fingerprint(isolated,app,monkeypatch):
    import ui.history as history
    opened=[];monkeypatch.setattr(history,'open_in_browser',lambda url:opened.append(url) or True)
    page=history.HistoryPage()
    page.db.add_scan('/a/clean','clean');page.db.add_scan('/a/unknown','found','Old');page.db.add_scan('/a/threat','found','Test',sha256='b'*64)
    page.refresh()
    assert not page.lookup_button.isEnabled()
    names=[page.table.item(row,1).text() for row in range(3)]
    page.table.selectRow(names.index('/a/clean'));assert not page.lookup_button.isEnabled()
    page.table.selectRow(names.index('/a/unknown'));assert not page.lookup_button.isEnabled()
    page.table.selectRow(names.index('/a/threat'));assert page.lookup_button.isEnabled()
    page.lookup_detection();assert opened==['https://www.virustotal.com/gui/file/'+'b'*64]
    page.db.close()

def test_new_downloads_are_announced_with_a_lookup_action(isolated,monkeypatch):
    import config
    import core.watcher as watcher_module
    config.save_config(dict(config.load_config(),notifications=True))
    downloads=isolated/'Downloads';downloads.mkdir();elsewhere=isolated/'Documents';elsewhere.mkdir()
    monkeypatch.setattr(watcher_module,'downloads_dir',lambda:downloads)
    monkeypatch.setattr(watcher_module,'GuardianScanner',lambda:SimpleNamespace(scan_file=lambda path:{'status':'clean','virus':None}))
    announced=[];monkeypatch.setattr(watcher_module.GuardianNotifier,'notify_action',lambda *a:announced.append(a))
    opened=[];monkeypatch.setattr(watcher_module.virustotal,'open_externally',opened.append)
    watcher=watcher_module.GuardianWatcher()
    monkeypatch.setattr(watcher,'queue',lambda path:None)
    event=lambda path:SimpleNamespace(is_directory=False,src_path=str(path),dest_path=str(path))
    new=downloads/'setup.bin';new.write_text('installer')
    watcher.on_moved(event(new));watcher.scan(new)
    assert len(announced)==1 and announced[0][1]=='Download checked: setup.bin · no threats found'
    announced[0][3]();assert opened==['https://www.virustotal.com/gui/file/'+hashlib.sha256(b'installer').hexdigest()]
    # Edits to a file already there, and new files elsewhere, are checked quietly.
    new.write_text('edited in place');watcher.on_modified(event(new));watcher.scan(new)
    other=elsewhere/'notes.txt';other.write_text('x');watcher.on_created(event(other));watcher.scan(other)
    assert len(announced)==1
    config.save_config(dict(config.load_config(),download_notifications=False))
    second=downloads/'two.bin';second.write_text('y');watcher.on_created(event(second));watcher.scan(second)
    assert len(announced)==1

def test_notification_action_runs_callback_or_falls_back(isolated,monkeypatch):
    import config
    import core.notifier as notifier
    config.save_config(dict(config.load_config(),notifications=True))
    monkeypatch.setattr(notifier,'Thread',lambda target,**kw:SimpleNamespace(start=target))
    calls=[];reply=[SimpleNamespace(returncode=0,stdout='open\n')]
    monkeypatch.setattr('core.notifier.subprocess.run',lambda args,**kw:calls.append(args) or reply[0])
    pressed=[]
    assert notifier.GuardianNotifier.notify_action('Guardian','checked','Look up',lambda:pressed.append(1)) is True
    assert pressed==[1] and calls[0][:2]==['notify-send','--action=open=Look up']
    reply[0]=SimpleNamespace(returncode=0,stdout='');notifier.GuardianNotifier.notify_action('Guardian','checked','Look up',lambda:pressed.append(2))
    assert pressed==[1]
    # Older notify-send rejects --action; the message is still shown.
    reply[0]=SimpleNamespace(returncode=1,stdout='');calls.clear()
    notifier.GuardianNotifier.notify_action('Guardian','checked','Look up',lambda:pressed.append(3))
    assert pressed==[1] and calls[1]==['notify-send','--','Guardian','checked']
    config.save_config(dict(config.load_config(),notifications=False))
    assert notifier.GuardianNotifier.notify_action('Guardian','checked','Look up',lambda:None) is False

def test_extra_signature_status_and_steps(tmp_path):
    from core import signatures
    conf=tmp_path/'freshclam.conf';folder=tmp_path/'db';folder.mkdir()
    conf.write_text('DatabaseMirror database.clamav.net\n')
    state=signatures.status([str(conf)],[str(folder)])
    assert signatures.describe(state)==('Not in use. Scans rely on ClamAV\'s official signatures only.',False)
    steps=signatures.setup_steps(state)
    assert 'DatabaseCustomURL https://urlhaus.abuse.ch/downloads/urlhaus.ndb' in steps and str(conf) in steps
    conf.write_text('DatabaseCustomURL https://urlhaus.abuse.ch/downloads/urlhaus.ndb\n')
    text,attention=signatures.describe(signatures.status([str(conf)],[str(folder)]))
    assert text.startswith('Configured but not downloaded yet') and attention
    (folder/'urlhaus.ndb').write_text('sig')
    text,attention=signatures.describe(signatures.status([str(conf)],[str(folder)]))
    assert text.startswith('In use: URLhaus') and not attention

def test_settings_shows_signature_sources_and_new_toggles(isolated,app):
    from config import load_config
    from ui.settings import SettingsPage
    page=SettingsPage()
    assert page.signatures_status.text()
    page.show_signature_steps();page.steps_dialog.close()
    page.show_onaccess_steps();page.steps_dialog.close()
    assert page.skip_unchanged.isChecked() and page.download_notifications.isChecked()
    page.skip_unchanged.setChecked(False);assert load_config()['skip_unchanged'] is False
    page.shutdown()

def test_cli_full_flag_rechecks_unchanged_files(isolated,monkeypatch):
    import io
    import core.scan_worker as worker_module
    from core.cli import run_scan
    file=isolated/'sample';file.write_text('x')
    engine=cached_engine();monkeypatch.setattr(worker_module,'GuardianScanner',lambda:engine)
    out=io.StringIO();assert run_scan(['--report-only',str(file)],out,io.StringIO())==0
    out=io.StringIO();assert run_scan(['--report-only',str(file)],out,io.StringIO())==0
    assert '1 unchanged since last scan, not rechecked' in out.getvalue() and len(engine.seen)==1
    out=io.StringIO();assert run_scan(['--full','--report-only',str(file)],out,io.StringIO())==0
    assert 'unchanged' not in out.getvalue() and len(engine.seen)==2

def test_other_writers_are_not_locked_out_while_a_file_is_being_scanned(isolated,monkeypatch):
    import core.scan_worker as worker_module
    import database.database as database
    from threading import Thread
    folder=isolated/'files';folder.mkdir()
    for name in ('a','b','c'):(folder/name).write_text(name)
    waited=[]
    def scan_files(paths,started=None):
        for index,path in enumerate(paths):
            if index==2:
                # Stand in for a slow file: meanwhile the interface or monitor writes to the database.
                other=sqlite3.connect(database.DATABASE,timeout=0.2);began=time.monotonic()
                other.execute("INSERT INTO exclusions(path) VALUES ('/elsewhere')");other.commit();other.close()
                waited.append(time.monotonic()-began)
            yield path,{'status':'clean','virus':None}
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:SimpleNamespace(scan_files=scan_files))
    worker=worker_module.ScanWorker([folder]);errors=[];worker.error.connect(errors.append);worker.run()
    assert waited and not errors
    db=database.GuardianDatabase();assert db.get_scan_count()==3 and db.get_exclusions()==['/elsewhere'];db.close()

def test_link_lookup_accepts_addresses_without_a_scheme():
    from core import virustotal
    assert virustotal.link_url('example.com/download?x=1')=='https://www.virustotal.com/gui/search/http%253A%252F%252Fexample.com%252Fdownload%253Fx%253D1'
    assert virustotal.link_url('example.com:8080/a').endswith('example.com%253A8080%252Fa')
    assert virustotal.link_url('just words/here') is None and virustotal.link_url('/etc/passwd') is None

def test_hostile_file_names_never_reach_the_daemon_by_name(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    decoy=isolated/'decoy';decoy.write_text('harmless')
    evil=isolated/'decoy\n.com';evil.write_text('threat')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock()
    # A daemon that answers about some other file is not believed.
    scanner.clamd.scan_file.side_effect=lambda name:{str(decoy):('OK',None)}
    monkeypatch.setattr('core.scanner.subprocess.run',lambda *a,**k:SimpleNamespace(returncode=1,stdout=a[0][-1]+': Eicar-Test FOUND',stderr=''))
    assert scanner.scan_file(evil)['status']=='found'
    assert not any(evil.name in str(call) for call in scanner.clamd.scan_file.call_args_list)
    other=isolated/'plain';other.write_text('x')
    assert scanner.scan_file(other)['status']=='found' and scanner.scan_file(decoy)['status']=='clean'

def test_long_paths_and_carriage_returns_are_scanned_without_the_daemon(isolated,monkeypatch):
    import core.scanner as engine_module
    monkeypatch.setattr(engine_module,'CLI_LIST_PATH_LIMIT',len(str(isolated))+12)
    short=[isolated/'a',isolated/'cr\rname'];long=isolated/('long'*10)
    for file in short+[long]:file.write_text('x')
    out=''.join(f'{file}: OK\n' for file in short)
    from test_features import fake_clamscan
    calls=fake_clamscan(monkeypatch,0,out)
    single=[];monkeypatch.setattr('core.scanner.subprocess.run',lambda args,**k:single.append(args[-1]) or SimpleNamespace(returncode=0,stdout='',stderr=''))
    scanner=engine_module.GuardianScanner.__new__(engine_module.GuardianScanner);scanner.clamd=None
    results=dict(scanner.scan_files(short+[long]))
    assert single==[str(long)] and len(calls)==1 and len(calls[0][1])==3
    assert all(results[file]['status']=='clean' for file in short+[long])

