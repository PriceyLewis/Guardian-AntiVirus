import hashlib
import io
import os
import signal
import tarfile
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from threading import Timer
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app
from test_engines import threats, clean_engine, run_worker, RULE, MARKED
from test_features import fake_clamscan


def test_ignored_suspicious_file_is_not_reported_until_it_changes(threats,monkeypatch):
    pytest.importorskip('yara_x')
    from database.database import GuardianDatabase
    folder=threats.folder.parent/'files';folder.mkdir();marked=folder/'marked';marked.write_bytes(MARKED)
    threats.rule()
    summary,results=run_worker(monkeypatch,[folder])
    assert results['marked'][0]=='suspicious' and summary['flagged']==1
    db=GuardianDatabase();db.ignore_file(summary['detections'][0],str(marked))
    assert [row[2] for row in db.recent_scans(5)]==['ignored'] and db.get_suspicious_count()==0
    summary,results=run_worker(monkeypatch,[folder])
    assert results['marked']==('clean','') and summary['flagged']==0
    # Remembered as clean now, like any other file.
    seen=[];summary,_=run_worker(monkeypatch,[folder],clean_engine(seen));assert seen==[] and summary['unchanged']==1
    marked.write_bytes(MARKED+b' edited')
    assert run_worker(monkeypatch,[folder])[0]['flagged']==1
    marked.write_bytes(MARKED)
    assert run_worker(monkeypatch,[folder])[0]['flagged']==0
    assert db.clear_ignored()==1;db.close()
    assert run_worker(monkeypatch,[folder])[0]['flagged']==1

def test_history_quarantines_or_ignores_a_suspicious_file(threats,app,monkeypatch):
    pytest.importorskip('yara_x')
    import ui.history as history
    folder=threats.folder.parent/'files';folder.mkdir()
    one=folder/'one';one.write_bytes(MARKED);two=folder/'two';two.write_bytes(MARKED+b'2');(folder/'fine').write_bytes(b'ok')
    threats.rule();run_worker(monkeypatch,[folder])
    page=history.HistoryPage()
    names=lambda:[Path(page.table.item(row,1).text()).name for row in range(page.table.rowCount())]
    states=lambda:{Path(page.table.item(row,1).text()).name:page.table.item(row,2).text() for row in range(page.table.rowCount())}
    assert states()=={'one':'Suspicious','two':'Suspicious','fine':'Clean'}
    page.table.selectRow(names().index('fine'));assert not page.quarantine_button.isEnabled() and not page.ignore_button.isEnabled()
    page.table.selectRow(names().index('one'));assert page.quarantine_button.isEnabled() and page.ignore_button.isEnabled() and page.lookup_button.isEnabled()
    page.quarantine_suspicious()
    assert not one.exists() and states()['one']=='Detection' and page.db.get_quarantine_count()==1
    page.table.selectRow(names().index('two'));page.ignore_suspicious()
    assert two.exists() and states()['two']=='Ignored' and page.db.ignored_hashes()=={hashlib.sha256(MARKED+b'2').hexdigest()}
    page.filter.setCurrentIndex(page.filter.findData('suspicious'));assert page.table.rowCount()==0
    # A file that has gone cannot be quarantined; the user is told.
    gone=folder/'gone';gone.write_bytes(MARKED+b'3');run_worker(monkeypatch,[folder]);gone.unlink()
    page.filter.setCurrentIndex(0);page.refresh();shown=Mock();monkeypatch.setattr(history.QMessageBox,'critical',shown)
    page.table.selectRow(names().index('gone'));page.quarantine_suspicious();shown.assert_called_once()
    page.db.close()

def archive(kind,members):
    buffer=io.BytesIO()
    if kind=='zip':
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as bundle:
            for name,content in members:bundle.writestr(name,content)
    else:
        with tarfile.open(fileobj=buffer,mode='w:gz' if kind=='tgz' else 'w') as bundle:
            for name,content in members:
                info=tarfile.TarInfo(name);info.size=len(content);bundle.addfile(info,io.BytesIO(content))
    return buffer.getvalue()

def test_second_opinion_looks_inside_archives(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import config
    import core.engines as engines
    threats.hashes(b'listed malware');threats.rule()
    base=threats.folder.parent
    cases={'hash.zip':archive('zip',[('readme.txt',b'hello'),('bin/tool.exe',b'listed malware')]),
           'yara.zip':archive('zip',[('a.txt',b'ok'),('doc.txt',MARKED)]),
           'yara.tar.gz':archive('tgz',[('a.txt',b'ok'),('deep/doc.txt',MARKED)]),
           'hash.tar':archive('tar',[('tool.exe',b'listed malware')]),
           'clean.zip':archive('zip',[('a.txt',b'ok'),('b.txt',b'fine')]),
           'broken.zip':b'PK\x03\x04'+b'not really a zip'*10,
           'plain.txt':b'just text'}
    for name,content in cases.items():(base/name).write_bytes(content)
    opinion=engines.SecondOpinion()
    verdict=lambda name:(opinion.check(base/name) or {}).get('virus')
    assert verdict('hash.zip')=='Guardian.KnownMalware.SHA256 (in archive: bin/tool.exe)'
    assert verdict('yara.zip')=='YARA.Guardian_Test_Marker (in archive: doc.txt)'
    assert verdict('yara.tar.gz')=='YARA.Guardian_Test_Marker (in archive: deep/doc.txt)'
    assert verdict('hash.tar')=='Guardian.KnownMalware.SHA256 (in archive: tool.exe)'
    assert verdict('clean.zip') is None and verdict('broken.zip') is None and verdict('plain.txt') is None
    # Archives read from disk rather than memory behave the same.
    monkeypatch.setattr(engines,'IN_MEMORY_LIMIT',8)
    assert verdict('hash.zip') and verdict('yara.tar.gz') and verdict('clean.zip') is None
    monkeypatch.undo();monkeypatch.setattr(__import__('core.paths',fromlist=['x']),'THREATS',threats.folder)
    # Limits: oversized members and members past the count are not opened.
    monkeypatch.setattr(engines,'ARCHIVE_MEMBER_SIZE',10);assert engines.SecondOpinion().check(base/'hash.zip') is None
    monkeypatch.setattr(engines,'ARCHIVE_MEMBER_SIZE',10**6);monkeypatch.setattr(engines,'ARCHIVE_MEMBERS',1)
    assert engines.SecondOpinion().check(base/'hash.zip') is None
    monkeypatch.setattr(engines,'ARCHIVE_MEMBERS',200)
    config.save_config(dict(config.load_config(),archives=False))
    assert engines.SecondOpinion().check(base/'hash.zip') is None

def test_archive_and_ignore_choices_change_the_engine_identity(threats):
    import config
    from core.engines import SecondOpinion
    threats.hashes(b'x')
    first=SecondOpinion().key()
    config.save_config(dict(config.load_config(),archives=False))
    assert SecondOpinion().key()!=first

def test_folder_scans_skip_large_and_media_files_but_not_named_ones(isolated,monkeypatch):
    import config
    import core.scan_worker as worker_module
    folder=isolated/'files';folder.mkdir()
    for name,size in (('song.MP3',10),('clip.mkv',10),('photo.jpg',10),('doc.pdf',10),('big.iso',3*1024*1024),('tool.exe',10)):(folder/name).write_bytes(b'x'*size)
    seen=[];summary,_=run_worker(monkeypatch,[folder],clean_engine(seen),skip_unchanged=False)
    assert len(seen)==6 and summary['skipped']==0
    config.save_config(dict(config.load_config(),skip_media=True))
    seen.clear();summary,_=run_worker(monkeypatch,[folder],clean_engine(seen),skip_unchanged=False)
    assert sorted(p.name for p in seen)==['big.iso','doc.pdf','tool.exe'] and summary['skipped']==3 and summary['scanned']==3
    monkeypatch.setitem(config.CHOICES,'max_scan_size_mb',(0,1));config.save_config(dict(config.load_config(),max_scan_size_mb=1))
    seen.clear();summary,_=run_worker(monkeypatch,[folder],clean_engine(seen),skip_unchanged=False)
    assert sorted(p.name for p in seen)==['doc.pdf','tool.exe'] and summary['skipped']==4
    seen.clear();summary,_=run_worker(monkeypatch,[folder/'big.iso',folder/'song.MP3'],clean_engine(seen),skip_unchanged=False)
    assert len(seen)==2 and summary['skipped']==0

def test_pausing_holds_the_scan_and_the_engine(isolated,monkeypatch):
    import core.scan_worker as worker_module
    folder=isolated/'files';folder.mkdir()
    for index in range(5):(folder/f'f{index}').write_text('x')
    calls=[];moments=[]
    engine=clean_engine();engine.pause=lambda:calls.append('pause');engine.resume=lambda:calls.append('resume')
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:engine)
    worker=worker_module.ScanWorker([folder]);summary={};worker.summary.connect(summary.update)
    def on_progress(count):
        moments.append(time.monotonic())
        if count==2:
            worker.paused.set();Timer(0.4,worker.paused.clear).start()
    worker.progress.connect(on_progress);worker.run()
    assert calls==['pause','resume'] and summary['scanned']==5 and not summary['cancelled']
    gaps=[b-a for a,b in zip(moments,moments[1:])];assert max(gaps)>=0.3
    # Cancelling while paused ends the scan instead of waiting for ever.
    worker=worker_module.ScanWorker([folder],skip_unchanged=False);summary={};worker.summary.connect(summary.update)
    worker.progress.connect(lambda count:count==1 and (worker.paused.set(),Timer(0.2,worker.cancelled.set).start()))
    worker.run();assert summary['cancelled'] and summary['scanned']==1

def test_engine_pause_stops_and_continues_clamscan(isolated):
    from core.scanner import GuardianScanner
    scanner=GuardianScanner.__new__(GuardianScanner)
    running=SimpleNamespace(poll=lambda:None,send_signal=Mock());finished=SimpleNamespace(poll=lambda:0,send_signal=Mock())
    scanner.running=[running,finished]
    scanner.pause();assert scanner.suspended and running.send_signal.call_args.args==(signal.SIGSTOP,)
    scanner.resume();assert not scanner.suspended and running.send_signal.call_args.args==(signal.SIGCONT,)
    finished.send_signal.assert_not_called()

def test_background_scans_use_one_gentle_worker(isolated,monkeypatch):
    import core.scanner as engine_module
    import core.scan_worker as worker_module
    files=[isolated/f'f{i}' for i in range(4)]
    for file in files:file.write_text('x')
    monkeypatch.setattr(engine_module,'cli_processes',lambda count:3)
    monkeypatch.setattr(engine_module.shutil,'which',lambda name:'/usr/bin/'+name)
    calls=fake_clamscan(monkeypatch,0)
    scanner=engine_module.GuardianScanner.__new__(engine_module.GuardianScanner);scanner.clamd=None;scanner.background=True
    assert len(dict(scanner.scan_files(files)))==4
    assert len(calls)==1 and calls[0][0][:7]==['nice','-n','19','ionice','-c','3','clamscan']
    # Without those tools the scan simply runs normally.
    monkeypatch.setattr(engine_module.shutil,'which',lambda name:None);calls.clear()
    list(scanner.scan_files(files));assert calls[0][0][0]=='clamscan'
    made=[]
    def make():
        engine=clean_engine();made.append(engine);return engine
    monkeypatch.setattr(worker_module,'GuardianScanner',make)
    worker_module.ScanWorker([isolated/'f0'],background=True).run();worker_module.ScanWorker([isolated/'f0']).run()
    assert made[0].background is True and not getattr(made[1],'background',False)

def test_scheduled_scans_run_in_the_background_when_asked(isolated,app,monkeypatch):
    import config
    from ui.main_window import MainWindow
    config.save_config(dict(config.load_config(),scheduled_scan=True))
    window=MainWindow()
    try:
        dashboard=window.stack.widget(0);started=[]
        monkeypatch.setattr(dashboard,'quick_scan',lambda background=False:started.append(background))
        window.run_scheduled_scan();assert started==[True]
        config.save_config(dict(config.load_config(),gentle_scheduled=False))
        window.run_scheduled_scan();assert started==[True,False]
    finally:
        window.shutdown()

def test_removable_mounts_are_read_from_the_mount_table(tmp_path):
    from core.mounts import removable_mounts
    media=tmp_path/'media'/'me';(media/'USB STICK').mkdir(parents=True);(media/'card').mkdir();(tmp_path/'elsewhere').mkdir()
    table=tmp_path/'mounts'
    escaped=str(media/'USB STICK').replace(' ',chr(92)+'040')
    table.write_text(f"/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 {escaped} vfat rw 0 0\n/dev/sdc1 {media/'card'} exfat rw 0 0\n"
                     f"/dev/sdd1 {tmp_path/'elsewhere'} ext4 rw 0 0\n/dev/sde1 {media/'unplugged'} vfat rw 0 0\nbroken line\n")
    assert removable_mounts(table,(str(media)+'/',))=={str(media/'USB STICK'),str(media/'card')}
    assert removable_mounts(tmp_path/'missing',(str(media)+'/',))==set()

def test_new_removable_drive_prompts_for_a_scan(isolated,app,monkeypatch):
    import config
    import ui.main_window as main_window
    present=[set()]
    monkeypatch.setattr(main_window,'removable_mounts',lambda:set(present[0]))
    present[0]={'/media/me/OLD'}
    window=main_window.MainWindow()
    try:
        dashboard=window.stack.widget(0);scans=[];asked=[]
        monkeypatch.setattr(dashboard,'scan_paths',scans.append)
        monkeypatch.setattr(window,'ask_to_scan',lambda mount:asked.append(mount) or True)
        window.check_removable();assert not asked
        present[0]={'/media/me/OLD','/media/me/NEW'};window.check_removable()
        assert asked==['/media/me/NEW'] and scans==[['/media/me/NEW']]
        window.check_removable();assert len(asked)==1
        # Unplugging and plugging in again asks again; declining or the setting being off does not scan.
        present[0]={'/media/me/OLD'};window.check_removable()
        monkeypatch.setattr(window,'ask_to_scan',lambda mount:asked.append(mount) and False)
        present[0]={'/media/me/OLD','/media/me/NEW'};window.check_removable();assert len(asked)==2 and len(scans)==1
        config.save_config(dict(config.load_config(),removable_prompt=False))
        present[0]={'/media/me/OLD','/media/me/NEW','/media/me/THIRD'};window.check_removable();assert len(asked)==2
    finally:
        window.shutdown()

def test_old_history_is_trimmed(isolated):
    from database.database import GuardianDatabase
    db=GuardianDatabase()
    old=(datetime.now()-timedelta(days=100)).isoformat(timespec='seconds');recent=(datetime.now()-timedelta(days=5)).isoformat(timespec='seconds')
    db.record_scans([(old,'/old','clean',None,None),(old,'/old-threat','found','X',None),(recent,'/recent','clean',None,None)])
    assert db.prune_scans(0)==0 and db.get_scan_count()==3
    assert db.prune_scans(90)==2 and [row[1] for row in db.recent_scans(5)]==['/recent']
    assert db.prune_scans(90)==0
    db.close()

def test_housekeeping_trims_history_and_updates_due_threat_lists(threats,app,monkeypatch):
    import config
    import ui.main_window as main_window
    from core import threatlists
    window=main_window.MainWindow()
    try:
        settings=window.stack.widget(5);updates=[]
        monkeypatch.setattr(settings,'update_threat_lists',lambda:updates.append(1))
        old=(datetime.now()-timedelta(days=400)).isoformat(timespec='seconds')
        window.stack.widget(0).db.record_scans([(old,'/old','clean',None,None)])
        assert threatlists.due()
        window.housekeeping()
        assert updates==[1] and window.stack.widget(0).db.get_scan_count()==0
        threats.folder.mkdir(exist_ok=True);threatlists.stamp().write_text('')
        assert not threatlists.due() and threatlists.due(time.time()+2*threatlists.UPDATE_INTERVAL)
        window.housekeeping();assert updates==[1]
        threatlists.stamp().unlink()
        config.save_config(dict(config.load_config(),auto_update_lists=False));window.housekeeping();assert updates==[1]
        config.save_config(dict(config.load_config(),auto_update_lists=True,hash_lookup=False,yara_scan=False));window.housekeeping();assert updates==[1]
    finally:
        window.shutdown()

def test_overview_describes_the_second_opinion_engines():
    from ui.dashboard import describe_second_opinion
    state=dict(hash_lookup=True,yara_scan=True,hashes=0,rule_files=0,yara_installed=True)
    assert describe_second_opinion(state)=='Second opinion: not set up · download threat lists in Settings'
    assert describe_second_opinion(dict(state,hash_lookup=False,yara_scan=False))=='Second opinion: switched off'
    assert describe_second_opinion(dict(state,hashes=1204611,rule_files=1),2)=='Second opinion: 1,204,611 known-malware fingerprints · YARA-X rules loaded · 2 suspicious files to review in History'
    assert describe_second_opinion(dict(state,hashes=5,rule_files=1,yara_installed=False))=='Second opinion: 5 known-malware fingerprints'

def test_dashboard_pause_button_and_summary_wording(isolated,app,monkeypatch):
    import ui.dashboard as dashboard
    page=dashboard.DashboardPage()
    held=[];monkeypatch.setattr(page.scan_manager,'pause',lambda paused=True:held.append(paused) or True)
    assert not page.pause_button.isEnabled()
    page.toggle_pause();assert held==[]
    page.scan_active=True;page.scan_name='Quick scan';page.pause_button.setEnabled(True)
    page.toggle_pause();assert held==[True] and page.pause_button.text()=='Resume' and page.scan_state.text()=='Quick scan · Paused'
    page.set_current_file('/some/file');assert page.current_file.text().startswith('Paused')
    page.toggle_pause();assert held==[True,False] and page.pause_button.text()=='Pause'
    page.receive_summary({'cancelled':False,'errors':0,'found':0,'clean':7,'quarantined':0,'unchanged':0,'flagged':2,'skipped':1500,'duration':3,'detections':['a'*64]})
    page.scan_finished(7)
    assert 'Suspicious: 2 (see History)' in page.result_text.text() and 'Skipped: 1,500 large or media' in page.result_text.text()
    assert not page.pause_button.isEnabled() and not page.detections_button.isHidden()
    page.db.close()

def test_cli_reports_suspicious_and_skipped_files(threats,monkeypatch):
    pytest.importorskip('yara_x')
    import config
    import core.scan_worker as worker_module
    from core.cli import run_scan
    folder=threats.folder.parent/'files';folder.mkdir();(folder/'marked.txt').write_bytes(MARKED);(folder/'song.mp3').write_bytes(b'x')
    threats.rule();config.save_config(dict(config.load_config(),skip_media=True))
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:clean_engine())
    out=io.StringIO();assert run_scan([str(folder)],out,io.StringIO())==1
    text=out.getvalue()
    assert f"{folder/'marked.txt'}: SUSPICIOUS YARA.Guardian_Test_Marker" in text
    assert '0 found (0 quarantined), 1 suspicious (matched by YARA rules only, left in place)' in text and 'Skipped 1 large or media file,' in text

def test_settings_can_stop_ignoring_files(isolated,app):
    from database.database import GuardianDatabase
    from ui.settings import SettingsPage
    db=GuardianDatabase();db.ignore_file('a'*64,'/x');db.close()
    page=SettingsPage()
    assert not page.ignored_button.isHidden() and '1 file ignored' in page.threats_status.text()
    page.clear_ignored()
    assert page.ignored_button.isHidden() and 'ignored' not in page.threats_status.text()
    for key in ('skip_media','removable_prompt','gentle_scheduled','auto_update_lists'):assert hasattr(page,key)
    assert page.history_retention_days.currentData()==90 and page.max_scan_size_mb.currentData()==0
    page.shutdown()
