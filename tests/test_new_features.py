import hashlib
import io
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app, engine
from test_features import drain


def test_old_database_gains_fingerprint_column(isolated):
    import database.database as database
    conn=sqlite3.connect(database.DATABASE)
    conn.execute("CREATE TABLE quarantine(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, original_path TEXT, quarantine_path TEXT, virus TEXT)")
    conn.execute("INSERT INTO quarantine VALUES (1,'2026-01-01T00:00:00','/a','/q','Old')");conn.commit();conn.close()
    db=database.GuardianDatabase()
    assert db.get_quarantined_files()==[(1,'2026-01-01T00:00:00','/a','/q','Old',None,None)]
    db.close()

def test_monitored_folders_seeded_once(isolated,monkeypatch):
    from database.database import GuardianDatabase
    monkeypatch.setattr(Path,'home',lambda:isolated)
    db=GuardianDatabase()
    assert db.get_monitored_folders()==sorted(str(isolated/n) for n in ('Downloads','Desktop','Documents'))
    for folder in db.get_monitored_folders():db.remove_folder('monitored_folders',folder)
    db.close()
    db=GuardianDatabase();assert db.get_monitored_folders()==[];db.close()
    with pytest.raises(ValueError):GuardianDatabase().get_folders('scans')

def test_quarantine_records_sha256(isolated):
    from core.quarantine import QuarantineManager
    from database.database import GuardianDatabase
    file=isolated/'sample';file.write_bytes(b'fixture bytes')
    QuarantineManager().quarantine(file,'Test')
    db=GuardianDatabase()
    assert db.get_quarantined_files()[0][5]==hashlib.sha256(b'fixture bytes').hexdigest()
    db.close()

def test_worker_scans_individual_files_and_reports_results(isolated,monkeypatch,app):
    from core.scan_worker import ScanWorker
    folder=isolated/'files';folder.mkdir()
    one=folder/'one';one.write_text('a');(folder/'two').write_text('b')
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:{'status':'found','virus':'Test'}))
    worker=ScanWorker([one],quarantine=False);results=[];errors=[]
    worker.result.connect(lambda *r:results.append(r));worker.error.connect(errors.append);worker.run()
    assert results==[(str(one),'found','Test')] and one.exists()
    worker=ScanWorker([isolated/'missing']);worker.error.connect(errors.append);worker.run()
    assert errors==['Not found or not accessible: '+str(isolated/'missing')]

@pytest.mark.parametrize('statuses,code',[(['clean'],0),(['clean','found'],1),(['error'],2)])
def test_cli_exit_codes_and_output(isolated,monkeypatch,app,statuses,code):
    from core.cli import run_scan
    files=[]
    for i,status in enumerate(statuses):
        f=isolated/f'{status}{i}';f.write_text('x');files.append(f)
    lookup={f:{'status':s,'virus':{'found':'Eicar','error':'engine failed','clean':None}[s]} for f,s in zip(files,statuses)}
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:lookup[p]))
    out,err=io.StringIO(),io.StringIO()
    assert run_scan(['--report-only',*map(str,files)],out,err)==code
    text=out.getvalue()
    for f,s in zip(files,statuses):
        assert f'{f}: '+{'clean':'OK','found':'FOUND Eicar','error':'ERROR engine failed'}[s] in text
    assert err.getvalue()==''
    assert all(f.exists() for f in files)

def test_cli_requires_paths():
    from core.cli import run_scan
    err=io.StringIO()
    assert run_scan([],io.StringIO(),err)==2 and 'usage' in err.getvalue()

def test_watcher_uses_and_reschedules_monitored_folders(isolated,monkeypatch):
    from core.watcher import Watcher
    from database.database import GuardianDatabase
    monkeypatch.setattr(Path,'home',lambda:isolated)
    custom=isolated/'projects';custom.mkdir()
    db=GuardianDatabase();db.add_folder('monitored_folders',custom);db.close()
    watcher=Watcher();watcher.start()
    try:
        assert [e.watch.path for e in watcher.observer.emitters]==[str(custom)]
        db=GuardianDatabase();db.remove_folder('monitored_folders',custom);db.close()
        with pytest.raises(RuntimeError,match='None of the monitored folders exist'):
            watcher.reschedule()
    finally:
        watcher.stop(wait=True)

def test_pause_and_auto_resume_monitoring(isolated,app,monkeypatch):
    from config import load_config,save_config
    from ui.main_window import MainWindow
    from ui.tray import GuardianTray
    monkeypatch.setattr(Path,'home',lambda:isolated)
    (isolated/'Downloads').mkdir()
    save_config(dict(load_config(),realtime=True))
    window=MainWindow();window.tray=GuardianTray(window)
    try:
        window.refresh_protection()
        assert window.tray.pause_action.isVisible() and not window.tray.resume_action.isVisible()
        window.pause_monitoring()
        assert window.watcher.handler.stopping.is_set()
        assert 'paused until' in window.stack.widget(0).protection.status.text()
        assert window.tray.resume_action.isVisible() and not window.tray.pause_action.isVisible()
        window.paused_until=datetime.now()-timedelta(seconds=1)
        window.refresh_protection()
        assert window.paused_until is None and not window.watcher.handler.stopping.is_set()
        assert load_config()['realtime']
    finally:
        window.shutdown()

def test_tray_menu_keeps_all_actions(isolated,app):
    import gc
    from ui.main_window import MainWindow
    from ui.tray import GuardianTray
    window=MainWindow();tray=GuardianTray(window);gc.collect()
    texts=[a.text() for a in tray.menu.actions()]
    for text in ('Open Guardian','Run Quick Scan','View History','Quit Guardian'):
        assert text in texts
    window.shutdown()

def test_dropped_paths_start_scan(isolated,app):
    from PySide6.QtCore import QMimeData,QUrl,QPointF,Qt
    from PySide6.QtGui import QDropEvent
    from ui.main_window import MainWindow
    window=MainWindow();dash=window.stack.widget(0);dash.scan_paths=Mock()
    mime=QMimeData();mime.setUrls([QUrl.fromLocalFile(str(isolated/'a')),QUrl.fromLocalFile(str(isolated/'b'))])
    event=QDropEvent(QPointF(5,5),Qt.DropAction.CopyAction,mime,Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
    window.dropEvent(event)
    dash.scan_paths.assert_called_once_with([str(isolated/'a'),str(isolated/'b')])
    window.shutdown()

def test_file_scan_and_hidden_notification(isolated,app,monkeypatch):
    from ui.dashboard import DashboardPage
    from PySide6.QtWidgets import QFileDialog
    file=isolated/'file';file.write_text('fixture')
    monkeypatch.setattr(QFileDialog,'getOpenFileNames',lambda *a:([str(file)],''))
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:{'status':'clean','virus':None}))
    notify=Mock();monkeypatch.setattr('ui.dashboard.GuardianNotifier.notify',notify)
    page=DashboardPage();page.file_scan()
    drain(app,lambda:not page.scan_active)
    assert page.last_summary['scanned']==1
    notify.assert_called_once()
    assert 'Custom scan: scan complete, 1 file checked, no threats found.' in notify.call_args.args[1]
    page.scan_manager.shutdown();page.db.close()

def test_history_period_filter(isolated,app):
    from ui.history import HistoryPage
    page=HistoryPage()
    page.db.add_scan('/recent','clean')
    page.db.conn.execute("INSERT INTO scans(timestamp,filepath,status,virus) VALUES ('2000-01-01T00:00:00','/old','clean',NULL)");page.db.conn.commit()
    page.refresh();assert page.table.rowCount()==2
    page.period.setCurrentIndex(2)
    assert [r[1] for r in page.filtered_rows]==['/recent']
    page.db.close()

def test_quarantine_bulk_actions_copy_and_report(isolated,app,monkeypatch):
    import csv
    from core.quarantine import QuarantineManager
    from ui.quarantine import QuarantinePage
    from PySide6.QtWidgets import QMessageBox,QApplication
    files=[isolated/n for n in ('one','two','three')]
    for f in files:
        f.write_text('=cmd|'+f.name);QuarantineManager().quarantine(f,'Test')
    page=QuarantinePage()
    page.table.selectAll()
    assert page.restore_button.text()=='Restore 3 selected' and not page.copy_button.isEnabled()
    page.table.selectRow(0);page.copy_hash()
    assert QApplication.clipboard().text()==hashlib.sha256(b'=cmd|three').hexdigest()
    report=isolated/'report.csv';page.write_report(report)
    rows=list(csv.reader(report.open(encoding='utf-8-sig')))
    assert rows[0]==['Date','Original file','Detection','SHA-256'] and len(rows)==4
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    page.table.selectAll();page.delete_file()
    assert page.table.rowCount()==0 and page.feedback.text()=='3 files permanently deleted.'
    page.db.close()

def test_update_definitions_outcomes(isolated,app):
    import sys
    from ui.settings import SettingsPage
    page=SettingsPage();updated=Mock();page.definitions_updated.connect(updated)
    page.check_kind='update'
    page.start_check(sys.executable,['-c','print("daily.cvd database is up-to-date")'],'update')
    drain(app,lambda:page.process is None)
    assert page.check_result.text()=='Definitions are up to date.';updated.assert_called_once()
    page.start_check(sys.executable,['-c','print("ERROR: Failed to lock the log file"); raise SystemExit(1)'],'update')
    drain(app,lambda:page.process is None)
    assert 'Failed to lock the log file' in page.check_result.text() and 'sudo freshclam' in page.check_result.text()
    page.start_check('/nonexistent/freshclam',[],'update')
    drain(app,lambda:page.process is None)
    assert 'freshclam is not installed' in page.check_result.text()
    assert page.update_button.isEnabled()
