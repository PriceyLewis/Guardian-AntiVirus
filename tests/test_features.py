import csv
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app, engine


def drain(app, predicate, timeout=3):
    deadline=time.monotonic()+timeout
    while not predicate() and time.monotonic()<deadline:
        app.processEvents()
        time.sleep(.005)
    assert predicate()

@pytest.mark.parametrize('key', ['realtime','archives','notifications','startup','close_to_tray','scheduled_scan'])
def test_every_setting_persists_both_states_and_reopens(isolated,app,key):
    from config import load_config
    from ui.settings import SettingsPage
    page=SettingsPage();page.runtime_apply=Mock()
    for value in (True,False):
        page.controls[key].setChecked(value)
        assert load_config()[key] is value
        other=SettingsPage()
        assert other.controls[key].isChecked() is value
        other.deleteLater()
    if key=='realtime':
        assert [c.args[0]['realtime'] for c in page.runtime_apply.call_args_list]==[True,False]
    page.deleteLater()

def test_failed_save_reverts_controls_and_runtime(isolated,app,monkeypatch):
    from ui.settings import SettingsPage
    from config import load_config
    page=SettingsPage();page.runtime_apply=Mock()
    monkeypatch.setattr('core.preferences.save_config',Mock(side_effect=OSError('disk full')))
    page.realtime.setChecked(True)
    assert page.realtime.isChecked() is False
    assert load_config()['realtime'] is False
    assert [c.args[0]['realtime'] for c in page.runtime_apply.call_args_list]==[True,False]
    assert 'disk full' in page.feedback.text()

def test_failed_runtime_does_not_persist(isolated,app):
    from ui.settings import SettingsPage
    from config import load_config
    page=SettingsPage()
    page.runtime_apply=Mock(side_effect=[RuntimeError('no folders'),None])
    page.realtime.setChecked(True)
    assert not page.realtime.isChecked() and not load_config()['realtime']
    assert 'no folders' in page.feedback.text()

def test_autostart_rollback_and_no_unrelated_writes(isolated,monkeypatch):
    from core.preferences import apply_preferences
    from core.startup import startup_path
    from config import load_config
    initial=load_config()
    save=Mock(side_effect=OSError('full'))
    monkeypatch.setattr('core.preferences.save_config',save)
    with pytest.raises(RuntimeError):
        apply_preferences(dict(initial,startup=True))
    assert not startup_path().exists()
    autostart=Mock()
    monkeypatch.setattr('core.preferences.set_startup',autostart)
    with pytest.raises(RuntimeError):
        apply_preferences(dict(initial,archives=False))
    autostart.assert_not_called()

def test_reset_defaults_applies_once_and_can_be_cancelled(isolated,app,monkeypatch):
    from config import DEFAULTS,load_config
    from ui.settings import SettingsPage
    from PySide6.QtWidgets import QMessageBox
    page=SettingsPage();page.runtime_apply=Mock()
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.No)
    page.reset_defaults();assert not load_config()['realtime']
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    page.reset_defaults()
    assert load_config()==DEFAULTS
    page.runtime_apply.assert_called_once()

def test_notifications_respect_setting(isolated,monkeypatch):
    from config import load_config,save_config
    from core.notifier import GuardianNotifier
    run=Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr('core.notifier.subprocess.run',run)
    assert GuardianNotifier.notify('a','b') is False
    run.assert_not_called()
    save_config(dict(load_config(),notifications=True))
    assert GuardianNotifier.notify('a','b') is True
    run.assert_called_once()

@pytest.mark.parametrize('available,keep,ignored',[(True,True,True),(True,False,False),(False,True,False)])
def test_close_behaviour(isolated,app,monkeypatch,available,keep,ignored):
    from config import load_config,save_config
    from ui.main_window import MainWindow
    from PySide6.QtWidgets import QSystemTrayIcon
    from PySide6.QtGui import QCloseEvent
    save_config(dict(load_config(),close_to_tray=keep))
    monkeypatch.setattr(QSystemTrayIcon,'isSystemTrayAvailable',lambda:available)
    window=MainWindow();event=QCloseEvent();window.closeEvent(event)
    assert event.isAccepted() is (not ignored)
    window.shutdown()

def test_engine_check_success_and_missing_command(isolated,app):
    import sys
    from ui.settings import SettingsPage
    page=SettingsPage()
    page.start_check(sys.executable,['-c','print("ClamAV test version")'],'engine')
    drain(app,lambda:page.process is None)
    assert 'ClamAV test version' in page.check_result.text()
    assert page.engine_button.isEnabled()
    page.start_check('/nonexistent/guardian-test-command',[],'engine')
    drain(app,lambda:page.process is None)
    assert 'unavailable' in page.check_result.text()

def test_notification_check_gating_and_command(isolated,app,monkeypatch):
    from ui.settings import SettingsPage
    page=SettingsPage();page.start_check=Mock()
    page.test_notification();page.start_check.assert_not_called()
    page.notifications.setChecked(True)
    page.test_notification()
    assert page.start_check.call_args.args[0]=='notify-send'
    page.notifications.setChecked(False)
    assert not page.notification_button.isEnabled()

def test_monitoring_pause_resume_does_not_wait_for_engine(isolated,monkeypatch):
    from core.watcher import Watcher
    monkeypatch.setattr(Path,'home',lambda:isolated)
    (isolated/'Downloads').mkdir()
    watcher=Watcher();watcher.start()
    try:
        observer=watcher.observer
        assert observer.is_alive()
        watcher.stop()
        assert watcher.handler.stopping.is_set()
        watcher.start()
        assert watcher.observer is observer
        assert not watcher.handler.stopping.is_set()
    finally:
        watcher.stop(wait=True)
    assert not observer.is_alive()

def test_history_filters_and_csv_use_visible_rows(isolated,app):
    from ui.history import HistoryPage
    page=HistoryPage()
    page.db.add_scan('/a/test','clean')
    page.db.add_scan('/b/test','found','=HYPERLINK("evil")')
    page.db.add_scan('/c/test','error','Permission denied')
    page.refresh();assert page.table.rowCount()==3
    page.filter.setCurrentIndex(2);assert page.table.rowCount()==1
    output=isolated/'out.csv';page.write_csv(output)
    rows=list(csv.reader(output.open(encoding='utf-8-sig')))
    assert len(rows)==2 and rows[1][3].startswith("'=")
    page.search.setText('no match');assert page.table.rowCount()==0
    assert not page.export_button.isEnabled()
    page.refresh();assert page.table.rowCount()==0
    page.db.close()

def test_quarantine_actions_selection_confirmation_and_ids(isolated,app,monkeypatch):
    from core.quarantine import QuarantineManager
    from ui.quarantine import QuarantinePage
    from PySide6.QtWidgets import QMessageBox
    original=isolated/'file';original.write_text('safe fixture')
    QuarantineManager().quarantine(original,'Test')
    page=QuarantinePage()
    assert not page.restore_button.isEnabled()
    page.table.selectRow(0);assert page.restore_button.isEnabled()
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.No)
    page.restore_file();assert not original.exists()
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    page.restore_file();assert original.read_text()=='safe fixture'
    assert page.table.rowCount()==0
    QuarantineManager().quarantine(original,'Test');page.refresh();page.table.selectRow(0)
    page.delete_file();assert page.table.rowCount()==0 and not original.exists()
    page.db.close()

def test_cancel_scan_reports_cancelled(isolated,app,monkeypatch):
    from ui.dashboard import DashboardPage
    from threading import Event
    entered=Event();release=Event()
    folder=isolated/'files';folder.mkdir()
    for name in ('one','two','three'):(folder/name).write_text('fixture')
    def scan(path):
        entered.set();release.wait(2)
        return {'status':'clean','virus':None}
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(scan))
    page=DashboardPage()
    page.start_scan(lambda **kw:page.scan_manager.custom_scan(folder,**kw))
    drain(app,entered.is_set)
    page.cancel_scan();release.set()
    drain(app,lambda:not page.scan_active)
    assert page.last_summary['cancelled'] is True
    assert page.last_summary['scanned']==1
    assert page.scan_state.text()=='Scan cancelled'
    assert page.buttons.isEnabled() and not page.cancel_button.isEnabled()
    page.scan_manager.shutdown();page.db.close()

def test_custom_scan_dialog_and_error_summary(isolated,app,monkeypatch):
    from ui.dashboard import DashboardPage
    from PySide6.QtWidgets import QFileDialog
    folder=isolated/'files';folder.mkdir();(folder/'file').write_text('fixture')
    monkeypatch.setattr(QFileDialog,'getExistingDirectory',lambda *a:str(folder))
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:{'status':'error','virus':'engine unavailable'}))
    page=DashboardPage();page.custom_scan()
    drain(app,lambda:not page.scan_active)
    assert page.last_summary['errors']==1
    assert page.scan_state.text()=='Finished with errors'
    assert 'engine unavailable' in page.error_text.text()
    page.scan_manager.shutdown();page.db.close()

def test_main_window_monitor_setting_controls_observer(isolated,app,monkeypatch):
    from ui.main_window import MainWindow
    from config import load_config
    monkeypatch.setattr(Path,'home',lambda:isolated)
    (isolated/'Downloads').mkdir()
    window=MainWindow();page=window.stack.widget(5)
    try:
        page.realtime.setChecked(True)
        assert window.watcher.observer.is_alive()
        assert not window.watcher.handler.stopping.is_set()
        assert load_config()['realtime']
        page.realtime.setChecked(False)
        assert window.watcher.handler.stopping.is_set()
        assert not load_config()['realtime']
        page.realtime.setChecked(True)
        assert not window.watcher.handler.stopping.is_set()
    finally:
        window.shutdown()

def test_diagnostic_timeout_releases_controls(isolated,app):
    import sys
    from ui.settings import SettingsPage
    page=SettingsPage()
    page.start_check(sys.executable,['-c','import time; time.sleep(10)'],'engine')
    page.check_timer.start(30)
    drain(app,lambda:page.process is None)
    assert 'timed out' in page.check_result.text()
    assert page.engine_button.isEnabled()

def test_watcher_ignores_guardian_storage_and_duplicate_events(isolated,monkeypatch):
    import core.paths as paths
    from core.watcher import GuardianWatcher
    from database.database import GuardianDatabase
    monkeypatch.setattr(paths,'DATABASE_DIR',isolated/'database')
    (isolated/'database').mkdir()
    internal=isolated/'database'/'guardian.db';internal.write_text('history')
    scan=Mock(return_value={'status':'clean','virus':None})
    monkeypatch.setattr('core.watcher.GuardianScanner',lambda:SimpleNamespace(scan_file=scan))
    watcher=GuardianWatcher()
    watcher.scan(internal)
    scan.assert_not_called()
    file=isolated/'download';file.write_text('first')
    watcher.scan(file);watcher.scan(file)
    assert scan.call_count==1
    file.write_text('second version')
    watcher.scan(file)
    assert scan.call_count==2
    db=GuardianDatabase();assert db.get_scan_count()==2;db.close()

def test_worker_skips_database_folder(isolated,monkeypatch,app):
    import core.paths as paths
    from core.scan_worker import ScanWorker
    from test_guardian import engine
    monkeypatch.setattr(paths,'DATABASE_DIR',isolated/'files'/'database')
    (isolated/'files'/'database').mkdir(parents=True)
    (isolated/'files'/'database'/'guardian.db').write_text('history')
    (isolated/'files'/'document').write_text('fixture')
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:{'status':'clean','virus':None}))
    worker=ScanWorker([isolated/'files']);done=[]
    worker.finished.connect(done.append);worker.run()
    assert done==[1]

def fake_clamscan(monkeypatch,code,out='',err='',check=None):
    """Stand in for the streaming clamscan processes; returns the list of command lines."""
    import io
    calls=[]
    def popen(args,stdout=None,stderr=None,**kw):
        if check:check()
        calls.append((args,Path(args[-1].split('=',1)[1]).read_text().splitlines()))
        stderr.write(err.encode())
        return SimpleNamespace(stdout=io.StringIO(out),wait=lambda:code,poll=lambda:code,kill=lambda:None)
    monkeypatch.setattr('core.scanner.subprocess.Popen',popen)
    return calls

def test_cli_batch_parses_each_file_with_one_process(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/name for name in ('clean','a: b','empty','denied','eicar')]
    for file in files:file.write_text('x')
    out='\n'.join([f'{files[0]}: OK',f'{files[1]}: OK',f'{files[2]}: Empty file',f'{files[3]}: Permission denied',f'{files[4]}: Eicar-Test FOUND'])+'\n'
    calls=fake_clamscan(monkeypatch,1,out)
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=None
    results=dict(scanner.scan_files(files+[isolated/'missing']))
    assert [listed for _,listed in calls]==[[str(f) for f in files]]
    assert [results[f]['status'] for f in files]==['clean','clean','clean','error','found']
    assert results[files[4]]['virus']=='Eicar-Test'
    assert results[isolated/'missing']['status']=='error'

def test_cli_batch_never_reports_unlisted_files_clean(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/'one',isolated/'two']
    for file in files:file.write_text('x')
    fake_clamscan(monkeypatch,2,err='No supported database files found\n')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=None
    results=dict(scanner.scan_files(files))
    assert len(results)==2 and all(r=={'status':'error','virus':'No supported database files found'} for r in results.values())

def test_daemon_scans_files_individually(isolated):
    from core.scanner import GuardianScanner
    files=[isolated/'one',isolated/'two']
    for file in files:file.write_text('x')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock()
    scanner.clamd.scan_file.return_value=None
    assert [r['status'] for _,r in scanner.scan_files(files)]==['clean','clean']
    assert scanner.clamd.scan_file.call_count==2

def test_clear_history_requires_confirmation(isolated,app,monkeypatch):
    from ui.history import HistoryPage
    from PySide6.QtWidgets import QMessageBox
    page=HistoryPage();page.db.add_scan('/a','clean');page.refresh()
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.No)
    page.clear_history();assert page.table.rowCount()==1
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    page.clear_history();assert page.table.rowCount()==0
    assert not page.clear_button.isEnabled()
    page.db.close()

def test_login_entry_starts_minimized(isolated):
    from core.startup import set_startup,startup_path
    set_startup(True)
    assert '--minimized' in startup_path().read_text()

@pytest.mark.parametrize('output,expected,attention',[
    ('ClamAV 1.5.4/27500/Tue Oct 20 08:00:00 2026','definitions 27500, updated 2 days ago',False),
    ('ClamAV 1.5.4/27400/Thu Oct  1 08:00:00 2026','out of date',True),
    ('ClamAV 1.5.4','no official signature database',True),
    ('','ClamAV not found',True),
])
def test_definitions_freshness(output,expected,attention):
    from datetime import datetime
    from core.definitions import describe
    text,needs=describe(output,now=datetime(2026,10,22,12,0))
    assert expected in text and needs is attention

def test_watcher_waits_for_writes_and_skips_partial_downloads(isolated,monkeypatch):
    import core.watcher as watcher_module
    from core.watcher import GuardianWatcher
    monkeypatch.setattr(watcher_module,'SETTLE_SECONDS',.2)
    scanned=[]
    monkeypatch.setattr('core.watcher.GuardianScanner',lambda:SimpleNamespace(scan_file=lambda p:scanned.append(p) or {'status':'clean','virus':None}))
    file=isolated/'download.bin';file.write_text('data')
    watcher=GuardianWatcher()
    try:
        for _ in range(5):watcher.queue(file)
        watcher.queue(isolated/'video.mp4.crdownload')
        deadline=time.monotonic()+3
        while not scanned and time.monotonic()<deadline:time.sleep(.02)
        time.sleep(.5)
        assert scanned==[file]
    finally:
        watcher.close()
    assert not watcher.thread.is_alive()

def test_exclusions_apply_to_scans_and_monitoring(isolated,monkeypatch,app):
    from core.scan_worker import ScanWorker
    from core.watcher import GuardianWatcher
    from database.database import GuardianDatabase
    from test_guardian import engine
    folder=isolated/'files';(folder/'vm').mkdir(parents=True)
    (folder/'vm'/'disk.img').write_text('large');(folder/'doc').write_text('fixture')
    db=GuardianDatabase();db.add_exclusion(folder/'vm');db.close()
    scan=Mock(return_value={'status':'clean','virus':None})
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(scan))
    worker=ScanWorker([folder]);done=[]
    worker.finished.connect(done.append);worker.run()
    assert done==[1] and scan.call_args.args[0].name=='doc'
    monkeypatch.setattr('core.watcher.GuardianScanner',lambda:SimpleNamespace(scan_file=scan))
    GuardianWatcher().scan(folder/'vm'/'disk.img')
    assert scan.call_count==1

def test_scan_runs_persist_last_scan_and_duration(isolated,monkeypatch,app):
    from ui.dashboard import DashboardPage
    from test_guardian import engine
    folder=isolated/'files';folder.mkdir();(folder/'file').write_text('fixture')
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine(lambda p:{'status':'clean','virus':None}))
    page=DashboardPage()
    assert page.protection.last_scan.text()=='No scans yet'
    page.start_scan(lambda **kw:page.scan_manager.custom_scan(folder,**kw))
    drain(app,lambda:not page.scan_active)
    assert 'Took' in page.result_text.text()
    page.scan_manager.shutdown();page.db.close()
    reopened=DashboardPage()
    assert reopened.protection.last_scan.text().startswith('Last scan: Custom scan complete')
    reopened.db.close()

def test_scheduled_scan_runs_daily_only_when_enabled(isolated,app):
    from config import load_config,save_config
    from ui.main_window import MainWindow
    window=MainWindow();dash=window.stack.widget(0);dash.quick_scan=Mock()
    try:
        window.run_scheduled_scan();dash.quick_scan.assert_not_called()
        save_config(dict(load_config(),scheduled_scan=True))
        window.run_scheduled_scan();dash.quick_scan.assert_called_once()
        dash.db.add_scan_run('Quick scan',1,0,0,True,1.0)
        window.run_scheduled_scan();dash.quick_scan.assert_called_once()
        dash.db.conn.execute("UPDATE scan_runs SET timestamp='2000-01-01T00:00:00'");dash.db.conn.commit()
        window.run_scheduled_scan();assert dash.quick_scan.call_count==2
    finally:
        window.shutdown()

def test_settings_folder_lists(isolated,app,monkeypatch):
    from ui.settings import SettingsPage
    from PySide6.QtWidgets import QFileDialog
    from database.database import GuardianDatabase
    folder=isolated/'trusted';folder.mkdir()
    monkeypatch.setattr(QFileDialog,'getExistingDirectory',lambda *a:str(folder))
    page=SettingsPage();monitored=Mock();page.monitored_changed.connect(monitored)
    assert page.exclusions.list.item(0).text()=='No folders excluded.'
    assert page.exclusions.folders()==[]
    page.exclusions.add()
    assert page.exclusions.folders()==[str(folder)]
    monitored.assert_not_called()
    page.exclusions.list.setCurrentRow(0);assert page.exclusions.remove_button.isEnabled()
    page.exclusions.remove()
    assert page.exclusions.folders()==[]
    page.monitored.add();assert str(folder) in page.monitored.folders()
    monitored.assert_called_once()
    db=GuardianDatabase();assert str(folder) in db.get_monitored_folders();db.close()

def test_batch_progress_reports_before_engine_runs(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/'one',isolated/'two']
    for file in files:file.write_text('x')
    started=[]
    def check():assert started
    calls=fake_clamscan(monkeypatch,0,check=check)
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=None
    list(scanner.scan_files(files,started=started.append))
    assert started==[files] and len(calls)==1

def test_shutdown_during_running_checks(isolated,app):
    import sys
    from ui.main_window import MainWindow
    window=MainWindow();settings=window.stack.widget(5)
    settings.start_check(sys.executable,['-c','import time; time.sleep(10)'],'engine')
    window.shutdown()
    assert settings.process is None and window.definitions_process is None

def test_large_cli_scans_share_few_processes(isolated,monkeypatch):
    import core.scanner as engine_module
    files=[isolated/f'f{i}' for i in range(7)]
    for file in files:file.write_text('x')
    monkeypatch.setattr(engine_module,'cli_processes',lambda count:3)
    calls=fake_clamscan(monkeypatch,0)
    scanner=engine_module.GuardianScanner.__new__(engine_module.GuardianScanner);scanner.clamd=None
    results=dict(scanner.scan_files(files))
    assert len(calls)==3 and sorted(name for _,listed in calls for name in listed)==sorted(map(str,files))
    assert len(results)==7 and all(r['status']=='clean' for r in results.values())

def test_cli_process_count_respects_size_and_memory(monkeypatch):
    import core.scanner as engine_module
    monkeypatch.setattr(engine_module.os,'cpu_count',lambda:8)
    assert engine_module.cli_processes(10)==1
    assert 1<=engine_module.cli_processes(10**6)<=engine_module.CLI_MAX_PROCESSES

def test_daemon_leaves_unanswered_files_to_one_clamscan(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/f'f{i}' for i in range(6)]
    for file in files:file.write_text('x')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock()
    scanner.clamd.scan_file.side_effect=lambda name:None if name.endswith(('f0','f1')) else {name:('ERROR','Permission denied')}
    calls=fake_clamscan(monkeypatch,0)
    results=dict(scanner.scan_files(files))
    assert len(calls)==1 and sorted(calls[0][1])==[str(f) for f in files[2:]]
    assert all(results[f]['status']=='clean' for f in files)

def test_daemon_gets_a_descriptor_for_files_it_cannot_open(isolated,monkeypatch):
    from core.scanner import GuardianScanner
    files=[isolated/'one',isolated/'two']
    for file in files:file.write_text('x')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock();scanner.socket='/nonexistent'
    scanner.clamd.scan_file.side_effect=lambda name:{name:('ERROR','Permission denied')}
    handed=[]
    monkeypatch.setattr(scanner,'_scan_descriptor',lambda fd:handed.append(fd) or 'Eicar-Test FOUND')
    assert scanner.scan_file(files[0])=={'status':'found','virus':'Eicar-Test'}
    assert scanner.scan_file(files[1])['status']=='found'
    # After the first refusal the path-based request is skipped.
    assert len(handed)==2 and scanner.clamd.scan_file.call_count==1

def test_closing_a_daemon_scan_stops_submitting_files(isolated):
    import core.scanner as engine_module
    files=[isolated/f'f{i}' for i in range(200)]
    for file in files:file.write_text('x')
    scanner=engine_module.GuardianScanner.__new__(engine_module.GuardianScanner);scanner.clamd=Mock()
    scanner.clamd.scan_file.return_value=None
    results=scanner.scan_files(files);next(results);results.close()
    assert scanner.clamd.scan_file.call_count<=2*engine_module.DAEMON_WORKERS

def test_scan_history_is_committed_in_batches(isolated,monkeypatch):
    import core.scan_worker as worker_module
    from database.database import GuardianDatabase
    (isolated/'files').mkdir()
    for i in range(20):(isolated/'files'/f'f{i}').write_text('x')
    commits=[];commit=GuardianDatabase.commit
    monkeypatch.setattr(GuardianDatabase,'commit',lambda self:commits.append(1) or commit(self))
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:SimpleNamespace(scan_files=lambda paths,started=None:((p,{'status':'clean','virus':None}) for p in paths)))
    worker_module.ScanWorker([isolated/'files']).run()
    db=GuardianDatabase();assert db.get_scan_count()==20;db.close()
    assert len(commits)<20

def test_dashboard_shows_whether_the_daemon_is_connected(isolated,app,monkeypatch):
    import config
    import ui.dashboard as dashboard
    found=[None]
    monkeypatch.setattr(dashboard,'daemon_socket',lambda timeout=5:found[0])
    page=dashboard.DashboardPage()
    assert 'daemon not found' in page.protection.engine.text()
    found[0]='/run/clamav/clamd.ctl';page.refresh_dashboard()
    assert page.protection.engine.text()=='Scan engine: ClamAV daemon connected · fast scanning'
    config.save_config(dict(config.load_config(),archives=False));page.refresh_dashboard()
    assert 'not used while Inspect archives is off' in page.protection.engine.text()
    page.db.close()

def test_daemon_socket_returns_first_answering_path(monkeypatch):
    import core.scanner as engine_module
    def client(filename,timeout):
        if filename==engine_module.CLAMD_SOCKETS[0]:raise OSError('missing')
        return SimpleNamespace(ping=lambda:True)
    monkeypatch.setattr(engine_module.pyclamd,'ClamdUnixSocket',client)
    assert engine_module.daemon_socket()==engine_module.CLAMD_SOCKETS[1]
    monkeypatch.setattr(engine_module.pyclamd,'ClamdUnixSocket',Mock(side_effect=OSError))
    assert engine_module.daemon_socket() is None and engine_module.GuardianScanner().clamd is None

def test_scan_survives_file_names_that_are_not_utf8(isolated,monkeypatch):
    import os
    import core.scan_worker as worker_module
    from core.scanner import GuardianScanner
    from database.database import GuardianDatabase
    folder=isolated/'files';folder.mkdir()
    with open(os.fsencode(folder)+b'/bad-\xff.bin','wb') as file:file.write(b'x')
    (folder/'good').write_text('x')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock()
    scanner.clamd.scan_file.return_value=None
    monkeypatch.setattr('core.scanner.subprocess.run',lambda *a,**k:SimpleNamespace(returncode=1,stdout=a[0][-1]+': Eicar-Test FOUND',stderr=''))
    monkeypatch.setattr(worker_module,'GuardianScanner',lambda:scanner)
    worker=worker_module.ScanWorker([folder]);results=[];summary={}
    worker.result.connect(lambda path,status,virus:results.append((Path(path).name,status)));worker.summary.connect(summary.update)
    worker.run()
    # The unnameable file bypasses the daemon's text protocol, and the daemon stays in use.
    assert sorted(results)==[('bad-\ufffd.bin','found'),('good','clean')] and scanner.clamd is not None
    assert summary['scanned']==2 and summary['quarantined']==1 and summary['errors']==0
    assert sorted(os.listdir(os.fsencode(folder)))==[b'good']
    db=GuardianDatabase();assert db.get_scan_count()==2;db.close()

