import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import threading
import pytest

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    import config
    import database.database as database
    import core.quarantine as quarantine
    import core.scan_worker as worker
    import core.watcher as watcher
    monkeypatch.setattr(config, 'CONFIG', tmp_path / 'config.json')
    monkeypatch.setattr(database, 'DATABASE', tmp_path / 'db.sqlite')
    for module in (quarantine, worker, watcher):
        monkeypatch.setattr(module, 'QUARANTINE', tmp_path / 'quarantine')
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    config.save_config(dict(config.DEFAULTS, realtime=False, notifications=False))
    return tmp_path

@pytest.fixture(scope='session')
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])

@pytest.mark.parametrize('status,expected', [('FOUND','found'), ('OK','clean'), ('ERROR','error')])
def test_daemon_status(isolated, monkeypatch, status, expected):
    from core.scanner import GuardianScanner
    file = isolated / 'sample'; file.write_text('test')
    scanner = GuardianScanner.__new__(GuardianScanner)
    scanner.clamd = Mock()
    scanner.clamd.scan_file.return_value = {str(file):(status,'detail')}
    monkeypatch.setattr('core.scanner.subprocess.run', lambda *a,**k: SimpleNamespace(returncode=2,stdout='',stderr='access denied'))
    assert scanner.scan_file(file)['status'] == expected

@pytest.mark.parametrize('code,output,expected', [(0,'file: OK','clean'),(1,'file: Test FOUND','found'),(2,'FOUND in filename','error')])
def test_cli_status(isolated, monkeypatch, code, output, expected):
    from core.scanner import GuardianScanner
    file=isolated/'sample';file.write_text('test')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=None
    monkeypatch.setattr('core.scanner.subprocess.run', lambda *a,**k:SimpleNamespace(returncode=code,stdout=output,stderr=''))
    assert scanner.scan_file(file)['status']==expected

def test_archives_setting(isolated, monkeypatch):
    import config
    from core.scanner import GuardianScanner
    config.save_config(dict(config.DEFAULTS, archives=False))
    file=isolated/'sample';file.write_text('test')
    scanner=GuardianScanner.__new__(GuardianScanner);scanner.clamd=Mock()
    run=Mock(return_value=SimpleNamespace(returncode=0,stdout='',stderr=''))
    monkeypatch.setattr('core.scanner.subprocess.run',run)
    scanner.scan_file(file)
    assert '--scan-archive=no' in run.call_args.args[0]
    scanner.clamd.scan_file.assert_not_called()

def test_quarantine_restore_and_collision(isolated):
    from core.quarantine import QuarantineManager
    from database.database import GuardianDatabase
    file=isolated/'sample';file.write_text('test')
    manager=QuarantineManager();path=manager.quarantine(file,'Test')
    assert not file.exists() and path.read_text()=='test'
    assert path.stat().st_mode & 0o777 == 0o600
    db=GuardianDatabase();record=db.get_quarantined_files()[0][0]
    file.write_text('replacement')
    with pytest.raises(FileExistsError):manager.restore(record)
    assert file.read_text()=='replacement' and path.exists()
    file.unlink();manager.restore(record)
    assert file.read_text()=='test' and not db.get_quarantined_files()
    db.close()

def test_quarantine_delete_and_path_validation(isolated):
    from core.quarantine import QuarantineManager
    from database.database import GuardianDatabase
    file=isolated/'sample';file.write_text('test')
    manager=QuarantineManager();path=manager.quarantine(file)
    db=GuardianDatabase();manager.delete(db.get_quarantined_files()[0][0])
    assert not path.exists()
    outside=isolated/'outside';outside.write_text('keep')
    db.add_quarantine('original',str(outside),'Test')
    with pytest.raises(ValueError):manager.delete(db.get_quarantined_files()[0][0])
    assert outside.read_text()=='keep'
    db.close()

def test_worker_completes_on_error(isolated, monkeypatch, app):
    from core.scan_worker import ScanWorker
    monkeypatch.setattr('core.scan_worker.GuardianScanner',Mock(side_effect=RuntimeError('missing engine')))
    worker=ScanWorker([isolated]);done=[];errors=[]
    worker.finished.connect(done.append);worker.error.connect(errors.append)
    worker.run()
    assert done==[0] and errors==['missing engine']

def test_worker_quarantines_and_excludes_storage(isolated,monkeypatch,app):
    from core.scan_worker import ScanWorker
    from database.database import GuardianDatabase
    folder=isolated/'files';folder.mkdir();(folder/'sample').write_text('test')
    engine=Mock();engine.scan_file.return_value={'status':'found','virus':'Test'}
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:engine)
    worker=ScanWorker([folder,folder,isolated/'quarantine']);done=[]
    worker.finished.connect(done.append);worker.run()
    assert done==[1]
    db=GuardianDatabase();assert db.get_quarantine_count()==1;db.close()

def test_watcher_database_thread(isolated,monkeypatch):
    from core.watcher import GuardianWatcher
    from database.database import GuardianDatabase
    file=isolated/'sample';file.write_text('test')
    monkeypatch.setattr('core.watcher.GuardianScanner',lambda:SimpleNamespace(scan_file=lambda p:{'status':'clean','virus':None}))
    watcher=GuardianWatcher()
    thread=threading.Thread(target=watcher.scan,args=(file,));thread.start();thread.join()
    assert watcher.last_error is None
    db=GuardianDatabase();assert db.get_scan_count()==1;db.close()

def test_config_validation(isolated):
    import config
    config.CONFIG.write_text('{"realtime": "false", "notifications": false}')
    assert config.load_config()['realtime'] is True
    assert config.load_config()['notifications'] is False
    config.CONFIG.write_text('broken')
    assert config.load_config()==config.DEFAULTS

def test_startup(isolated):
    from core.startup import set_startup
    path=isolated/'config/autostart/guardian.desktop'
    set_startup(True);assert 'guardian.py' in path.read_text()
    set_startup(False);assert not path.exists()

def test_notification_missing_binary(monkeypatch):
    from core.notifier import GuardianNotifier
    monkeypatch.setattr(GuardianNotifier,'notifications_enabled',lambda:True)
    monkeypatch.setattr('core.notifier.subprocess.run',Mock(side_effect=FileNotFoundError))
    GuardianNotifier.notify('title','message')

def test_ui_navigation_settings_and_shutdown(isolated,monkeypatch,app):
    import guardian
    from ui.main_window import MainWindow
    window=MainWindow()
    dash=window.stack.widget(0)
    dash.quick_scan=Mock();dash.full_scan=Mock()
    window.sidebar.setCurrentRow(1);dash.quick_scan.assert_called_once()
    window.sidebar.setCurrentRow(2);dash.full_scan.assert_called_once()
    window.sidebar.setCurrentRow(3);assert window.stack.currentIndex()==3
    settings=window.stack.widget(5)
    settings.startup.setChecked(True)
    assert (isolated/'config/autostart/guardian.desktop').exists()
    assert 'off' in dash.protection.status.text().lower()
    window.show();app.processEvents()
    window.grab().save('/tmp/guardian-review.png')
    window.shutdown();window.allow_close=True;window.close()

def test_scan_thread_and_duplicate_guard(isolated,monkeypatch,app):
    import time
    from core.scan_manager import ScanManager
    folder=isolated/'files';folder.mkdir();(folder/'file').write_text('test')
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:SimpleNamespace(scan_file=lambda p:{'status':'clean','virus':None}))
    manager=ScanManager()
    assert manager.start_scan([folder]) is True
    assert manager.start_scan([folder]) is False
    deadline=time.monotonic()+5
    while manager.thread.isRunning() and time.monotonic()<deadline:
        app.processEvents();time.sleep(.01)
    assert not manager.thread.isRunning()
    manager.shutdown()
