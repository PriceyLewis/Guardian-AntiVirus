import csv
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app


def drain(app, predicate, timeout=3):
    deadline=time.monotonic()+timeout
    while not predicate() and time.monotonic()<deadline:
        app.processEvents()
        time.sleep(.005)
    assert predicate()

@pytest.mark.parametrize('key', ['realtime','archives','notifications','startup','close_to_tray'])
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
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:SimpleNamespace(scan_file=scan))
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
    monkeypatch.setattr('core.scan_worker.GuardianScanner',lambda:SimpleNamespace(scan_file=lambda p:{'status':'error','virus':'engine unavailable'}))
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
