import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app


def test_choice_settings_are_validated(isolated):
    import config
    config.CONFIG.write_text('{"theme": "neon", "scan_hour": 25, "quarantine_retention_days": 30, "weekly_home_scan": "yes"}')
    settings=config.load_config()
    assert settings['theme']=='system' and settings['scan_hour']==-1
    assert settings['quarantine_retention_days']==30 and settings['weekly_home_scan'] is False
    from core.preferences import apply_preferences
    with pytest.raises(ValueError):
        apply_preferences(dict(settings,theme='neon'))

def test_choice_settings_persist_from_settings_page(isolated,app):
    from config import load_config
    from ui.settings import SettingsPage
    page=SettingsPage()
    page.theme.setCurrentIndex(page.theme.findData('light'))
    page.scan_hour.setCurrentIndex(page.scan_hour.findData(9))
    assert load_config()['theme']=='light' and load_config()['scan_hour']==9
    assert SettingsPage().theme.currentData()=='light'

def test_legacy_data_migrates_once_without_overwriting(tmp_path):
    from core.migrate import migrate_legacy_data
    legacy,target=tmp_path/'checkout',tmp_path/'data'
    (legacy/'database').mkdir(parents=True);(legacy/'quarantine').mkdir()
    (legacy/'database'/'__init__.py').write_text('')
    (legacy/'config.json').write_text('{}')
    (legacy/'quarantine'/'abc.quarantine').write_text('threat')
    conn=sqlite3.connect(legacy/'database'/'guardian.db')
    conn.execute('CREATE TABLE quarantine(id INTEGER PRIMARY KEY, timestamp TEXT, original_path TEXT, quarantine_path TEXT, virus TEXT)')
    conn.execute('INSERT INTO quarantine VALUES (1,?,?,?,?)',('2026-01-01T00:00:00','/home/a',str(legacy/'quarantine'/'abc.quarantine'),'Test'))
    conn.commit();conn.close()
    assert sorted(migrate_legacy_data(legacy,target))==['config.json','database/guardian.db','quarantine']
    assert (legacy/'database'/'__init__.py').exists() and not (legacy/'quarantine').exists()
    assert (target/'quarantine'/'abc.quarantine').read_text()=='threat'
    conn=sqlite3.connect(target/'database'/'guardian.db')
    assert conn.execute('SELECT quarantine_path FROM quarantine').fetchone()[0]==str(target/'quarantine'/'abc.quarantine')
    conn.close()
    (legacy/'config.json').write_text('{"new": true}')
    assert migrate_legacy_data(legacy,target)==[]
    assert (target/'config.json').read_text()=='{}'

def test_quarantined_record_restores_after_migration(tmp_path,monkeypatch):
    import core.quarantine as quarantine
    import database.database as database
    from core.migrate import migrate_legacy_data
    legacy,target=tmp_path/'checkout',tmp_path/'data'
    monkeypatch.setattr(database,'DATABASE',legacy/'database'/'guardian.db')
    monkeypatch.setattr(quarantine,'QUARANTINE',legacy/'quarantine')
    original=tmp_path/'file';original.write_text('fixture')
    quarantine.QuarantineManager().quarantine(original,'Test')
    migrate_legacy_data(legacy,target)
    monkeypatch.setattr(database,'DATABASE',target/'database'/'guardian.db')
    monkeypatch.setattr(quarantine,'QUARANTINE',target/'quarantine')
    db=database.GuardianDatabase();record=db.get_quarantined_files()[0][0];db.close()
    quarantine.QuarantineManager().restore(record)
    assert original.read_text()=='fixture'

def test_default_data_dir_follows_xdg(monkeypatch,tmp_path):
    from core.paths import default_data_dir
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path))
    assert default_data_dir()==tmp_path/'guardian'
    monkeypatch.delenv('XDG_DATA_HOME')
    monkeypatch.setattr(Path,'home',lambda:tmp_path)
    assert default_data_dir()==tmp_path/'.local'/'share'/'guardian'

def test_log_file_written(tmp_path,monkeypatch):
    import core.log as logmodule
    monkeypatch.setattr(logmodule,'LOGS',tmp_path/'logs')
    before=list(logmodule.log.handlers)
    try:
        logmodule.setup_logging();logmodule.setup_logging()
        assert len(logmodule.log.handlers)==len(before)+1
        logmodule.log.info('hello log')
        for handler in logmodule.log.handlers:handler.flush()
        assert 'hello log' in (tmp_path/'logs'/'guardian.log').read_text()
    finally:
        for handler in logmodule.log.handlers[len(before):]:
            handler.close();logmodule.log.removeHandler(handler)

def test_log_folder_is_guardian_storage():
    from core.paths import LOGS,is_guardian_storage
    assert is_guardian_storage(LOGS/'guardian.log')

def test_restore_original_permissions_is_opt_in(isolated):
    from core.quarantine import QuarantineManager
    from database.database import GuardianDatabase
    file=isolated/'tool';file.write_text('#!/bin/sh');file.chmod(0o4755)
    manager=QuarantineManager()
    for keep,expected in ((False,0o600),(True,0o755)):
        manager.quarantine(file,'Test')
        db=GuardianDatabase();record=db.get_quarantined_files()[0][0];db.close()
        manager.restore(record,original_mode=keep)
        assert file.stat().st_mode & 0o7777==expected
        file.chmod(0o4755)

def test_purge_and_disk_usage(isolated):
    from core.quarantine import QuarantineManager
    from database.database import GuardianDatabase
    manager=QuarantineManager()
    for name in ('old','new'):
        f=isolated/name;f.write_text('x'*10);manager.quarantine(f,'Test')
    db=GuardianDatabase()
    db.conn.execute("UPDATE quarantine SET timestamp='2000-01-01T00:00:00' WHERE original_path LIKE '%old'");db.conn.commit()
    assert manager.disk_usage()==20
    assert manager.purge_older_than(0)==0
    assert manager.purge_older_than(30)==1
    assert [r[2] for r in db.get_quarantined_files()]==[str(isolated/'new')]
    assert manager.disk_usage()==10
    db.close()

def test_quarantine_page_usage_and_permission_option(isolated,app,monkeypatch):
    from core.quarantine import QuarantineManager
    from ui.quarantine import QuarantinePage,format_size
    from PySide6.QtWidgets import QMessageBox
    f=isolated/'tool';f.write_text('abc');f.chmod(0o755);QuarantineManager().quarantine(f,'Test')
    page=QuarantinePage()
    assert page.usage.text()=='1 file in quarantine · 3 bytes on disk'
    assert format_size(5*1024*1024)=='5.0 MB'
    monkeypatch.setattr(QMessageBox,'question',lambda *a:QMessageBox.StandardButton.Yes)
    page.keep_mode.setChecked(True);page.table.selectRow(0);page.restore_file()
    assert f.stat().st_mode & 0o777==0o755
    page.db.close()

@pytest.mark.parametrize('last,days,hour,now,due',[
    (None,1,-1,'2026-10-22T08:00',True),
    ('2026-10-21T09:00',1,-1,'2026-10-22T08:00',False),
    ('2026-10-21T07:00',1,-1,'2026-10-22T08:00',True),
    ('2026-10-21T20:00',1,9,'2026-10-22T08:00',False),
    ('2026-10-21T20:00',1,9,'2026-10-22T09:30',True),
    ('2026-10-22T09:05',1,9,'2026-10-22T15:00',False),
    ('2026-10-16T10:00',7,9,'2026-10-22T09:30',False),
    ('2026-10-15T10:00',7,9,'2026-10-22T09:30',True),
])
def test_scan_due(last,days,hour,now,due):
    from ui.main_window import scan_due
    run=(last+':00',) if last else None
    assert scan_due(run,days,hour,datetime.fromisoformat(now))==due

def test_scheduler_runs_weekly_home_scan_and_purges(isolated,app):
    from config import load_config,save_config
    from core.quarantine import QuarantineManager
    from ui.main_window import MainWindow
    f=isolated/'old';f.write_text('x');QuarantineManager().quarantine(f,'Test')
    window=MainWindow();dash=window.stack.widget(0);dash.quick_scan=Mock();dash.full_scan=Mock()
    try:
        dash.db.conn.execute("UPDATE quarantine SET timestamp='2000-01-01T00:00:00'");dash.db.conn.commit()
        save_config(dict(load_config(),weekly_home_scan=True,scan_hour=9,quarantine_retention_days=90))
        window.run_scheduled_scan(now=datetime(2026,10,22,8,0))
        dash.full_scan.assert_not_called()
        assert dash.db.get_quarantine_count()==0
        window.run_scheduled_scan(now=datetime(2026,10,22,9,1))
        dash.full_scan.assert_called_once();dash.quick_scan.assert_not_called()
    finally:
        window.shutdown()

def test_theme_resolution_and_switching(isolated,app):
    from config import load_config,save_config
    from ui.theme import apply_theme,resolve
    from ui.main_window import MainWindow
    assert resolve(app,'light')=='light' and resolve(app,'dark')=='dark'
    assert resolve(app,'system') in ('light','dark')
    assert apply_theme(app,'dark')=='dark' and 'QWidget' in app.styleSheet()
    window=MainWindow();settings=window.stack.widget(5)
    try:
        settings.theme.setCurrentIndex(settings.theme.findData('light'))
        assert app.property('guardianTheme')=='light' and '#f4f6fa' in app.styleSheet()
    finally:
        window.shutdown();app.setStyleSheet('')

def test_light_theme_styles_every_dark_selector():
    from core.paths import ROOT
    def selectors(name):
        return {line.split('{')[0].strip() for line in (ROOT/'assets'/'themes'/name).read_text().splitlines() if '{' in line}
    assert selectors('dark.qss')<=selectors('light.qss')

def test_keyboard_shortcuts(isolated,app):
    from PySide6.QtGui import QShortcut
    from ui.main_window import MainWindow
    window=MainWindow()
    try:
        keys={s.key().toString() for s in window.findChildren(QShortcut)}
        assert {'Ctrl+1','Ctrl+2','Ctrl+3','Ctrl+4','Ctrl+F','F5','Ctrl+Q','Del'}<=keys
        for shortcut in window.findChildren(QShortcut):
            if shortcut.key().toString()=='Ctrl+3':shortcut.activated.emit()
        assert window.stack.currentIndex()==4
        window.show();window.focus_search();app.processEvents()
        assert window.stack.widget(4).search.hasFocus()
    finally:
        window.shutdown()

def test_onaccess_status_and_steps(tmp_path):
    from core import onaccess
    proc=tmp_path/'proc';(proc/'42').mkdir(parents=True);(proc/'42'/'comm').write_text('bash\n')
    (proc/'self').mkdir()
    conf=tmp_path/'clamd.conf'
    conf.write_text('User clamav\n# OnAccessPrevention yes\nOnAccessIncludePath /home/me/Downloads\n')
    state=onaccess.status(proc,[str(tmp_path/'missing.conf'),str(conf)])
    assert state=={'running':False,'config':str(conf),'prevention':False,'paths':['/home/me/Downloads'],'user':'clamav'}
    assert onaccess.describe(state)[0].startswith('Not active')
    (proc/'42'/'comm').write_text('clamonacc\n')
    state=onaccess.status(proc,[str(conf)])
    assert onaccess.describe(state)==('Active in notify-only mode for: /home/me/Downloads. Set OnAccessPrevention yes to block files.',True)
    conf.write_text(conf.read_text()+'OnAccessPrevention yes\n')
    assert onaccess.describe(onaccess.status(proc,[str(conf)]))[1] is False
    steps=onaccess.setup_steps(['/home/me/Downloads','/home/me/Desktop'],state)
    assert 'OnAccessIncludePath /home/me/Desktop' in steps and 'OnAccessExcludeUname clamav' in steps
    assert 'sudo systemctl restart clamav-daemon' in steps
    assert 'clamd@scan' in onaccess.setup_steps([],dict(state,config='/etc/clamd.d/scan.conf'))

def test_settings_onaccess_dialog(isolated,app):
    from PySide6.QtWidgets import QApplication
    from ui.settings import SettingsPage
    page=SettingsPage()
    assert page.onaccess_status.text()
    page.show_onaccess_steps()
    page.steps_dialog.findChildren(type(page.engine_button))[0].click()
    assert 'OnAccessPrevention yes' in QApplication.clipboard().text()
    page.steps_dialog.close()

def test_menu_entry_install_and_remove(isolated,monkeypatch):
    from core.startup import menu_entry_path,set_menu_entry,ICON
    monkeypatch.setenv('XDG_DATA_HOME',str(isolated/'share'))
    entry=set_menu_entry(True)
    assert entry==menu_entry_path()==isolated/'share'/'applications'/'guardian.desktop'
    text=entry.read_text()
    assert f'Icon={ICON}' in text and '--minimized' not in text and 'Categories=System;Security;' in text
    set_menu_entry(False);assert not entry.exists()
    assert ICON.exists()

def test_help_option(monkeypatch,capsys):
    import sys
    import guardian
    monkeypatch.setattr(sys,'argv',['guardian','--help'])
    monkeypatch.setattr(guardian,'setup_logging',lambda:None)
    monkeypatch.setenv('GUARDIAN_DATA_DIR','/unused')
    assert guardian.main()==0
    assert '--scan' in capsys.readouterr().out

@pytest.mark.parametrize('theme',['dark','light'])
def test_pages_fit_minimum_window_without_sideways_scrolling(isolated,app,theme):
    from ui.theme import apply_theme
    from ui.main_window import MainWindow
    apply_theme(app,theme)
    window=MainWindow();window.resize(window.minimumSize());window.show()
    try:
        for row in (0,3,4,5):
            window.sidebar.setCurrentRow(row);app.processEvents()
            assert window.stack.currentWidget().horizontalScrollBar().maximum()==0,row
    finally:
        window.shutdown();app.setStyleSheet('')
