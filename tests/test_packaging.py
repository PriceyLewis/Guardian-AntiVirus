import io
import sys
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from test_guardian import isolated, app
from test_features import fake_clamscan


@pytest.fixture
def flatpak(isolated,monkeypatch):
    """Pretend to run inside the Flatpak: Guardian keeps its own definitions."""
    monkeypatch.setenv('FLATPAK_ID','io.github.priceylewis.Guardian')
    monkeypatch.delenv('GUARDIAN_CLAMAV_DB',raising=False)
    import core.paths as paths
    monkeypatch.setattr(paths,'DATA',isolated/'data');(isolated/'data'/'clamav').mkdir(parents=True)
    return isolated/'data'/'clamav'

def test_system_clamav_is_used_outside_a_flatpak(isolated,monkeypatch):
    from core import clamav
    monkeypatch.delenv('FLATPAK_ID',raising=False);monkeypatch.delenv('GUARDIAN_CLAMAV_DB',raising=False)
    assert clamav.private_database() is None and clamav.scan_args()==[]
    assert clamav.version_command()==['clamscan','--version'] and clamav.freshclam_command()==['freshclam','--stdout']
    assert clamav.database_dirs()==('/var/lib/clamav',) and not clamav.definitions_due()

def test_flatpak_keeps_private_definitions(flatpak):
    from core import clamav
    assert clamav.private_database()==flatpak and clamav.scan_args()==['--database='+str(flatpak)]
    assert clamav.version_command()==['clamscan','--version','--database='+str(flatpak)]
    command=clamav.freshclam_command()
    config=flatpak/'freshclam.conf'
    assert command==['freshclam','--stdout','--config-file='+str(config),'--datadir='+str(flatpak)]
    assert f'DatabaseDirectory {flatpak}' in config.read_text() and 'DatabaseMirror database.clamav.net' in config.read_text()
    assert clamav.definitions_due() and not clamav.has_definitions()
    (flatpak/'daily.cvd').write_text('x')
    assert clamav.has_definitions() and not clamav.definitions_due()
    assert clamav.definitions_due(time.time()+2*clamav.UPDATE_INTERVAL)

def test_custom_database_folder_from_environment(isolated,monkeypatch):
    from core import clamav
    monkeypatch.setenv('GUARDIAN_CLAMAV_DB',str(isolated/'db'))
    assert clamav.private_database()==isolated/'db' and clamav.database_dirs()==(str(isolated/'db'),)

def test_scans_use_private_definitions_and_never_the_host_daemon(flatpak,monkeypatch):
    import core.scanner as engine_module
    probed=[];monkeypatch.setattr(engine_module.pyclamd,'ClamdUnixSocket',lambda **kw:probed.append(kw) or SimpleNamespace(ping=lambda:True))
    assert engine_module.daemon_socket() is None and probed==[]
    files=[flatpak.parent/'a',flatpak.parent/'b']
    for file in files:file.write_text('x')
    calls=fake_clamscan(monkeypatch,0)
    scanner=engine_module.GuardianScanner()
    assert scanner.clamd is None and len(dict(scanner.scan_files(files)))==2
    assert '--database='+str(flatpak) in calls[0][0]
    single=Mock(return_value=SimpleNamespace(returncode=0,stdout='',stderr=''));monkeypatch.setattr(engine_module.subprocess,'run',single)
    scanner.scan_file(files[0]);assert '--database='+str(flatpak) in single.call_args.args[0]
    assert engine_module.describe_engine(False,True).startswith('Scan engine: ClamAV built into Guardian')

def test_definitions_advice_matches_who_maintains_them():
    from core.definitions import describe
    assert 'Run freshclam' in describe('ClamAV 1.5.4',managed=False)[0]
    text,attention=describe('ClamAV 1.5.4',managed=True);assert attention and 'Guardian is downloading them' in text
    old='ClamAV 1.5.4/27000/Tue Oct 21 08:23:45 2025'
    assert 'FreshClam is running' in describe(old,managed=False)[0] and 'Update definitions in Settings' in describe(old,managed=True)[0]

def test_flatpak_window_fetches_definitions_and_hides_daemon_setup(flatpak,app,monkeypatch):
    import ui.main_window as main_window
    window=main_window.MainWindow()
    try:
        settings=window.stack.widget(5);updates=[]
        monkeypatch.setattr(settings,'update_definitions',lambda:updates.append(1))
        monkeypatch.setattr(settings,'update_threat_lists',lambda:None)
        window.housekeeping();assert updates==[1]
        (flatpak/'daily.cvd').write_text('x');window.housekeeping();assert updates==[1]
        dashboard=window.stack.widget(0);dashboard.daemon_checked=-99;dashboard.refresh_dashboard()
        assert dashboard.daemon_button.isHidden() and 'built into Guardian' in dashboard.protection.engine.text()
    finally:
        window.shutdown()

def test_flatpak_update_failure_advice(flatpak,app):
    from ui.settings import SettingsPage
    page=SettingsPage()
    text=page.update_result(False,'ERROR: Thu Nov 12 19:57:59 2026 -> Database update process failed: HTTP GET failed')
    assert 'Check your internet connection' in text and 'sudo' not in text
    page.shutdown()

def test_flatpak_autostart_runs_through_flatpak(flatpak,monkeypatch):
    from core import startup
    entry=startup.desktop_entry('--minimized')
    assert 'Exec=flatpak run "io.github.priceylewis.Guardian" --minimized' in entry and 'Icon=io.github.priceylewis.Guardian' in entry
    with pytest.raises(RuntimeError):startup.set_menu_entry(True)
    monkeypatch.setenv('XDG_CONFIG_HOME','/sandbox/config')
    assert startup.startup_path()==Path.home()/'.config'/'autostart'/'io.github.priceylewis.Guardian.desktop'

def test_cli_updates_definitions(flatpak,monkeypatch):
    from core import cli
    ran=[];monkeypatch.setattr('subprocess.run',lambda args,**kw:ran.append(args) or SimpleNamespace(returncode=0))
    assert cli.update_definitions(io.StringIO())==0 and ran[0][0]=='freshclam' and '--datadir='+str(flatpak) in ran[0]
    def missing(*a,**k):raise FileNotFoundError('freshclam')
    monkeypatch.setattr('subprocess.run',missing);out=io.StringIO()
    assert cli.update_definitions(out)==2 and 'Could not run freshclam' in out.getvalue()


def release_json(tag,**extra):
    import json
    return json.dumps(dict(tag_name=tag,html_url='https://github.com/PriceyLewis/Guardian-AntiVirus/releases/tag/'+tag,draft=False,prerelease=False,**extra)).encode()

def test_version_matches_the_package():
    import re
    from core.version import VERSION
    toml=(Path(__file__).resolve().parents[1]/'pyproject.toml').read_text()
    assert re.search(r'^version = "([^"]+)"',toml,re.M).group(1)==VERSION

def test_release_check_compares_versions_and_survives_errors(isolated,monkeypatch):
    import core.paths as paths
    from core import updates
    monkeypatch.setattr(paths,'DATA',isolated/'data')
    assert updates.parse('v1.10.0')>updates.parse('1.9.3') and updates.parse('1.2')==(1,2,0) and updates.parse('nightly') is None
    assert updates.due()
    found=updates.check(lambda url:release_json('v9.0.0'))
    assert found=={'version':'9.0.0','tag':'v9.0.0','url':'https://github.com/PriceyLewis/Guardian-AntiVirus/releases/tag/v9.0.0'}
    assert not updates.due() and updates.due(time.time()+2*updates.CHECK_INTERVAL)
    assert updates.check(lambda url:release_json('v'+updates.VERSION)) is None
    assert updates.check(lambda url:release_json('v0.9.0')) is None
    assert updates.check(lambda url:release_json('v9.0.0',prerelease=True)) is None
    def offline(url):raise OSError('no network')
    assert updates.check(offline) is None
    assert updates.check(lambda url:b'<html>rate limited</html>') is None

def test_install_kind_and_update_command(isolated,monkeypatch):
    import sys
    from core import updates
    import core.paths as paths
    monkeypatch.delenv('FLATPAK_ID',raising=False)
    monkeypatch.setattr(paths,'ROOT',isolated)
    monkeypatch.setattr(sys,'prefix',str(isolated));monkeypatch.setattr(sys,'base_prefix','/usr')
    assert updates.install_kind()=='environment'
    (isolated/'.git').mkdir();assert updates.install_kind()=='checkout'
    monkeypatch.setenv('FLATPAK_ID','io.github.priceylewis.Guardian');assert updates.install_kind()=='flatpak'
    assert 'flatpak update' in updates.how_to_update('flatpak') and updates.how_to_update('environment')==''
    command=updates.update_command({'tag':'v9.0.0','version':'9.0.0'},with_yara=True)
    assert command[:5]==[sys.executable,'-m','pip','install','--upgrade']
    assert command[-1]=='guardian-antivirus[yara] @ https://github.com/PriceyLewis/Guardian-AntiVirus/archive/refs/tags/v9.0.0.tar.gz'
    assert updates.update_command({'tag':'v9.0.0','version':'9.0.0'},with_yara=False)[-1].startswith('guardian-antivirus @ ')

def test_dashboard_offers_and_installs_an_update(isolated,app,monkeypatch):
    import ui.dashboard as dashboard
    from core import updates
    page=dashboard.DashboardPage()
    release={'version':'9.0.0','tag':'v9.0.0','url':'https://example.invalid/notes'}
    monkeypatch.setattr(updates,'install_kind',lambda:'environment')
    assert page.update_card.isHidden()
    page.show_update(release)
    assert not page.update_card.isHidden() and page.update_text.text()=='Guardian 9.0.0 is available' and not page.update_button.isHidden()
    started=[]
    monkeypatch.setattr(updates,'update_command',lambda release:[sys.executable,'-c','print("installed")'])
    page.install_update()
    deadline=time.monotonic()+10
    while page.update_process is not None and time.monotonic()<deadline:app.processEvents()
    assert page.update_text.text()=='Guardian 9.0.0 is installed' and not page.restart_button.isHidden() and page.update_button.isHidden()
    page.show_update(release)
    monkeypatch.setattr(updates,'update_command',lambda release:[sys.executable,'-c','import sys; print("ERROR: no matching distribution"); sys.exit(1)'])
    page.install_update()
    deadline=time.monotonic()+10
    while page.update_process is not None and time.monotonic()<deadline:app.processEvents()
    assert 'The update failed: ERROR: no matching distribution' in page.update_detail.text() and page.update_button.isEnabled()
    monkeypatch.setattr(updates,'install_kind',lambda:'flatpak');page.show_update(release)
    assert page.update_button.isHidden() and 'flatpak update' in page.update_detail.text()
    opened=[];monkeypatch.setattr(dashboard,'open_in_browser',opened.append);page.open_release_notes()
    assert opened==['https://example.invalid/notes']
    page.db.close()

def test_update_check_respects_the_setting_and_runs_in_the_background(isolated,app,monkeypatch):
    import config
    import ui.dashboard as dashboard
    from core import updates
    page=dashboard.DashboardPage()
    calls=[];monkeypatch.setattr(updates,'check',lambda:calls.append(1) or {'version':'9.0.0','tag':'v9.0.0','url':'u'})
    monkeypatch.setattr(updates,'due',lambda:True);monkeypatch.setattr(updates,'install_kind',lambda:'environment')
    page.check_for_updates();assert calls==[]
    config.save_config(dict(config.load_config(),check_updates=True))
    page.check_for_updates();page.update_thread.join()
    deadline=time.monotonic()+5
    while page.update_card.isHidden() and time.monotonic()<deadline:app.processEvents()
    assert calls==[1] and not page.update_card.isHidden()
    page.db.close()
