#!/usr/bin/env python3

import subprocess

MASTER_PASSWORD = 'test'
HEADER = 'url,username,password\n'
IMPORT_CREDENTIAL = 'http://www.example.com,foo,bar\n'
EXPECTED_EXPORT_OUTPUT = f'{HEADER}http://www.stealmylogin.com,test,test\n'
EXPECTED_IMPORT_OUTPUT = EXPECTED_EXPORT_OUTPUT + IMPORT_CREDENTIAL


def run_ffpass(mode, path):
    command = ["ffpass", mode, "-d", path]
    if mode == 'import':
        ffpass_input = HEADER + IMPORT_CREDENTIAL
    else:
        ffpass_input = None

    return subprocess.run(command, stdout=subprocess.PIPE, input=ffpass_input, encoding='utf-8')


def test_legacy_firefox_export():
    r = run_ffpass('export', 'tests/firefox-70')
    r.check_returncode()
    assert r.stdout == EXPECTED_EXPORT_OUTPUT


def test_firefox_export():
    r = run_ffpass('export', 'tests/firefox-84')
    r.check_returncode()
    assert r.stdout == EXPECTED_EXPORT_OUTPUT


def test_legacy_firefox():
    r = run_ffpass('import', 'tests/firefox-70')
    r.check_returncode()

    r = run_ffpass('export', 'tests/firefox-70')
    r.check_returncode()
    assert r.stdout == EXPECTED_IMPORT_OUTPUT


def test_firefox():
    r = run_ffpass('import', 'tests/firefox-84')
    r.check_returncode()

    r = run_ffpass('export', 'tests/firefox-84')
    r.check_returncode()
    assert r.stdout == EXPECTED_IMPORT_OUTPUT
