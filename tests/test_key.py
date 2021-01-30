#!/usr/bin/env python3

import ffpass
from pathlib import Path
import pytest

TEST_KEY = b'\xbfh\x13\x1a\xda\xb5\x9d\xe3X\x10\xe0\xa8\x8a\xc2\xe5\xbcE\xf2I\r\xa2pm\xf4'
MASTER_PASSWORD = 'test'


def test_firefox_key():
    key = ffpass.getKey(Path('tests/firefox-84'))
    assert key == TEST_KEY


def test_firefox_mp_key():
    key = ffpass.getKey(Path('tests/firefox-mp-84'), MASTER_PASSWORD)
    assert key == TEST_KEY


def test_firefox_wrong_masterpassword_key():
    with pytest.raises(ffpass.WrongPassword):
        ffpass.getKey(Path('tests/firefox-mp-84'), 'wrongpassword')


def test_legacy_firefox_key():
    key = ffpass.getKey(Path('tests/firefox-70'))
    assert key == TEST_KEY


def test_legacy_firefox_mp_key():
    key = ffpass.getKey(Path('tests/firefox-mp-70'), MASTER_PASSWORD)
    assert key == TEST_KEY


def test_legacy_firefox_wrong_masterpassword_key():
    with pytest.raises(ffpass.WrongPassword):
        ffpass.getKey(Path('tests/firefox-mp-70'), 'wrongpassword')
