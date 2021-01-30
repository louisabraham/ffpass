#!/usr/bin/env python3
"""
The MIT License (MIT)
Copyright (c) 2018 Louis Abraham <louis.abraham@yahoo.fr>

\x1B[34m\033[F\033[F

ffpass can import and export passwords from Firefox Quantum.

\x1B[0m\033[1m\033[F\033[F

example of usage:
    ffpass export --file passwords.csv

    ffpass import --file passwords.csv

\033[0m\033[1;32m\033[F\033[F

If you found this code useful, add a star on <https://github.com/louisabraham/ffpass>!

\033[0m\033[F\033[F
"""

import sys
from base64 import b64decode, b64encode
from hashlib import sha1, pbkdf2_hmac
import hmac
import argparse
import json
from pathlib import Path
import csv
import secrets
from getpass import getpass
from uuid import uuid4
from datetime import datetime
from urllib.parse import urlparse
import sqlite3
import os.path
import logging

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import Sequence, OctetString, ObjectIdentifier
from Crypto.Cipher import AES, DES3


MAGIC1 = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

# des-ede3-cbc
MAGIC2 = (1, 2, 840, 113_549, 3, 7)

# pkcs-12-PBEWithSha1AndTripleDESCBC
MAGIC3 = (1, 2, 840, 113_549, 1, 12, 5, 1, 3)


class NoDatabase(Exception):
    pass


class WrongPassword(Exception):
    pass


class NoProfile(Exception):
    pass


def getKey(directory: Path, masterPassword=""):
    dbfile: Path = directory / "key4.db"

    if not dbfile.exists():
        raise NoDatabase()

    conn = sqlite3.connect(dbfile.as_posix())
    c = conn.cursor()
    c.execute("""
        SELECT item1, item2
        FROM metadata
        WHERE id = 'password';
    """)
    row = next(c)
    globalSalt, item2 = row

    try:
        decodedItem2, _ = der_decode(item2)
        encryption_method = '3DES'
        entrySalt = decodedItem2[0][1][0].asOctets()
        cipherT = decodedItem2[1].asOctets()
        clearText = decrypt3DES(
            globalSalt, masterPassword, entrySalt, cipherT
        )  # usual Mozilla PBE
    except AttributeError:
        encryption_method = 'AES'
        decodedItem2 = der_decode(item2)
        clearText = decrypt_aes(decodedItem2, masterPassword, globalSalt)

    if clearText != b"password-check\x02\x02":
        raise WrongPassword()

    logging.info("password checked")

    # decrypt 3des key to decrypt "logins.json" content
    c.execute("""
        SELECT a11, a102
        FROM nssPrivate
        WHERE a102 = ?;
    """, (MAGIC1,))
    try:
        row = next(c)
        a11, a102 = row  # CKA_ID
    except StopIteration:
        raise Exception(
            "The Firefox database appears to be broken. Try to add a password to rebuild it."
        )  # CKA_ID

    if encryption_method == 'AES':
        decodedA11 = der_decode(a11)
        key = decrypt_aes(decodedA11, masterPassword, globalSalt)
    elif encryption_method == '3DES':
        decodedA11, _ = der_decode(a11)
        oid = decodedA11[0][0].asTuple()
        assert oid == MAGIC3, f"The key is encoded with an unknown format {oid}"
        entrySalt = decodedA11[0][1][0].asOctets()
        cipherT = decodedA11[1].asOctets()
        key = decrypt3DES(globalSalt, masterPassword, entrySalt, cipherT)

    logging.info("{}: {}".format(encryption_method, key.hex()))
    return key[:24]


def PKCS7pad(b):
    l = (-len(b) - 1) % 8 + 1
    return b + bytes([l] * l)


def PKCS7unpad(b):
    return b[: -b[-1]]


def decrypt_aes(decoded_item, master_password, global_salt):
    entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
    iteration_count = int(decoded_item[0][0][1][0][1][1])
    key_length = int(decoded_item[0][0][1][0][1][2])
    assert key_length == 32

    encoded_password = sha1(global_salt + master_password.encode('utf-8')).digest()
    key = pbkdf2_hmac(
        'sha256', encoded_password,
        entry_salt, iteration_count, dklen=key_length)

    init_vector = b'\x04\x0e' + decoded_item[0][0][1][1][1].asOctets()
    encrypted_value = decoded_item[0][1].asOctets()
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    return cipher.decrypt(encrypted_value)


def decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    hp = sha1(globalSalt + masterPassword.encode()).digest()
    pes = entrySalt + b"\x00" * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    logging.info("key={} iv={}".format(key.hex(), iv.hex()))
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)


def decodeLoginData(key, data):
    # first base64 decoding, then ASN1DERdecode
    asn1data, _ = der_decode(b64decode(data))
    assert asn1data[0].asOctets() == MAGIC1
    assert asn1data[1][0].asTuple() == MAGIC2
    iv = asn1data[1][1].asOctets()
    ciphertext = asn1data[2].asOctets()
    des = DES3.new(key, DES3.MODE_CBC, iv)
    return PKCS7unpad(des.decrypt(ciphertext)).decode()


def encodeLoginData(key, data):
    iv = secrets.token_bytes(8)
    des = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = des.encrypt(PKCS7pad(data.encode()))
    asn1data = Sequence()
    asn1data[0] = OctetString(MAGIC1)
    asn1data[1] = Sequence()
    asn1data[1][0] = ObjectIdentifier(MAGIC2)
    asn1data[1][1] = OctetString(iv)
    asn1data[2] = OctetString(ciphertext)
    return b64encode(der_encode(asn1data)).decode()


def getJsonLogins(directory):
    with open(directory / "logins.json", "r") as loginf:
        jsonLogins = json.load(loginf)
    return jsonLogins


def dumpJsonLogins(directory, jsonLogins):
    with open(directory / "logins.json", "w") as loginf:
        json.dump(jsonLogins, loginf, separators=",:")


def exportLogins(key, jsonLogins):
    if "logins" not in jsonLogins:
        logging.error("no 'logins' key in logins.json")
        return []
    logins = []
    for row in jsonLogins["logins"]:
        encUsername = row["encryptedUsername"]
        encPassword = row["encryptedPassword"]
        logins.append(
            (
                row["hostname"],
                decodeLoginData(key, encUsername),
                decodeLoginData(key, encPassword),
            )
        )
    return logins


def lower_header(csv_file):
    it = iter(csv_file)
    yield next(it).lower()
    yield from it


def readCSV(csv_file):
    logins = []
    reader = csv.DictReader(lower_header(csv_file))
    for row in reader:
        logins.append((rawURL(row["url"]), row["username"], row["password"]))
    logging.info(f'read {len(logins)} logins')
    return logins


def rawURL(url):
    p = urlparse(url)
    return type(p)(*p[:2], *[""] * 4).geturl()


def addNewLogins(key, jsonLogins, logins):
    nextId = jsonLogins["nextId"]
    timestamp = int(datetime.now().timestamp() * 1000)
    logging.info('adding logins')
    for i, (url, username, password) in enumerate(logins, nextId):
        logging.debug(f'adding {url} {username}')
        entry = {
            "id": i,
            "hostname": url,
            "httpRealm": None,
            "formSubmitURL": "",
            "usernameField": "",
            "passwordField": "",
            "encryptedUsername": encodeLoginData(key, username),
            "encryptedPassword": encodeLoginData(key, password),
            "guid": "{%s}" % uuid4(),
            "encType": 1,
            "timeCreated": timestamp,
            "timeLastUsed": timestamp,
            "timePasswordChanged": timestamp,
            "timesUsed": 0,
        }
        jsonLogins["logins"].append(entry)
    jsonLogins["nextId"] += len(logins)


def guessDir():
    dirs = {
        "darwin": "~/Library/Application Support/Firefox/Profiles",
        "linux": "~/.mozilla/firefox",
        "win32": os.path.expandvars(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles"),
        "cygwin": os.path.expandvars(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles"),
    }

    if sys.platform not in dirs:
        logging.error(f"Automatic profile selection is not supported for {sys.platform}")
        logging.error("Please specify a profile to parse (-d path/to/profile)")
        raise NoProfile

    paths = Path(dirs[sys.platform]).expanduser()
    profiles = [path.parent for path in paths.glob(os.path.join("*", "logins.json"))]
    logging.debug(f"Paths: {paths}")
    logging.debug(f"Profiles: {profiles}")

    if len(profiles) == 0:
        logging.error("Cannot find any Firefox profiles")
        raise NoProfile

    if len(profiles) > 1:
        logging.error("More than one profile detected. Please specify a profile to parse (-d path/to/profile)")
        logging.error("valid profiles:\n\t\t" + '\n\t\t'.join(map(str, profiles)))
        raise NoProfile

    profile_path = profiles[0]

    logging.info(f"Using profile: {profile_path}")
    return profile_path


def askpass(directory):
    password = ""
    while True:
        try:
            key = getKey(directory, password)
        except WrongPassword:
            password = getpass("Master Password:")
        else:
            break
    return key


def main_export(args):
    try:
        key = askpass(args.directory)
    except NoDatabase:
        # if the database is empty, we are done!
        return
    jsonLogins = getJsonLogins(args.directory)
    logins = exportLogins(key, jsonLogins)
    writer = csv.writer(args.file)
    writer.writerow(["url", "username", "password"])
    writer.writerows(logins)


def main_import(args):
    if args.file == sys.stdin:
        try:
            key = getKey(args.directory)
        except WrongPassword:
            # it is not possible to read the password
            # if stdin is used for input
            logging.error("Password is not empty. You have to specify FROM_FILE.")
            sys.exit(1)
    else:
        key = askpass(args.directory)
    jsonLogins = getJsonLogins(args.directory)
    logins = readCSV(args.file)
    addNewLogins(key, jsonLogins, logins)
    dumpJsonLogins(args.directory, jsonLogins)


def makeParser():
    parser = argparse.ArgumentParser(
        prog="ffpass",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode")
    subparsers.required = True

    parser_export = subparsers.add_parser(
        "export", description="outputs a CSV with header `url,username,password`"
    )
    parser_import = subparsers.add_parser(
        "import",
        description="imports a CSV with columns `url,username,password` (order insensitive)",
    )

    parser_import.add_argument(
        "-f",
        "--file",
        dest="file",
        type=argparse.FileType("r", encoding="utf-8"),
        default=sys.stdin,
    )
    parser_export.add_argument(
        "-f",
        "--file",
        dest="file",
        type=argparse.FileType("w", encoding="utf-8"),
        default=sys.stdout,
    )

    for sub in subparsers.choices.values():
        sub.add_argument(
            "-d",
            "--directory",
            "--dir",
            type=Path,
            default=None,
            help="Firefox profile directory",
        )
        sub.add_argument("-v", "--verbose", action="store_true")
        sub.add_argument("--debug", action="store_true")

    parser_import.set_defaults(func=main_import)
    parser_export.set_defaults(func=main_export)
    return parser


def main():
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

    parser = makeParser()
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.INFO
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.ERROR

    logging.getLogger().setLevel(log_level)

    if args.directory is None:
        try:
            args.directory = guessDir()
        except NoProfile:
            print("")
            parser.print_help()
            parser.exit()
    args.directory = args.directory.expanduser()

    try:
        args.func(args)
    except NoDatabase:
        logging.error("Firefox password database is empty. Please create it from Firefox.")


if __name__ == "__main__":
    main()
