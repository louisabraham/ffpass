[![PyPI
version](https://badge.fury.io/py/ffpass.svg)](https://badge.fury.io/py/ffpass)
[![Downloads](https://pepy.tech/badge/ffpass)](https://pepy.tech/project/ffpass)

# ffpass - Import and Export passwords for Firefox Quantum

The latest version of Firefox doesn't allow to import or export the
stored logins and passwords as a file.

This tools interacts with the encrypted password database of Firefox to
provide these features.

## Installation

ffpass requires Python 3.6+ and will work with Firefox 58+

``` bash
pip install ffpass
```

## Features

  - Supports master passwords
  - Automatic profile selection for Linux, macOS and Windows
  - Export to CSV
  - Import from CSV compatible with Google Chrome

> Note: Firefox must be closed during the whole process, as these
> actions change its database. 
>
> Note: If you have Sync enabled, you'll have to disconnect and
> reconnect your Firefox account after importing the passwords.

## Export to CSV

``` bash
ffpass export > passwords.csv
ffpass export -f passwords.csv
ffpass export --file passwords.csv
```

### Usage

    usage: ffpass export [-h] [-t TO_FILE] [-d DIRECTORY] [-v]
    
    outputs a CSV with header `url,username,password`
    
    optional arguments:
      -h, --help            show this help message and exit
      -f FILE, --file FILE  file to export password (defaults to stdout)
      -d DIRECTORY, --directory DIRECTORY, --dir DIRECTORY
                            Firefox profile directory
      -v, --verbose

## Import from CSV

``` bash
ffpass import < passwords.csv
ffpass import -f passwords.csv
ffpass import --file passwords.csv
```

By default, it works with the passwords exported from Google Chrome.

### Usage

    usage: ffpass import [-h] [-f FROM_FILE] [-d DIRECTORY] [-v]
    
    imports a CSV with columns `url,username,password` (order insensitive)
    
    optional arguments:
      -h, --help            show this help message and exit
      -f FILE, --file FILE  file to import from (defaults to stdin)
      -d DIRECTORY, --directory DIRECTORY, --dir DIRECTORY
                            [Firefox profile directory](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_how-do-i-find-my-profile)
      -v, --verbose

### Formatting

For CSV files not exported from Google Chrome, take these formatting rules into consideration:

    1. The CSV must have the headers "url", "username", and "password". Any other columns will be safely ignored.
    2. The url must be formatted to include all prefixes ("http://", "https://", etc), or ffpass will not be able to read them correctly.
    3. ffpass does not care if the CSV has quotes around fields, even if some fields have them and others don't.

## Transfer from Google Chrome to Firefox

Now, Firefox can more accurately import logins saved in Chrome/Chromium on Windows and macOS (including timestamps, deduping, http auth. logins, etc.) so you don't need to use this tool on those operating systems. See File > Import from Another Browser… in Firefox to import.

### Export from Google Chrome

1.  Open Chrome and enter the following in the address bar:
    `chrome://flags/#PasswordExport`
2.  Click Default next to “Password export” and choose Enabled.
3.  Click Relaunch Now. Chrome will restart.
4.  Click the Chrome menu <i class="fa fa-ellipsis-v"></i> in the
    toolbar and choose Settings.
5.  Scroll to the bottom and click Advanced.
6.  Scroll to the “Passwords and forms” section and click “Manage
    passwords”.
7.  Click <i class="fa fa-ellipsis-v"></i> next to Saved Passwords and
    choose Export.
8.  Click Export Passwords, enter the password you use to log in to your
    computer, and save the file to `passwords.csv` (or any other
    available name).

*(instructions from <https://support.1password.com/import-chrome/>)*

### Import in Firefox

1.  Stop Firefox
2.  Import into Firefox:

<!-- end list -->

``` bash
ffpass import --file passwords.csv
```

Restart Firefox, making sure it didn't leave any process still open.

## Transfer from Firefox to Google Chrome

### Export from Firefox

1.  Stop Firefox
2.  Export from Firefox:

<!-- end list -->

``` bash
ffpass export --file passwords.csv
```

### Import in Google Chrome

1.  Open Chrome and enter the following in the address bar:
    `chrome://flags/#PasswordImport`
2.  Click Default next to “Password import” and choose Enabled.
3.  Click Relaunch Now. Chrome will restart.
4.  Click the Chrome menu <i class="fa fa-ellipsis-v"></i> in the
    toolbar and choose Settings.
5.  Scroll to the bottom and click Advanced.
6.  Scroll to the “Passwords and forms” section and click “Manage
    passwords”.
7.  Click <i class="fa fa-ellipsis-v"></i> next to Saved Passwords and
    choose Import.
8.  Select the file `passwords.csv` and click Import.

## Troubleshoot

  - `ffpass export: error: the following arguments are required:
    -d/--directory/--dir`
    
    It means one of the following (launch with option `--verbose` to
    know):
    
      - Automatic profile selection is not supported for your platform.
      - There is more than one user profile for Firefox.
    
    You have to provide the `--dir` option with your Firefox Profile
    Folder. To find it, follow these
    [instructions](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_how-do-i-find-my-profile)
    on the website of Firefox.

  - `Firefox password database is empty. Please create it from Firefox.`
    
    It means that Firefox currently doens't store any password. `ffpass`
    cannot create the password database for security reasons. Just add
    one password manually to Firefox to create the database.

  - `TypeError: 'PosixPath' object is not iterable`
    
    See [\#17](https://github.com/louisabraham/ffpass/issues/17).

  - Empty url field ("example.com") in Firefox after importing: the urls of the source
    csv file must begin with a scheme (`http://`, `https://`, `ftp://`,
    etc…)
    
  - Passwords do not sync to other devices, including Lockwise app.

    Importing passwords break the sync. You'll have to disconnect the
    Firefox account in the Sync options and the re-add it.

## Credits

Thanks a lot to @lclevy for the retro-engineering\! I was inspired by
his repository <https://github.com/lclevy/firepwd>.
