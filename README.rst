|Downloads|

ffpass - Import and Export passwords for Firefox Quantum
========================================================

The latest version of Firefox doesn’t allow to import or export the
stored logins and passwords.

This tools interacts with the encrypted password database of Firefox to
provide these features.

Installation
------------

ffpass requires Python 3.5+ and will work with Firefox 58+

.. code:: bash

   pip install ffpass

Features
--------

-  Supports master passwords
-  Automatic profile selection for Linux, macOS and Windows
-  Export to CSV
-  Import from CSV compatible with Google Chrome

Export to CSV
-------------

.. code:: bash

   ffpass export > passwords.csv
   ffpass export -t passwords.csv
   ffpass export --to passwords.csv

Usage
~~~~~

::

   usage: ffpass export [-h] [-t TO_FILE] [-d DIRECTORY] [-v]

   outputs a CSV with header `url,username,password`

   optional arguments:
     -h, --help            show this help message and exit
     -t TO_FILE, --to TO_FILE
     -d DIRECTORY, --directory DIRECTORY, --dir DIRECTORY
                           Firefox profile directory
     -v, --verbose

Import from CSV
---------------

.. code:: bash

   ffpass import < passwords.csv
   ffpass import -f passwords.csv
   ffpass import --from passwords.csv

By default, it works with the passwords exported from Google Chrome.

.. _usage-1:

Usage
~~~~~

::

   usage: ffpass import [-h] [-f FROM_FILE] [-d DIRECTORY] [-v]

   imports a CSV with columns `url,username,password` (order insensitive)

   optional arguments:
     -h, --help            show this help message and exit
     -f FROM_FILE, --from FROM_FILE
     -d DIRECTORY, --directory DIRECTORY, --dir DIRECTORY
                           Firefox profile directory
     -v, --verbose

Transfer from Google Chrome to Firefox
--------------------------------------

Export from Google Chrome
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Open Chrome and enter the following in the address bar:
   ``chrome://flags/#PasswordExport``
2. Click Default next to “Password export” and choose Enabled.
3. Click Relaunch Now. Chrome will restart.
4. Click the Chrome menu in the toolbar and choose Settings.
5. Scroll to the bottom and click Advanced.
6. Scroll to the “Passwords and forms” section and click “Manage
   passwords”.
7. Click next to Saved Passwords and choose Export.
8. Click Export Passwords, enter the password you use to log in to your
   computer, and save the file to ``passwords.csv`` (or any other
   available name).

*(instructions from*\ https://support.1password.com/import-chrome/\ *)*

Import in Firefox
~~~~~~~~~~~~~~~~~

.. code:: bash

   ffpass import --from passwords.csv

Transfer from Firefox to Google Chrome
--------------------------------------

Export from Firefox
~~~~~~~~~~~~~~~~~~~

.. code:: bash

   ffpass export --to passwords.csv

Import in Google Chrome
~~~~~~~~~~~~~~~~~~~~~~~

1. Open Chrome and enter the following in the address bar:
   ``chrome://flags/#PasswordImport``
2. Click Default next to “Password import” and choose Enabled.
3. Click Relaunch Now. Chrome will restart.
4. Click the Chrome menu in the toolbar and choose Settings.
5. Scroll to the bottom and click Advanced.
6. Scroll to the “Passwords and forms” section and click “Manage
   passwords”.
7. Click next to Saved Passwords and choose Import.
8. Select the file ``passwords.csv`` and click Import.

Troubleshoot
------------

-  ``ffpass export: error: the following arguments are required: -d/--directory/--dir``

   It means one of the following (launch with option ``--verbose`` to
   know):

   -  Automatic profile selection is not supported for your platform.
   -  There is more than one user profile for Firefox.

   You have to provide the ``--dir`` option with your Firefox Profile
   Folder. To find it, follow these
   `instructions <https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_how-do-i-find-my-profile>`__
   on the website of Firefox.

-  ``Firefox password database is empty. Please create it from Firefox.``

   It means that Firefox currently doens’t store any password.
   ``ffpass`` cannot create the password database for security reasons.
   Just add one password manually to Firefox to create the database.

-  Empty url field in Firefox after importing: the urls of the source
   csv file must begin with a scheme (``http://``, ``https://``,
   ``ftp://``, etc…)

Credits
-------

Thanks a lot to @lclevy for the retro-engineering! I was inspired by his
repository https://github.com/lclevy/firepwd.

.. |Downloads| image:: https://pepy.tech/badge/ffpass
   :target: https://pepy.tech/project/ffpass
