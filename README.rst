.. This README is meant for consumption by humans and pypi. Pypi can render rst files so please do not use Sphinx features.
   If you want to learn more about writing documentation, please check out: http://docs.plone.org/about/documentation_styleguide.html
   This text does not appear on pypi or github. It is a comment.

.. image:: https://github.com/collective/pas.plugins.tfa/actions/workflows/plone-package.yml/badge.svg
    :target: https://github.com/collective/pas.plugins.tfa/actions/workflows/plone-package.yml

.. image:: https://coveralls.io/repos/github/collective/pas.plugins.tfa/badge.svg?branch=main
    :target: https://coveralls.io/github/collective/pas.plugins.tfa?branch=main
    :alt: Coveralls

.. image:: https://codecov.io/gh/collective/pas.plugins.tfa/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/collective/pas.plugins.tfa

.. image:: https://img.shields.io/pypi/v/pas.plugins.tfa.svg
    :target: https://pypi.python.org/pypi/pas.plugins.tfa/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/status/pas.plugins.tfa.svg
    :target: https://pypi.python.org/pypi/pas.plugins.tfa
    :alt: Egg Status

.. image:: https://img.shields.io/pypi/pyversions/pas.plugins.tfa.svg?style=plastic   :alt: Supported - Python Versions

.. image:: https://img.shields.io/pypi/l/pas.plugins.tfa.svg
    :target: https://pypi.python.org/pypi/pas.plugins.tfa/
    :alt: License


===============
pas.plugins.tfa
===============

This is a requirement for the https://github.com/collective/volto-tfa Volto plugin.

Features
--------

- Provides a PAS plugin to add 2FA authentication to the normal login machinery.
- Provides additional UI components & javascript for Plone ClassicUI

Installation
------------

Install pas.plugins.tfa by adding it to your buildout::

    [buildout]

    ...

    eggs =
        pas.plugins.tfa


and then running ``bin/buildout``

If you are only using this plugin for `volto-tfa` then you do not need to
anything further. Continue with the [installation instructions for volto-tfa](https://github.com/collective/volto-tfa/blob/main/README.md)


Setting up 2FA in ClassicUI
---------------------------

In order to enable 2FA on your classic site, start by enabling the addon.

Go the Plone control panel and install "pas.plugins.tfa"

To enable 2FA for a particular user, go to the Users control panel, select a
user and check 'Two Factor Authentication'.

Once enbaled a user will be prompted to configure their 2FA code the next time
they login.


Authors
-------

This add-on is heavily inspired by and built upon collective.googleauthenticator (major credit goes to its contributors).

Initial plugin development by:

Mauro Amico (https://github.com/mamico)



Contributors
------------

Put your name here, you deserve it!

- Jon Pentland (https://github.com/instification)


Contribute
----------

- Issue Tracker: https://github.com/collective/pas.plugins.tfa/issues
- Source Code: https://github.com/collective/pas.plugins.tfa


Support
-------

If you are having issues, please create an issue at https://github.com/collective/pas.plugins.tfa/issues


License
-------

The project is licensed under the GPLv2.
