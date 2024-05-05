# pas.plugins.tfa

This is a requirement for the https://github.com/collective/volto-tfa Volto plugin.

## Features

- Provides a PAS plugin to add 2FA authentication to the normal login machinery.
- Provides additional UI components & javascript for Plone ClassicUI

## Installation

### via buildout 

Install pas.plugins.tfa by adding it to your buildout

```
[buildout]
    ...
    eggs =
        pas.plugins.tfa
```

and then running `bin/buildout`

If you are only using this plugin for `volto-tfa` then you do not need to
anything further. Continue with the [installation instructions for volto-tfa](https://github.com/collective/volto-tfa/blob/main/README.md)

### via pip

... TODO: install instructions if package released on pypi

## Setting up 2FA in ClassicUI

In order to enable 2FA on your classic site, start by enabling the addon.

Go the Plone control panel and install "pas.plugins.tfa"

To enable 2FA for a particular user, go to the Users control panel, select a
user and check 'Two Factor Authentication'.

Once enabled a user will be prompted to configure their 2FA code the next time
they login.


## Authors

This add-on is heavily inspired by and built upon collective.googleauthenticator (major credit goes to its contributors).

Initial plugin development by:

Mauro Amico (https://github.com/mamico)



## Contributors

Put your name here, you deserve it!

- Jon Pentland (https://github.com/instification)


## Contribute

- Issue Tracker: https://github.com/collective/pas.plugins.tfa/issues
- Source Code: https://github.com/collective/pas.plugins.tfa


## Support

If you are having issues, please create an issue at https://github.com/collective/pas.plugins.tfa/issues


## License

The project is licensed under the GPLv2.