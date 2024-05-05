- [pas.plugins.tfa](#paspluginstfa)
  - [Features](#features)
  - [Installation](#installation)
    - [via buildout](#via-buildout)
    - [via pip](#via-pip)
  - [Setting up 2FA in ClassicUI](#setting-up-2fa-in-classicui)
  - [Test the package in a Testenvironment](#test-the-package-in-a-testenvironment)
  - [Development](#development)
  - [Authors](#authors)
  - [Contributors](#contributors)
  - [Contribute](#contribute)
  - [Support](#support)
  - [License](#license)

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

checkout the package and install it via

`pip install -e .`

## Setting up 2FA in ClassicUI

In order to enable 2FA on your classic site, start by enabling the addon.

Go the Plone control panel and install "pas.plugins.tfa"

To enable 2FA for a particular user, go to the Users control panel, select a
user and check 'Two Factor Authentication'.

Once enabled a user will be prompted to configure their 2FA code the next time
they login.

## Test the package in a Testenvironment

```
python3 -m venv ./venv
source venv/bin/activate
pip install cookiecutter
pip install mxdev
mxdev -c mx.ini
pip install -r requirements-mxdev.txt
cookiecutter -f --no-input --config-file instance.yaml https://github.com/plone/cookiecutter-zope-instance
runwsgi -v instance/etc/zope.ini
deactivate 
```

## Development

we use tox

```
python3 -m venv ./venv
source venv/bin/activate
tox -e init
```

Format the code run 

```
tox -e format
```

Lint the code run 

```
tox -e lint
```

Run tests

```
tox -e test
```

Run code coverage

```
tox -e coverage
```

check dependencies

```
tox -e dependencies
```

check circular dependencies

```
tox -e circular
```

check release   

```
tox -e release-check
```

run all together

```
tox
```


## Authors

This add-on is heavily inspired by and built upon collective.googleauthenticator (major credit goes to its contributors).

Initial plugin development by:

Mauro Amico (https://github.com/mamico)


## Contributors

Put your name here, you deserve it!

- Jon Pentland (https://github.com/instification)
- 1letter


## Contribute

- Issue Tracker: https://github.com/collective/pas.plugins.tfa/issues
- Source Code: https://github.com/collective/pas.plugins.tfa


## Support

If you are having issues, please create an issue at https://github.com/collective/pas.plugins.tfa/issues


## License

The project is licensed under the GPLv2.