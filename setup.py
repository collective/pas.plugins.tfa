"""Installer for the pas.plugins.tfa package."""

from setuptools import find_packages
from setuptools import setup


long_description = "\n\n".join(
    [
        open("README.md").read(),
        open("CONTRIBUTORS.md").read(),
        open("CHANGES.md").read(),
    ]
)


setup(
    name="pas.plugins.tfa",
    version="1.0a1",
    description="An add-on for Plone",
    long_description=long_description,
    long_description_content_type="text/markdown",
    # Get more from https://pypi.org/classifiers/
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Framework :: Plone",
        "Framework :: Plone :: Addon",
        "Framework :: Plone :: 6.0",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    ],
    keywords="Python Plone CMS",
    author="mamico",
    author_email="mauro.amico@gmail.com",
    url="https://github.com/collective/pas.plugins.tfa",
    project_urls={
        "PyPI": "https://pypi.python.org/pypi/pas.plugins.tfa",
        "Source": "https://github.com/collective/pas.plugins.tfa",
        "Tracker": "https://github.com/collective/pas.plugins.tfa/issues",
        # 'Documentation': 'https://pas.plugins.tfa.readthedocs.io/en/latest/',
    },
    license="GPL version 2",
    packages=find_packages("src", exclude=["ez_setup"]),
    namespace_packages=["pas", "pas.plugins"],
    package_dir={"": "src"},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.9",
    install_requires=[
        "setuptools",
        "plone.api",
        "plone.restapi",
        "pyotp",
        "iw.rejectanonymous",
        "Products.GenericSetup",
        "Products.PluggableAuthService",
        "Products.statusmessages",
        "plone.autoform",
        "plone.base",
        "plone.supermodel",
        "plone.rest",
        "plone.keyring",
        "Zope",
        "z3c.form",
        "qrcode",
    ],
    extras_require={
        "test": [
            "plone.testing>=5.0.0",
            "plone.app.testing",
            "plone.testing",
            "plone.browserlayer",
            "plone.base",
            "plone.app.robotframework[debug]",
            "requests",
        ],
    },
    entry_points="""
    [z3c.autoinclude.plugin]
    target = plone
    [console_scripts]
    update_locale = pas.plugins.tfa.locales.update:update_locale
    """,
)
