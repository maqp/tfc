#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2022  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request

from typing import Dict, List, Optional


WORKING_DIR = '/home/user/tfc'
TESTING_DIR = ''  # Must include slash!

REQ_FILE_DEV   = 'requirements-dev.txt'
REQ_FILE_NET   = 'requirements-relay.txt'
REQ_FILE_TPRE  = 'requirements-pre.txt'
REQ_FILE_TAILS = 'requirements-relay-tails.txt'
REQ_FILE_TCB   = 'requirements.txt'
REQ_FILE_VENV  = 'requirements-venv.txt'

persistent = False  # When True, uses cached dependencies.
debug      = True   # When True, prints debug messages

# Dependency statics
APIPKG = 'APIPKG'
APPDIRS = 'APPDIRS'
ARGON2_CFFI = 'ARGON2_CFFI'
ARGON2_CFFI_BINDINGS = 'ARGON2_CFFI_BINDINGS'
ATTRS = 'ATTRS'
BP_EP_SEL = 'BACKPORTS_ENTRYPOINTS_SELECTABLE'
CERTIFI = 'CERTIFI'
CFFI = 'CFFI'
CHARDET = 'CHARDET'
CHARSET_NORMALIZER = 'CHARSET_NORMALIZER'
CLICK = 'CLICK'
COVERAGE = 'COVERAGE'
CRYPTOGRAPHY = 'CRYPTOGRAPHY'
DISTLIB = 'DISTLIB'
EXCEPTIONGROUP = 'EXCEPTIONGROUP'
EXECNET = 'EXECNET'
FLASK = 'FLASK'
FILELOCK = 'FILELOCK'
IDNA = 'IDNA'
IMPORTLIB_METADATA = 'IMPORTLIB_METADATA'
INICONFIG = 'INICONFIG'
ITSDANGEROUS = 'ITSDANGEROUS'
JINJA2 = 'JINJA2'
MARKUPSAFE = 'MARKUPSAFE'
MCCABE = 'MCCABE'
MORE_ITERTOOLS = 'MORE_ITERTOOLS'
MYPY = 'MYPY'
MYPY_EXTENSIONS = 'MYPY_EXTENSIONS'
PACKAGING = 'PACKAGING'
PIP = 'PIP'
PLATFORM_DIRS = 'PLATFORM_DIRS'
PLUGGY = 'PLUGGY'
PY = 'PY'
PYCODESTYLE = 'PYCODESTYLE'
PYCPARSER = 'PYCPARSER'
PYDOCSTYLE = 'PYDOCSTYLE'
PYFLAKES = 'PYFLAKES'
PYLAMA = 'PYLAMA'
PYNACL = 'PYNACL'
PYPARSING = 'PYPARSING'
PYSERIAL = 'PYSERIAL'
PYSOCKS = 'PYSOCKS'
PYTEST = 'PYTEST'
PYTEST_COV = 'PYTEST_COV'
PYTEST_FORKED = 'PYTEST_FORKED'
PYTEST_XDIST = 'PYTEST_XDIST'
REQUESTS = 'REQUESTS'
TYPES_REQUESTS = 'TYPES_REQUESTS'
SETUPTOOLS = 'SETUPTOOLS'
SIX = 'SIX'
SNOWBALLSTEMMER = 'SNOWBALLSTEMMER'
STEM = 'STEM'
TOMLI = 'TOMLI'
TYPED_AST = 'TYPED_AST'
TYPING_EXTENSIONS = 'TYPING_EXTENSIONS'
URLLIB3 = 'URLLIB3'
VIRTUALENV = 'VIRTUALENV'
WCWIDTH = 'WCWIDTH'
WERKZEUG = 'WERKZEUG'
ZIPP = 'ZIPP'



def print_debug(string: str) -> None:
    if debug:
        print(f"Debug: {string}")


def create_file_digest(file_name: str) -> str:
    """Create the SHA512 digest of a dependency file."""
    with open(file_name, 'rb') as f:
        data = f.read()
    digest = hashlib.sha512(data).hexdigest()
    return digest


def create_and_change_to_download_directory() -> None:
    """Create download directory for the dependencies."""
    if TESTING_DIR:
        os.chdir(WORKING_DIR)
        try:
            os.mkdir(TESTING_DIR)
        except FileExistsError:
            if not persistent:
                shutil.rmtree(TESTING_DIR)
                os.mkdir(TESTING_DIR)
                os.chdir(TESTING_DIR)
        os.chdir(f"{WORKING_DIR}/{TESTING_DIR}")


class Dependency(object):
    """A dependency object represents one dependency installed with PIP."""

    def __init__(self,
                 uid:               str,
                 stylized_name:     str,
                 pip_name:          str,
                 description_dict:  Optional[Dict[str, str]] = None,
                 sub_dependencies:  Optional[List[str]]      = None,
                 pinned_version:    Optional[str]            = None,
                 is_dev_dependency: bool                     = False
                 ) -> None:
        self.uid               = uid
        self.stylized_name     = stylized_name
        self.pip_name          = pip_name
        self.description_dict  = description_dict
        self.sub_dependencies  = sub_dependencies
        self.hash_dict         = dict()  # Filename : SHA512 hash
        self.pinned_version    = pinned_version  # type: Optional[str]
        self.latest_version    = None
        self.version_to_use    = None
        self.is_dev_dependency = is_dev_dependency

    @staticmethod
    def release_is_irrelevant(url: str) -> bool:
        """Return True if release file candidate is irrelevant."""
        if any(string in url for string in ['macosx', 'win', 'cp27', 'cpu310']):
            return True

        return False

    def fetch_attributes(self) -> None:
        """Download packages from PyPI and parse attributes."""
        #if self.is_dev_dependency:
        #   return

        self.setup()

        # Obtain dependency release data from PyPi JSON API
        req      = urllib.request.urlopen(f"https://pypi.org/pypi/{self.pip_name}/json")
        dep_data = json.loads(req.read())

        # Determine latest version
        self.latest_version = dep_data['info']['version']
        self.version_to_use = self.latest_version if self.pinned_version is None else self.pinned_version

        # Obtain SHA512 hash of every available Linux version for supported Python versions.
        for release_file in dep_data['releases'][self.version_to_use]:
            file_url  = release_file['url']
            file_name = file_url.split('/')[-1]

            if self.release_is_irrelevant(file_url):
                continue

            while True:
                subprocess.Popen(f"wget -T 30 {file_url} -q", shell=True).wait()
                if not os.path.isfile(file_name):
                    print("Download failed. Trying again.")
                    continue
                break
            self.hash_dict[file_name] = create_file_digest(file_name)
            print(f"{self.hash_dict[file_name]} - {file_name}")

        self.teardown()

    def generate_dev_string(self, file_name: str) -> str:
        """Return requirements-dev.txt string for the dependency.
        E.g. (for latest)
            MarkupSafe>=1.1.1
        or (for pinned)
            idna==2.10
        """
        requirements_string = ''

        # Add description for the dependency
        if self.description_dict is not None:
            if file_name in self.description_dict.keys():
                description = self.description_dict[file_name]
                requirements_string += f"\n# {description}\n"

        # Check of version needs to be pinned to some specific value
        if self.pinned_version is None:
            requirements_string += f"{self.pip_name}>={self.latest_version}\n"
        else:
            requirements_string += f"{self.pip_name}=={self.pinned_version}\n"

        return requirements_string

    def generate_production_string(self, file_name: str, max_spacing: int) -> str:
        """Generate requirements-file string for dependency."""
        requirements_string = ''

        # Add description for the dependency
        if self.description_dict is not None:
            if file_name in self.description_dict.keys():
                description         = self.description_dict[file_name]
                requirements_string = f"\n# {description}\n"

        # Parse string
        name_and_version = f"{self.pip_name}=={self.version_to_use}"
        spacing          = (max_spacing - len(name_and_version)) * ' '

        for i, file_name in enumerate(list(self.hash_dict.keys())):
            if i == 0:
                requirements_string += name_and_version
                requirements_string += spacing
                requirements_string += f'  --hash=sha512:{self.hash_dict[file_name]}'
            else:
                requirements_string += ' \\\n'
                requirements_string += max_spacing * ' '
                requirements_string += f'  --hash=sha512:{self.hash_dict[file_name]}'
        requirements_string += '\n'

        return requirements_string

    def setup(self):
        os.mkdir(self.uid)
        os.chdir(self.uid)

    def teardown(self):
        os.chdir('..')
        shutil.rmtree(self.uid)


class RequirementsFile(object):
    """RequirementsFile object contains list of dependencies and their hashes."""

    def __init__(self,
                 file_name:       str,
                 dependency_dict: Dict[str, Dependency],
                 dependencies:    List[str]
                 ) -> None:
        self.file_name       = file_name
        self.dependency_dict = dependency_dict
        self.dependencies    = dependencies

    def generate_file(self):
        with open(f"{self.file_name}", 'w+') as f:

            dependency_uid_list = []
            for dependency_uid in self.dependencies:
                dependency_uid_list.append(dependency_uid)
                dependency = self.dependency_dict[dependency_uid]
                self.check_sub_dependencies(dependency_uid_list, dependency)

            if len(dependency_uid_list) > 1:
                f.writelines("# Sub-dependencies are listed below dependencies\n")

            dependency_list = [self.dependency_dict[d] for d in dependency_uid_list]
            max_spacing     = max([len(f"{d.pip_name}=={d.version_to_use}") for d in dependency_list])

            for dependency_uid in dependency_uid_list:
                dependency = self.dependency_dict[dependency_uid]

                if self.file_name == REQ_FILE_DEV:
                    f.writelines(dependency.generate_dev_string(self.file_name))
                else:
                    f.writelines(dependency.generate_production_string(self.file_name, max_spacing))

    def check_sub_dependencies(self, dependency_uid_list: List[str], dependency: Dependency):
        """Add subdependencies of dependency to list of dependency UIDs."""

        if dependency.sub_dependencies is not None:
            for sub_dependency_uid in dependency.sub_dependencies:
                if sub_dependency_uid not in dependency_uid_list:
                    dependency_uid_list.append(sub_dependency_uid)

                sub_dependency = self.dependency_dict[sub_dependency_uid]

                # Recursive search of deeper sub-dependencies
                self.check_sub_dependencies(dependency_uid_list, sub_dependency)


def create_bash_hashmap(dep_dict):
    file_name       = f'{WORKING_DIR}/{TESTING_DIR}install.sh'
    hashmap_name    = 'dependency_hashes'
    declaration_str = f'declare -A {hashmap_name}'

    # Read file
    with open(file_name) as f:
        data = f.read().splitlines()

    # Remove hashmap entries
    data = [l for l in data if not l.startswith(hashmap_name)]

    # Find index of hashmap declaration string
    index_of_declaration_str = next(i for i, l in enumerate(data) if l.startswith(declaration_str))

    # Create list of hashmap kv-value creation lines
    for dep_id in list(reversed(list(dep_dict.keys()))):  # Reverse so insertion is in order

        dependency = dep_dict[dep_id]

        # Ignore non-pinned dependencies
        if dependency.is_dev_dependency:
            continue

        # Create kv-value line
        kv_value_lines = [f"{hashmap_name}['{filename}']='{digest}'" for filename, digest in dependency.hash_dict.items()]

        # Insert lines that add kv-values to the hashmap
        data.insert(index_of_declaration_str+1, '\n'.join(kv_value_lines))

    # Write data with up-to-date dependency names from memory to install.sh
    with open(file_name, 'w+') as f:
        for line in data:
            f.write(line + '\n')


def main() -> None:

    create_and_change_to_download_directory()

    dependency_dict = {
        APIPKG:               Dependency(uid=APIPKG,             stylized_name='apipkg',             pip_name='apipkg',             sub_dependencies=None, is_dev_dependency=True),
        APPDIRS:              Dependency(uid=APPDIRS,            stylized_name='appdirs',            pip_name='appdirs',            sub_dependencies=None),
        ARGON2_CFFI:          Dependency(uid=ARGON2_CFFI,        stylized_name='argon2-cffi',        pip_name='argon2-cffi',        sub_dependencies=[ARGON2_CFFI_BINDINGS, PYCPARSER, CFFI],
                                         description_dict={REQ_FILE_DEV:   'Argon2 Password Hashing Function (Derives keys that protect persistent user data)',
                                                           REQ_FILE_TCB:   'Argon2 Password Hashing Function (Derives keys that protect persistent user data)',
                                                           REQ_FILE_NET:   'Argon2 Password Hashing Function (Not needed but allows importing from src.common.crypto)',
                                                           REQ_FILE_TAILS: 'Argon2 Password Hashing Function (Not needed but allows importing from src.common.crypto)'}),
        ARGON2_CFFI_BINDINGS: Dependency(uid=ARGON2_CFFI_BINDINGS, stylized_name='Argon2 CFFI Bindings', pip_name='argon2-cffi-bindings', sub_dependencies=[PYCPARSER, CFFI]),
        ATTRS:                Dependency(uid=ATTRS,              stylized_name='attrs',              pip_name='attrs',              sub_dependencies=None, is_dev_dependency=True),
        BP_EP_SEL:            Dependency(uid=BP_EP_SEL,          stylized_name='BP_EP_SEL',          pip_name='backports.entry-points-selectable', sub_dependencies=None),
        CERTIFI:              Dependency(uid=CERTIFI,            stylized_name='Certifi',            pip_name='certifi',            sub_dependencies=None),
        CFFI:                 Dependency(uid=CFFI,               stylized_name='CFFI',               pip_name='cffi',               sub_dependencies=[PYCPARSER]),
        CHARDET:              Dependency(uid=CHARDET,            stylized_name='chardet',            pip_name='chardet',            sub_dependencies=None),
        CHARSET_NORMALIZER:   Dependency(uid=CHARSET_NORMALIZER, stylized_name='Charset Normalizer', pip_name='charset-normalizer', sub_dependencies=None, pinned_version='2.1.1'),
        CLICK:                Dependency(uid=CLICK,              stylized_name='Click',              pip_name='click',              sub_dependencies=[IMPORTLIB_METADATA, TYPING_EXTENSIONS, ZIPP]),
        COVERAGE:             Dependency(uid=COVERAGE,           stylized_name='Coverage.py',        pip_name='coverage',           sub_dependencies=None, is_dev_dependency=True),
        CRYPTOGRAPHY:         Dependency(uid=CRYPTOGRAPHY,       stylized_name='cryptography',       pip_name='cryptography',       sub_dependencies=[CFFI, SIX],
                                         description_dict={REQ_FILE_DEV:   'cryptography (pyca) (Provides X448 key exchange)',
                                                           REQ_FILE_TCB:   'cryptography (pyca) (Handles TCB-side X448 key exchange)',
                                                           REQ_FILE_NET:   'cryptography (pyca) (Handles URL token derivation)',
                                                           REQ_FILE_TAILS: 'cryptography (pyca) (Handles URL token derivation)'}),
        DISTLIB:              Dependency(uid=DISTLIB,            stylized_name='distlib',            pip_name='distlib',            sub_dependencies=None),
        EXCEPTIONGROUP:       Dependency(uid=EXCEPTIONGROUP,     stylized_name='exceptiongroup',     pip_name='exceptiongroup',     sub_dependencies=None,     is_dev_dependency=True),
        EXECNET:              Dependency(uid=EXECNET,            stylized_name='execnet',            pip_name='execnet',            sub_dependencies=[APIPKG], is_dev_dependency=True),
        FILELOCK:             Dependency(uid=FILELOCK,           stylized_name='py-filelock',        pip_name='filelock',           sub_dependencies=None),
        FLASK:                Dependency(uid=FLASK,              stylized_name='Flask',              pip_name='Flask',              sub_dependencies=[CLICK, ITSDANGEROUS, JINJA2, WERKZEUG],
                                         description_dict={REQ_FILE_DEV:   'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)',
                                                           REQ_FILE_NET:   'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)',
                                                           REQ_FILE_TAILS: 'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)'}),
        IDNA:                 Dependency(uid=IDNA,               stylized_name='IDNA',               pip_name='idna',               sub_dependencies=None),
        IMPORTLIB_METADATA:   Dependency(uid=IMPORTLIB_METADATA, stylized_name='importlib_metadata', pip_name='importlib-metadata', sub_dependencies=[ZIPP]),
        INICONFIG:            Dependency(uid=INICONFIG,          stylized_name='iniconfig',          pip_name='iniconfig',          sub_dependencies=None, is_dev_dependency=True),
        ITSDANGEROUS:         Dependency(uid=ITSDANGEROUS,       stylized_name='ItsDangerous',       pip_name='itsdangerous',       sub_dependencies=None),
        JINJA2:               Dependency(uid=JINJA2,             stylized_name='Jinja2',             pip_name='Jinja2',             sub_dependencies=[MARKUPSAFE]),
        MARKUPSAFE:           Dependency(uid=MARKUPSAFE,         stylized_name='MarkupSafe',         pip_name='MarkupSafe',         sub_dependencies=None),
        MCCABE:               Dependency(uid=MCCABE,             stylized_name='McCabe',             pip_name='mccabe',             sub_dependencies=None, is_dev_dependency=True),
        MORE_ITERTOOLS:       Dependency(uid=MORE_ITERTOOLS,     stylized_name='More Itertools',     pip_name='more-itertools',     sub_dependencies=None, is_dev_dependency=True),
        MYPY:                 Dependency(uid=MYPY,               stylized_name='mypy',               pip_name='mypy',               sub_dependencies=[MYPY_EXTENSIONS, TYPED_AST, TYPES_REQUESTS, TYPING_EXTENSIONS, TOMLI],
                                         description_dict={REQ_FILE_DEV: 'mypy (Static type checking tool)'}, is_dev_dependency=True),
        MYPY_EXTENSIONS:      Dependency(uid=MYPY_EXTENSIONS,    stylized_name='Mypy Extensions',    pip_name='mypy-extensions',    sub_dependencies=None, is_dev_dependency=True),
        PACKAGING:            Dependency(uid=PACKAGING,          stylized_name='packaging',          pip_name='packaging',          sub_dependencies=[PYPARSING, SIX], is_dev_dependency=True),
        PIP:                  Dependency(uid=PIP,                stylized_name='pip',                pip_name='pip',                sub_dependencies=None),
        PLATFORM_DIRS:        Dependency(uid=PLATFORM_DIRS,      stylized_name='platformdirs',      pip_name='platformdirs',                sub_dependencies=None),
        PLUGGY:               Dependency(uid=PLUGGY,             stylized_name='pluggy',             pip_name='pluggy',             sub_dependencies=[IMPORTLIB_METADATA], is_dev_dependency=True),
        PY:                   Dependency(uid=PY,                 stylized_name='py',                 pip_name='py',                 sub_dependencies=None, is_dev_dependency=True),
        PYCODESTYLE:          Dependency(uid=PYCODESTYLE,        stylized_name='pycodestyle',        pip_name='pycodestyle',        sub_dependencies=None, is_dev_dependency=True),
        PYCPARSER:            Dependency(uid=PYCPARSER,          stylized_name='pycparser',          pip_name='pycparser',          sub_dependencies=None),
        PYDOCSTYLE:           Dependency(uid=PYDOCSTYLE,         stylized_name='pydocstyle',         pip_name='pydocstyle',         sub_dependencies=[SNOWBALLSTEMMER], is_dev_dependency=True),
        PYFLAKES:             Dependency(uid=PYFLAKES,           stylized_name='Pyflakes',           pip_name='pyflakes',           sub_dependencies=None, is_dev_dependency=True),
        PYLAMA:               Dependency(uid=PYLAMA,             stylized_name='Pylama',             pip_name='pylama',             sub_dependencies=[MCCABE, PYCODESTYLE, PYDOCSTYLE, PYFLAKES],
                                         description_dict={REQ_FILE_DEV: 'PyLama (Code audit tool for Python)'}, is_dev_dependency=True),
        PYNACL:               Dependency(uid=PYNACL,             stylized_name='PyNaCl',             pip_name='PyNaCl',             sub_dependencies=[CFFI, SIX],
                                         description_dict={REQ_FILE_DEV:   'PyNaCl (pyca) (Handles TCB-side XChaCha20-Poly1305 symmetric encryption and Derives TFC account from Onion Service private key)',
                                                           REQ_FILE_NET:   'PyNaCl (pyca) (Derives TFC account from Onion Service private key)',
                                                           REQ_FILE_TAILS: 'PyNaCl (pyca) (Derives TFC account from Onion Service private key)',
                                                           REQ_FILE_TCB:   'PyNaCl (pyca) (Handles TCB-side XChaCha20-Poly1305 symmetric encryption)'}),
        PYPARSING:            Dependency(uid=PYPARSING,          stylized_name='PyParsing',          pip_name='pyparsing',          sub_dependencies=None, is_dev_dependency=True),
        PYSERIAL:             Dependency(uid=PYSERIAL,           stylized_name='pySerial',           pip_name='pyserial',           sub_dependencies=None,
                                         description_dict={REQ_FILE_DEV:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                           REQ_FILE_NET:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                           REQ_FILE_TAILS: 'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                           REQ_FILE_TCB:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)'}),
        PYSOCKS:              Dependency(uid=PYSOCKS,            stylized_name='PySocks',            pip_name='PySocks',            sub_dependencies=None,
                                         description_dict={REQ_FILE_DEV:   'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)',
                                                           REQ_FILE_NET:   'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)',
                                                           REQ_FILE_TAILS: 'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)'}),
        PYTEST:               Dependency(uid=PYTEST,             stylized_name='pytest',             pip_name='pytest',             sub_dependencies=[ATTRS, EXCEPTIONGROUP, IMPORTLIB_METADATA, INICONFIG, MORE_ITERTOOLS, PACKAGING, PLUGGY, PY, WCWIDTH],
                                         description_dict={REQ_FILE_DEV: 'pytest (Test framework)'}, is_dev_dependency=True),
        PYTEST_COV:           Dependency(uid=PYTEST_COV,         stylized_name='pytest-cov',         pip_name='pytest-cov',         sub_dependencies=[COVERAGE, PYTEST],
                                         description_dict={REQ_FILE_DEV: 'pytest-cov (Pytest plugin for measuring coverage)'}, is_dev_dependency=True),
        PYTEST_FORKED:        Dependency(uid=PYTEST_FORKED,      stylized_name='pytest-forked',      pip_name='pytest-forked',      sub_dependencies=[PYTEST], is_dev_dependency=True),
        PYTEST_XDIST:         Dependency(uid=PYTEST_XDIST,       stylized_name='xdist',              pip_name='pytest-xdist',       sub_dependencies=[EXECNET, PYTEST, PYTEST_FORKED, SIX],
                                         description_dict={REQ_FILE_DEV: 'xdist (Pytest distributed testing plugin)'}, is_dev_dependency=True),
        REQUESTS:             Dependency(uid=REQUESTS,           stylized_name='Requests',           pip_name='requests',           sub_dependencies=[CERTIFI, CHARSET_NORMALIZER, IDNA, URLLIB3],
                                         description_dict={REQ_FILE_DEV:   "Requests (Connects to the contact's Tor Onion Service)",
                                                           REQ_FILE_NET:   "Requests (Connects to the contact's Tor Onion Service)",
                                                           REQ_FILE_TAILS: "Requests (Connects to the contact's Tor Onion Service)"}),
        SETUPTOOLS:           Dependency(uid=SETUPTOOLS,         stylized_name='Setuptools',         pip_name='setuptools',         sub_dependencies=None),
        SIX:                  Dependency(uid=SIX,                stylized_name='six',                pip_name='six',                sub_dependencies=None),
        SNOWBALLSTEMMER:      Dependency(uid=SNOWBALLSTEMMER,    stylized_name='snowballstemmer',    pip_name='snowballstemmer',    sub_dependencies=None, is_dev_dependency=True),
        STEM:                 Dependency(uid=STEM,               stylized_name='Stem',               pip_name='stem',               sub_dependencies=None,
                                         description_dict={REQ_FILE_DEV:   'Stem (Connects to Tor and manages Onion Services)',
                                                           REQ_FILE_NET:   'Stem (Connects to Tor and manages Onion Services)',
                                                           REQ_FILE_TAILS: 'Stem (Connects to Tor and manages Onion Services)'}),
        TOMLI:                Dependency(uid=TOMLI,              stylized_name='Tomli',              pip_name='tomli',              sub_dependencies=None, is_dev_dependency=True),
        TYPED_AST:            Dependency(uid=TYPED_AST,          stylized_name='Typed AST',          pip_name='typed-ast',          sub_dependencies=None, is_dev_dependency=True),
        TYPES_REQUESTS:       Dependency(uid=TYPES_REQUESTS,     stylized_name='types-requests',     pip_name='types-requests',     sub_dependencies=None, is_dev_dependency=True),
        TYPING_EXTENSIONS:    Dependency(uid=TYPING_EXTENSIONS,  stylized_name='Typing Extensions',  pip_name='typing-extensions',  sub_dependencies=None),
        URLLIB3:              Dependency(uid=URLLIB3,            stylized_name='urllib3',            pip_name='urllib3',            sub_dependencies=None),
        VIRTUALENV:           Dependency(uid=VIRTUALENV,         stylized_name='virtualenv',         pip_name='virtualenv',         sub_dependencies=[APPDIRS, BP_EP_SEL, DISTLIB, FILELOCK, IMPORTLIB_METADATA, PLATFORM_DIRS, TYPING_EXTENSIONS, SIX],
                                         description_dict={REQ_FILE_VENV: 'Virtual environment (Used to create an isolated Python environment for TFC dependencies)'}),
        WCWIDTH:              Dependency(uid=WCWIDTH,            stylized_name='wcwidth',            pip_name='wcwidth',            sub_dependencies=None, is_dev_dependency=True),
        WERKZEUG:             Dependency(uid=WERKZEUG,           stylized_name='Werkzeug',           pip_name='Werkzeug',           sub_dependencies=None),
        ZIPP:                 Dependency(uid=ZIPP,               stylized_name='zipp',               pip_name='zipp',               sub_dependencies=None)
    }

    for d in dependency_dict.keys():
        if os.path.isdir(d):
            shutil.rmtree(f'{d}/')

    for dependency_uid in dependency_dict.keys():
        dependency = dependency_dict[dependency_uid]
        dependency.fetch_attributes()

    requirements = RequirementsFile(file_name=REQ_FILE_TCB,
                                    dependency_dict=dependency_dict,
                                    dependencies=[PYSERIAL,
                                                  ARGON2_CFFI,
                                                  CRYPTOGRAPHY,
                                                  PYNACL,
                                                  SETUPTOOLS
                                                  ])

    requirements_r = RequirementsFile(file_name=REQ_FILE_NET,
                                      dependency_dict=dependency_dict,
                                      dependencies=[PYSERIAL,
                                                    STEM,
                                                    PYSOCKS,
                                                    REQUESTS,
                                                    FLASK,
                                                    CRYPTOGRAPHY,
                                                    PYNACL,
                                                    SETUPTOOLS,
                                                    ARGON2_CFFI
                                                    ])

    requirements_rt = RequirementsFile(file_name=REQ_FILE_TAILS,
                                       dependency_dict=dependency_dict,
                                       dependencies=[PYSERIAL,
                                                     # STEM,  # Not needed ATM
                                                     PYSOCKS,
                                                     REQUESTS,
                                                     FLASK,
                                                     CRYPTOGRAPHY,
                                                     PYNACL,
                                                     ARGON2_CFFI
                                                     ])

    requirements_tails_pre = RequirementsFile(file_name=REQ_FILE_TPRE,
                                               dependency_dict=dependency_dict,
                                               dependencies=[PIP,
                                                             SETUPTOOLS])

    requirements_venv = RequirementsFile(file_name=REQ_FILE_VENV,
                                         dependency_dict=dependency_dict,
                                         dependencies=[VIRTUALENV])

    requirements_dev = RequirementsFile(file_name=REQ_FILE_DEV,
                                        dependency_dict=dependency_dict,
                                        dependencies=[ARGON2_CFFI,
                                                      CRYPTOGRAPHY,
                                                      FLASK,
                                                      MYPY,
                                                      PYLAMA,
                                                      PYNACL,
                                                      PYSERIAL,
                                                      PYSOCKS,
                                                      PYTEST,
                                                      PYTEST_COV,
                                                      PYTEST_XDIST,
                                                      REQUESTS,
                                                      SETUPTOOLS,
                                                      STEM
                                                      ])

    create_bash_hashmap(dependency_dict)

    requirements.generate_file()
    requirements_r.generate_file()
    requirements_rt.generate_file()
    requirements_tails_pre.generate_file()
    requirements_venv.generate_file()
    requirements_dev.generate_file()


if __name__ == '__main__':
    main()
