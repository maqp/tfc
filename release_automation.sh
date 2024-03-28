#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2023  Markus Ottela
#
# This file is part of TFC.
#
# TFC is free software: you can redistribute it and/or modify it under the terms
# of the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with TFC. If not, see <https://www.gnu.org/licenses/>.
#
# --------------------------------------------------------------------------------


function cd_cwd() {
    # cd to current working directory
    cd /home/user/tfc/
}

function box_print() {
  local s="$*"
  tput setaf 3
  echo " -${s//?/-}-
| ${s//?/ } |
| $(tput setaf 4)$s$(tput setaf 3) |
| ${s//?/ } |
 -${s//?/-}-"
  tput sgr 0
}


function remove_pycache_files() {
    find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete
}


function install_global_dependencies() {
  box_print "Installing global dependencies"
  sudo apt install -y wget
  sudo apt install -y python3-pip
  sudo apt install -y python3-virtualenv
  sudo apt install -y python3-tk
  sudo apt install -y tor
}


function update_ide_venv() {
    box_print "Updating IDE Virtualenv"

    # Cleanup
    rm -rf /home/user/tfc/venv

    # Create virtualenv
    python3 -m virtualenv venv --system-site-packages

    # Activate virtualenv
    . /home/user/tfc/venv/bin/activate

    # Upgrade PIP in virtualenv
    python3 -m pip install --upgrade pip

    # Install packages to virtualenv
    python3 -m pip install --no-cache-dir --no-deps -r "/home/user/tfc/requirements-dev.txt"

    # Cleanup
    deactivate
}


function update_dependencies() {
    box_print "Updating dependencies"
    python3 /home/user/tfc/auto_dependency_updater.py
}


function test_requirement_files_with_pinned_hashes() {
    box_print "Testing requirement files with pinned hashes"

    req_test_venv_name=venv_req_test
    requirements_files="requirements.txt requirements-relay.txt requirements-relay-tails.txt"

    for req_file in ${requirements_files}; do
        # Setup
        cd_cwd
        rm -rf req_test 2>/dev/null
        mkdir req_test
        cd req_test

        # Test
        python3 -m virtualenv ${req_test_venv_name}
        . /home/user/tfc/req_test/${req_test_venv_name}/bin/activate
        python3 -m pip install  -r "/home/user/tfc/${req_file}" --require-hashes  --no-deps --no-cache-dir
        python3 -m pip download -r "/home/user/tfc/${req_file}" --require-hashes  --no-deps --no-cache-dir  # Check that downloading also works
        deactivate

        # Teardown
        cd_cwd
        rm -rf req_test 2>/dev/null
    done
}

function run_mypy_type_checks() {
    box_print "Running mypy type checks"

    # Setup
    cd_cwd
    remove_pycache_files
    rm -rf /home/user/tfc/.mypy_cache 2>/dev/null
    . /home/user/tfc/venv/bin/activate

    # Run mypy type checks
    python3 -m mypy {tfc,relay,dd}.py --ignore-missing-imports  # --strict (Strict is disabled until pyca/cryptography PKCS7 (un)padder uses types)

    # Teardown
    deactivate
    remove_pycache_files
    rm -rf /home/user/tfc/.mypy_cache 2>/dev/null
}

function run_style_checks() {
    box_print "Running style checks"

    # Setup
    cd_cwd
    remove_pycache_files
    . /home/user/tfc/venv/bin/activate
    cd src/

    # Run style checks on source files
    python3 -m pylama -i E122,E272,E221,E202,E226,E271,E701,E251,E201,E222,E231,E127,E131,E128,E125,E501,W0611,C901

    # Cleanup
    deactivate
    cd_cwd
    remove_pycache_files
}

function run_unit_tests() {
    box_print "Running unit tests"

    # Setup
    cd_cwd
    rm -rf /home/user/tfc/.pytest_cache 2>/dev/null
    rm -rf /home/user/tfc/htmlcov/ 2>/dev/null
    . /home/user/tfc/venv/bin/activate

    # Run unit tests
    python3 -m pytest --cov=src --cov-report=html -d --tx 7*popen//python=python3 tests/

    # Teardown
    deactivate
    cd_cwd
    remove_pycache_files
    rm -rf /home/user/tfc/.pytest_cache 2>/dev/null
}


function update_installer_digests() {
    # Setup
    cd_cwd
    rm -f BLAKE2b.list 2>/dev/null

    # Actions
    box_print "Updating install.sh pinned BLAKE2b hashes"
    find . -type f -exec b2sum "{}" + > BLAKE2b.list
    python3 hash_replacer.py

    box_print "Verifying installer.sh pinned BLAKE2b digests via install.sh itself"
    bash install.sh test

    # Teardown
    rm -f BLAKE2b.list 2>/dev/null
}

function run_release_checks() {
    box_print "Checking version number consistency"
    python3 release_checks.py
}

function sign_the_installer() {
    # Setup
    box_print "Press any key to continue with signing"
    rm -f install.sh.asc 2>/dev/null
    read -r -n 1

    # Sign the installer
    gpg --detach-sign --armor install.sh
}


function main() {
    set -e

    # DL Actions
    # install_global_dependencies
    # update_ide_venv
    # update_dependencies
    # test_requirement_files_with_pinned_hashes

    # Actions
    # run_mypy_type_checks
    # run_style_checks
    # run_unit_tests

    update_installer_digests
    run_release_checks
    sign_the_installer

    box_print 'Publish script completed successfully.'
}

main
