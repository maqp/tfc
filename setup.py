#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || setup.py

"""
Copyright (C) 2013-2016  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import pipes
import random
import readline
import subprocess
import sys
import time

repository = "https://raw.githubusercontent.com/maqp/tfc/master/"
str_version = "0.16.10"


###############################################################################
#                                APT COMMANDS                                 #
###############################################################################

def cmd(command, message=''):
    """
    Display message and run command as subprocess.

    :param command: Command to run
    :param message: Message to be displayed
    :return:        None
    """

    if message:
        print("\n%s\n" % message)
    shell(command)


sagi = "sudo apt install --yes"


def update_repositories():
    """Update repositories."""

    cmd("sudo apt --yes update", "Updating repository list")


def install_python_serial():
    """Install Python serial."""

    cmd("%s python-serial" % sagi, "Installing Python serial")


def install_python_qt4():
    """Install Python QT4."""

    cmd("%s python-qt4" % sagi, "Installing Python QT4")


def install_python_qt4_dbus():
    """Install Python QT4-DBus."""

    cmd("%s python-qt4-dbus" % sagi, "Installing Python QT4-DBus")


def install_pidgin():
    """Install Pidgin."""

    cmd("%s pidgin" % sagi, "Installing Pidgin")


def install_pidgin_otr():
    """Install Pidgin OTR."""

    cmd("%s pidgin-otr" % sagi, "Installing Pidgin OTR")


def install_python_setuptools():
    """Install Python Setuptools."""

    cmd("%s python-setuptools" % sagi, "Installing Python Setuptools")


def install_python_dev():
    """Install Python-Dev."""

    cmd("%s python-dev" % sagi, "Installing Python-Dev")


def install_libffi_dev():
    """Install Libffi."""

    cmd("%s libffi-dev" % sagi, "Installing libffi")


def install_tkinter():
    """Install Tkinter."""

    cmd("%s python-tk" % sagi, "Installing Python Tkinter")


def install_libssl_dev():
    """Install Libssl-dev."""

    cmd("%s libssl-dev" % sagi, "Installing libssl-dev")


def install_build_essential():
    """Install Build-essential."""

    cmd("%s build-essential" % sagi, "Installing Build-essential")


def add_terminator_repository():
    """Add terminator repository."""

    cmd("sudo add-apt-repository --yes ppa:gnome-terminator",
        "Adding Terminator repository")


def install_terminator():
    """Install Terminator."""

    cmd("%s terminator" % sagi, "Installing Terminator")


###############################################################################
#                            INSTALLER VERIFICATION                           #
###############################################################################

def shell(command):
    """
    Run terminal command in shell.

    :param command: Command to run
    :return:        None
    """

    subprocess.Popen(command, shell=True).wait()


###############################################################################
#                            FILE HASH VERIFICATION                           #
###############################################################################

hash_list = ("""
5e38c7738f15a05d5bd43a6ff729e47711dc214f4b71d99bdd11f48e17cb558a  tfc-mods.zip
a83d34f53dc9b17aa42c9a35c3fbcc5120f3fcb07f7f8721ec45e6a27be347fc  passlb.tar.gz
1898d64e22c03aadce9e6b2936897a4bdc125f17ebbd15a96bdc3f71d7f69cf6  sha3.tar.bz2
be2623c41873e8e8a512a77f93edb301f64377331714b71116f7c30ea4fe6e2a  pyc.zip
64cf1ee26d1cde3c73c6d7d107f835fed7c6a2904aef9eac223d57ad800c43fa  ecdsa.tar.gz
402c44cd30284a6acf80fdb4de56de44b879049f4d0342e28c84ef60223113bc  paramiko.zip
043f6f1738fc85c8b6c8b7943b08e0aeb5f82397175503fb69427d869c706251  logo.png
0da4e578093b35a13d7646f358943bcc51808b0e2aaed6864c736f7e108ae333  dd.py
0b79504e902209df2bcd6ccb690e69d69e1dfeba568410a6b9957ccfc3f93308  hwrng.py
be0b5a59873e007940c1a91f387a7acfc04493ee285b4f08fe3b62c53c90c2d3  NH.py
9d45e531b81f3d1398fe9acd5e2b011d1249a8265ac3c205113f8293e5e91405  Rx.py
2e241ba8dac9fbd203846286695d5109b6ea3083839c7874d8757b9391f3a4ba  test_nh.py
7eddcfe1ed755dbee58669bd4a863eecc0800ab71ad67a1c599b3c7333d02b30  test_rx.py
9a1baf41fa169967b9bed16e873713cb9fd475bf0b15d1b2e7d6f28fd9e51fe2  test_tx.py
5e0b957bad7c06e7da67e051d31d4e3594161212ec87e053561f21ff61e2ec9e  Tx.py
""")


def check_file_hash(filename):
    """
    Verify that SHA-256 hash of file matches the one in installer.

    Unless you verify the authenticity of this installer with the PGP signature
    verification key, the fingerprint of which you have obtained through secure
    channel such as Web-of-Trust, you can NOT trust the hashes written above
    were not created by attacker for the purpose of TLS-MITM attack.

    :param filename: File to verify
    :return:         None
    """

    f_hash = subprocess.check_output(["sha256sum", filename]).split()[0]

    h_list = hash_list.split('\n')
    for h in h_list:
        if filename in h:
            if f_hash not in h:
                clear_screen()
                print("CRITICAL ERROR: SHA256 hash of %s was incorrect.   \n"
                      "This might indicate a TLS-MITM attack, transmission\n"
                      "error or that this installer is outdated.\n" % filename)
                exit()

    print("\nSHA256 hash of %s was correct.\n" % filename)


###############################################################################
#                                CRYPTO LIBRARIES                             #
###############################################################################

def simplesha3_download():
    """Download and verify SimpleSHA3 library."""

    cmd("wget https://pypi.python.org/packages/source/s/simplesha3/"
        "simplesha3-2015.09.22.post1.tar.bz2 -O sha3.tar.bz2",
        "Downloading SimpleSHA3 library")
    check_file_hash("sha3.tar.bz2")


def simplesha3_install():
    """Install SimpleSHA3 library."""

    app_root_directory = os.getcwd()
    cmd("tar -vxjf sha3.tar.bz2", "Unzipping SimpleSHA3")
    os.chdir("simplesha3-2015.09.22.post1/")
    cmd("sudo python setup.py install", "Installing SimpleSHA3")
    os.chdir(app_root_directory)
    cmd("rm sha3.tar.bz2", "Removing install files")
    cmd("sudo rm -r simplesha3-2015.09.22.post1/")
    clear_screen()


def pynacl_download():
    """Download and verify PyNaCl library."""

    cmd("wget https://github.com/maqp/pynacl/archive/tfc-mods.zip",
        "Downloading PyNaCl library")
    check_file_hash("tfc-mods.zip")


def pynacl_install():
    """Install PyNaCl library into system files."""

    app_root_directory = os.getcwd()
    cmd("sudo mv tfc-mods.zip /usr/local/lib/"
        "python2.7/dist-packages/tfc-mods.zip")
    os.chdir("/usr/local/lib/python2.7/dist-packages/")
    lib_root_directory = os.getcwd()
    cmd("unzip tfc-mods.zip", "Unzipping PyNaCl library")
    os.chdir("/usr/local/lib/python2.7/dist-packages/pynacl-tfc-mods/")
    cmd("sudo python setup.py install", "Installing PyNaCl library")
    os.chdir(lib_root_directory)
    cmd("sudo chown -R %s pynacl-tfc-mods/" % os.getenv("SUDO_USER"))
    cmd("rm tfc-mods.zip", "Removing install files")
    os.chdir(app_root_directory)
    clear_screen()


def passlib_download():
    """Download and verify Passlib."""

    cmd("wget https://pypi.python.org/packages/source/p/"
        "passlib/passlib-1.6.5.tar.gz -O passlb.tar.gz",
        "Downloading Passlib")
    check_file_hash("passlb.tar.gz")


def passlib_install():
    """Install Passlib."""

    app_root_directory = os.getcwd()
    cmd("tar -xf passlb.tar.gz", "Unzipping Passlib")
    os.chdir("passlib-1.6.5/")
    cmd("sudo python setup.py install", "Installing Passlib")
    os.chdir(app_root_directory)
    cmd("rm passlb.tar.gz", "Removing install files")
    cmd("sudo rm -r passlib-1.6.5/")
    clear_screen()


def pycrypto_download():
    """Download and verify PyCrypto library (Paramiko dependency)."""

    cmd("wget https://github.com/dlitz/pycrypto/archive/master.zip -O pyc.zip",
        "Downloading PyCrypto library")
    check_file_hash("pyc.zip")


def pycrypto_install():
    """Install PyCrypto library (Paramiko dependency)."""

    app_root_dir = os.getcwd()
    cmd("unzip pyc.zip", "Unzipping PyCrypto Library")
    os.chdir("pycrypto-master/")
    cmd("sudo python setup.py install", "Installing PyCrypto Library")
    os.chdir(app_root_dir)
    cmd("rm pyc.zip", "Removing install files")
    cmd("sudo rm -rf pycrypto-master")
    clear_screen()


def ecdsa_download():
    """Download and verify ECDSA library (Paramiko dependency)."""

    cmd("wget https://pypi.python.org/packages/"
        "source/e/ecdsa/ecdsa-0.13.tar.gz -O ecdsa.tar.gz")
    check_file_hash("ecdsa.tar.gz")


def ecdsa_install():
    """Install ECDSA library (Paramiko dependency)."""

    app_root_directory = os.getcwd()
    cmd("tar xf ecdsa.tar.gz", "Unzipping PyNaCl library")
    os.chdir("ecdsa-0.13/")
    cmd("sudo python setup.py install", "Installing ECDSA library")
    os.chdir(app_root_directory)
    cmd("rm ecdsa.tar.gz", "Removing install files")
    cmd("sudo rm -rf ecdsa-0.13")
    clear_screen()


def paramiko_download():
    """Download and verify Paramiko SSH library."""

    cmd("wget https://github.com/maqp/paramiko/"
        "archive/master.zip -O paramiko.zip",
        "Downloading Paramiko SSH Library")
    check_file_hash("paramiko.zip")


def paramiko_install():
    """Install Paramiko SSH library."""

    app_root_directory = os.getcwd()
    cmd("unzip paramiko.zip", "Unzipping Paramiko")
    os.chdir("paramiko-master/")
    cmd("sudo python setup.py install", "Installing Paramiko SSH Library")
    os.chdir(app_root_directory)
    cmd("rm paramiko.zip", "Removing install files")
    cmd("sudo rm -r paramiko-master/")
    clear_screen()


###############################################################################
#                             DOWNLOAD TFC PROGRAMS                           #
###############################################################################

def get_files(files):
    """
    Download and verify file, fix ownership and enable run permissions.

    :param files: List of files to download
    :return:      None
    """

    for f in files:
        repo = repository
        if f.startswith("test_"):
            repo += "unittests/"
        cmd("wget %s%s" % (repo, f), "Downloading %s" % f)
        check_file_hash(f)
        fix_ownership(f)


###############################################################################
#                               EDIT OS SETTINGS                              #
###############################################################################


def set_serial_permissions(username=''):
    """
    Add user to 'dialout' group to allow use of serial interface without sudo.

    :param username: Username to be added.
    :return:         None
    """

    if username == '':
        u_acco = os.getenv("SUDO_USER")
        while True:
            clear_screen()
            username = raw_input("Select user for serial interface [%s]: "
                                 % u_acco)
            if username == '':
                username = u_acco
            if yes("\n  Confirm user '%s'?" % username):
                print('')
                break

    cmd("sudo gpasswd --add %s dialout" % pipes.quote(username))


def disable_network_interfaces():
    """
    Kill all active network interfaces from TxM / RxM to minimize the
    remote compromise time window of the TCB device.

    :return: None
    """

    iface_list = get_list_of_ifaces(all_if=True)

    for i in iface_list:
        cmd("sudo ifconfig %s down" % i, "Disabling network interface %s" % i)

    print("\nNetwork interfaces have now been disabled.\n"
          "To ensure isolation remove ethernet cable now.\n")
    raw_input("Once the cable is disconnected, press enter to continue.")
    print('')


def rpi_serial_config():
    """Enable serial exclusively for TFC."""

    print("\nDisabling Console from '/boot/cmdline.txt'.\n")
    content = open("/boot/cmdline.txt").readline()
    content = content.replace(" console=serial0,115200", '')
    open("/boot/cmdline.txt", "w+").write(content)

    print("Enabling UART in /boot/config.txt")
    contents = open("/boot/config.txt").read()
    if "enable_uart=0" in contents:
        contents.replace("enable_uart=0",
                         "enable_uart=1")
        open("/boot/config.txt", "w+").write(contents)
    else:
        cmd("sudo echo 'enable_uart=1' >> /boot/config.txt")

    cmd("sudo systemctl stop serial-getty@ttyS0.service")
    cmd("sudo systemctl disable serial-getty@ttyS0.service")


def iface_tab_complete(text, state):
    """
    Create new tab-completer with available ethernet interfaces.

    :param text:  Current string
    :param state: Current state
    :return:      None
    """

    cmd("ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' > tfc_ifaces")
    iface_list = open("tfc_ifaces").read().splitlines()
    os.remove("tfc_ifaces")

    options = [t for t in iface_list if t.startswith(text)]
    try:
        return options[state]
    except IndexError:
        pass


def get_list_of_ifaces(all_if=False):
    """
    Get list of ethernet interfaces.

    :param all_if: When True, returns list of all interfaces
    :return:       List of (ethernet) interfaces
    """

    cmd("ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' > tfc_ifaces")
    iface_list = open("tfc_ifaces").read().splitlines()
    os.remove("tfc_ifaces")

    if all_if:
        return iface_list

    cleaned = [i for i in iface_list if i.startswith("en")]

    return cleaned


def static_ip_ubuntu():
    """
    Set *buntu to use static IP for HWRNG.

    :return: None
    """

    while True:
        clear_screen()

        iface_list = get_list_of_ifaces()

        if not iface_list:
            print("\nSearching for ethernet interfaces...\n")
            time.sleep(1)
            continue

        print("Found following ethernet interfaces:")
        for iface in iface_list:
            print("  %s" % iface)
        print('')

        readline.set_completer(iface_tab_complete)
        readline.parse_and_bind("tab: complete")

        ask_abort = False
        try:
            iface = raw_input("Manually specify interface [refresh]: ")
        except KeyboardInterrupt:
            ask_abort = True

        if not iface:
            continue

        if ask_abort:
            if yes("\nAbort?"):
                print("\nStatic IP setup aborted.\n")
                time.sleep(2)
                return None

        if yes("\n  Confirm %s?" % iface):
            break

    cmd("sudo ifconfig %s up" % iface,
        "Enabling network interface %s" % iface)

    if_config = """\
auto lo
iface lo inet loopback

auto %s
iface %s inet static
address 192.168.1.3
netmask 255.255.255.0
gateway 192.168.1.1
""" % (iface, iface)

    print("Setting static IP '192.168.1.3' for TxM.\n")
    open("/etc/network/interfaces", "w+").write(if_config)

    time.sleep(0.5)
    cmd("sudo /etc/init.d/networking restart")
    time.sleep(0.5)


def static_ip_raspbian():
    """
    Set Raspbian to use static IP during HWRNG configuration.

    :return: None
    """

    cmd("sudo cp /etc/network/interfaces /etc/network/interfaces.sav",
        "Creating backup of network interfaces")

    print("Setting static IP '192.168.1.2' for Raspbian.\n")

    if_config = """\
interface eth0
static ip_address=192.168.1.2/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1 8.8.8.8
"""

    open("/etc/dhcpcd.conf", "a+").write(if_config)

    cmd("sudo /etc/init.d/networking restart", "Restarting networking")


###############################################################################
#                               EDIT TFC PROGRAMS                             #
###############################################################################

def ssh_hwrng_connection(local=False):
    """
    Ask user whether they will use Raspbian over SSH to load entropy.
    If yes, enable setting for Tx.py and set static IP for TxM.

    :param local: When true, asks user to configure IP for HWRNG
    :return:      None
    """

    clear_screen()

    if not yes("Will TxM load entropy from Raspberry Pi over SSH?"):
        return None

    print("\nEnabling SSH client during key generation\n")
    contents = open("Tx.py").read()
    contents = contents.replace("ssh_hwrng_sampling = False",
                                "ssh_hwrng_sampling = True")
    open("Tx.py", "w+").write(contents)

    if local:
        ssh_config()
    else:
        static_ip_ubuntu()


def ssh_config():
    """
    Configure Tx.py SSH settings for local testing.

    :return: None
    """

    clear_screen()
    if not yes("Configure HWRNG host/IP and username?"):
        return None

    host = ''
    user = ''
    def_host = "192.186.1.2"
    def_user = "pi"

    print('')

    def get_value(string, default):
        """
        Get value for settings from user.

        :param string:  String to print in prompt
        :param default: Default value when empty string is given
        :return:        Value to use in settings
        """

        while True:
            value = raw_input("%s    " % string)
            if value == '':
                value = default
                print_on_previous_line()
                print("%s    %s" % (string, value))

            if any(c in host for c in ['\\', '"', "'"]):
                print ("\nError: No chars '\\', '\"', \"'\" allowed.")
                time.sleep(1.5)
                for _ in range(3):
                    print_on_previous_line()
                continue
            return value

    while True:

        host = get_value("Enter host/IP [%s]:" % def_host, def_host)
        user = get_value("Enter username [%s]:        " % def_user, def_user)

        if not yes("\nAccept configuration?"):
            for _ in range(6):
                print_on_previous_line()
            continue
        break

    content = open("Tx.py").read()
    content = content.replace('hwrng_host = "192.168.1.2"',
                              'hwrng_host = "%s"' % host)

    content = content.replace('hwrng_user = "pi"',
                              'hwrng_user = "%s"' % user)

    open("Tx.py", "w+").write(content)


def serial_config_raspbian(program):
    """
    Ask user whether they will use USB to serial adapter with program.

    :param program: Program the serial interface of which is changed
    :return:        None
    """

    clear_screen()

    if program == "Tx.py":
        if yes("Will TxM connect to NH using USB to serial adapter?"):
            return None

    if program == "Rx.py":
        if yes("Will RxM connect to NH using USB to serial adapter?"):
            return None

    print("\nChanging %s's NH serial-interface to integrated.\n" % program)
    contents = open(program).read()
    contents = contents.replace("serial_usb_adapter = True",
                                "serial_usb_adapter = False")
    open(program, "w+").write(contents)


def serial_config_integrated(program):
    """
    Ask user whether they will use USB to serial adapter.
    Answering no enables integrated interface /dev/ttyS0.

    :param program: Program the serial interface of which is changed
    :return:        None
    """

    clear_screen()

    if program == "NH.py":
        usb_ifaces = 2

        if not yes("Will NH connect to TxM using USB to serial adapter?"):
            usb_ifaces -= 1

        if not yes("Will NH connect to RxM using USB to serial adapter?"):
            usb_ifaces -= 1

        if usb_ifaces != 2:
            content = open(program).read()
            content = content.replace("total_usb_adapters = 2",
                                      "total_usb_adapters = %s" % usb_ifaces)
            open(program, "w+").write(content)
        return None

    elif program == "Tx.py":
        if yes("Will TxM connect to NH using USB to serial adapter?"):
            return None

    elif program == "Rx.py":
        if yes("Will RxM connect to NH using USB to serial adapter?"):
            return None

    print("\nChanging %s's NH serial-interface to integrated.\n" % program)
    contents = open(program).read()
    contents = contents.replace("serial_usb_adapter = True",
                                "serial_usb_adapter = False")
    open(program, "w+").write(contents)


def change_to_local(file_name):
    """
    Configure {Tx,Rx,NH}.py local_testing_mode boolean to True.

    :param file_name: Target program from which local_testing_mode is enabled
    :return:          None
    """

    print("\nEnabling 'local_testing_mode' boolean in program '%s'.\n"
          % file_name)
    content = open(file_name).read()
    content = content.replace("local_testing_mode = False",
                              "local_testing_mode = True")
    open(file_name, "w+").write(content)


def move_to_install_directory(device):
    """
    Create new install directory and move to it.

    :return: None
    """

    install_dir = "tfc-%s" % device
    i = 0
    while os.path.exists("%s/" % install_dir):
        i += 1
        install_dir = "%s(%s)" % (install_dir, i)

    ensure_dir("%s/" % install_dir)
    os.chdir("%s/" % install_dir)


def fix_ownership(path):
    """
    Change the owner of the file to SUDO_UID.

    :return: None
    """

    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")

    if uid is not None:
        os.chown(path, int(uid), int(gid))


def set_run_permissions(program):
    """
    Enable read and execution permissions for TFC program.

    :param program: Name of the program
    :return:        None
    """

    cmd("chmod a+rx %s" % program,
        "Enabling run permissions for %s" % program)


###############################################################################
#                              SOFTWARE LAUNCHING                             #
###############################################################################

def add_local_desktop_entries():
    """
    Create desktop entries for local testing.

    :return: None
    """

    cwd = os.getcwd()

    entry = """\
[Desktop Entry]
Name=TFC
Comment=Local testing
Exec=terminator -m -p TFC-local-profile -l TFC-local-layout
Icon=%s/logo.png
Terminal=false
Type=Application
Categories=Network;Messaging;Security;""" % cwd

    dd_entry = """\
[Desktop Entry]
Name=TFC DD
Comment=Local testing with data diode simulators
Exec=terminator -m -p TFC-local-profile -l TFC-local-layout-dd
Icon=%s/logo.png
Terminal=false
Type=Application
Categories=Network;Messaging;Security;""" % cwd

    open("tfc.desktop", "w+").write(entry)
    open("tfc-dd.desktop", "w+").write(dd_entry)

    set_run_permissions("tfc.desktop")
    set_run_permissions("tfc-dd.desktop")
    fix_ownership("tfc.desktop")
    fix_ownership("tfc-dd.desktop")

    if os.path.exists("/usr/share/applications/"):
        cmd("cp tfc.desktop /usr/share/applications/")


def add_terminator_local_testing_profile_and_layouts():
    """
    Create a config file for Terminator in file ~/.config/terminator/config.

    The function preserves existing configurations,
    inserting profile data if no previous ones exist.

    :return: None
    """

    # Function is run while working directory is in TFC installation directory
    d = os.getcwd()

    layouts_to_add = """\
[global_config]
  inactive_color_offset = 1.0
  suppress_multiple_term_dialog = True
[keybindings]
[layouts]
  [[default]]
    [[[child1]]]
      parent = window0
      profile = default
      type = Terminal
    [[[window0]]]
      parent = ""
      type = Window
  [[TFC-local-layout]]
    [[[child0]]]
      fullscreen = False
      last_active_window = True
      maximised = True
      order = 0
      parent = ""
      position = 0:24
      title = TFC
      type = Window
    [[[child1]]]
      order = 0
      parent = child0
      position = 957
      ratio = 0.5
      type = HPaned
    [[[child3]]]
      order = 1
      parent = child1
      position = 698
      ratio = 0.694747274529
      type = VPaned
    [[[terminal2]]]
      command = "python '%s/Tx.py'"
      order = 0
      parent = child1
      profile = TFC-local-profile
      type = Terminal
    [[[terminal4]]]
      command = "python '%s/Rx.py'"
      order = 0
      parent = child3
      profile = TFC-local-profile
      type = Terminal
    [[[terminal5]]]
      command = "python '%s/NH.py'"
      directory = ""
      order = 1
      parent = child3
      profile = TFC-local-profile
      type = Terminal
  [[TFC-local-layout-dd]]
    [[[child0]]]
      fullscreen = False
      last_active_window = True
      maximised = True
      order = 0
      parent = ""
      position = 0:24
      title = TFC
      type = Window
    [[[child1]]]
      order = 0
      parent = child0
      position = 1205
      ratio = 0.629166666667
      type = HPaned
    [[[child2]]]
      order = 0
      parent = child1
      position = 952
      ratio = 0.792531120332
      type = HPaned
    [[[child3]]]
      order = 0
      parent = child2
      position = 559
      ratio = 0.499555555556
      type = VPaned
    [[[child6]]]
      order = 1
      parent = child2
      position = 559
      ratio = 0.499555555556
      type = VPaned
    [[[terminal4]]]
      command = "python '%s/Rx.py'"
      order = 0
      parent = child3
      profile = TFC-local-profile
      type = Terminal
    [[[terminal5]]]
      command = python '%s/Tx.py' -d
      order = 1
      parent = child3
      profile = TFC-local-profile
      type = Terminal
    [[[terminal7]]]
      command = python '%s/dd.py' nhrxlr
      directory = ""
      order = 0
      parent = child6
      profile = TFC-local-profile
      type = Terminal
    [[[terminal8]]]
      command = python '%s/dd.py' txnhlr
      directory = ""
      order = 1
      parent = child6
      profile = TFC-local-profile
      type = Terminal
    [[[terminal9]]]
      command = python '%s/NH.py' -d
      order = 1
      parent = child1
      profile = TFC-local-profile
      type = Terminal
[plugins]
[profiles]
  [[default]]
    background_color = "#3d3d3d"
    background_image = None
    foreground_color = "#a8bfcf"
    scrollback_infinite = True
    show_titlebar = False
  [[TFC-local-profile]]
    background_color = "#3d3d3d"
    background_darkness = 1.2
    background_image = None
    cursor_color = "#ffffff"
    foreground_color = "#a8bfcf"
    scrollback_infinite = True
    show_titlebar = False""" % (d, d, d, d, d, d, d, d)

    profile_to_add = """\
  [[TFC-local-profile]]
    background_color = "#3d3d3d"
    background_darkness = 1.2
    background_image = None
    cursor_color = "#ffffff"
    foreground_color = "#a8bfcf"
    scrollback_infinite = True
    show_titlebar = False"""

    # Ensure config file directory exists
    home_dir = os.getenv("HOME")
    terminator_dir = "%s/.config/terminator/" % home_dir
    ensure_dir(terminator_dir)
    fix_ownership(terminator_dir)

    # If config file does not exist yet, create one
    config_file = "%s/.config/terminator/config" % home_dir
    if not os.path.isfile(config_file):
        open(config_file, "w+").write(layouts_to_add)
        fix_ownership(config_file)
        return None

    # If Terminator's config file exists, add TFC profile and layouts to it
    config_file_content_list = open(config_file).read().splitlines()

    # Split config strings above to lists
    profile_data_list = profile_to_add.splitlines()
    layouts_data_list = layouts_to_add.splitlines()

    # Strip default layouts etc
    layouts_data_list = layouts_data_list[13:][:-16]

    # Check config file for pre-existing TFC profile
    tfc_profile_found = False
    tfc_layout_dd_found = False
    tfc_layout_found = False

    for line in config_file_content_list:

        if line == "  [[TFC-local-profile]]":
            print("\nProfile 'TFC-local-profile' already exists "
                  "in ~./config/terminator/config")
            tfc_profile_found = True

        if line == "  [[TFC-local-layout]]":
            print("\nLayout 'TFC-local-layout' already exists "
                  "in ~./config/terminator/config")
            tfc_layout_found = True

        if line == "  [[TFC-local-layout-dd]]":
            print("\nLayout 'TFC-local-layout-dd' already exists "
                  "in ~./config/terminator/config")
            tfc_layout_dd_found = True

    if not tfc_profile_found:
        for line in config_file_content_list:
            if line == "[profiles]":
                index = config_file_content_list.index(line)
                config_file_content_list[index + 1:1] = profile_data_list
                break

    # First so that TFC-local-layout will be put between it and [layouts]
    if not tfc_layout_dd_found:
        tmp_layout_dd_data_list = layouts_data_list[41:]
        for line in config_file_content_list:
            if line == "[layouts]":
                index = config_file_content_list.index(line)
                config_file_content_list[index + 1:1] = tmp_layout_dd_data_list
                break

    if not tfc_layout_found:
        tmp_layout_data_list = layouts_data_list[:41]
        for line in config_file_content_list:
            if line == "[layouts]":
                index = config_file_content_list.index(line)
                config_file_content_list[index + 1:1] = tmp_layout_data_list
                break

    open(config_file, "w+").write("\n".join(config_file_content_list))
    fix_ownership(config_file)


def add_desktop_entry(program):
    """
    Create desktop entry for TxM/RxM/NH *buntu / Linux Mint.

    :return: None
    """

    d = {"Tx.py": "Transmitter program",
         "Rx.py": "Receiver program",
         "NH.py": "Network handler"}

    cwd = os.getcwd()

    entry = """\
[Desktop Entry]
Name=TFC
Comment=%s
Exec=terminator -p TFC-%s-profile -l TFC-%s-layout
Icon=%s/logo.png
Terminal=false
Type=Application
Categories=Network;Messaging;Security;
""" % (d[program], program[:2], program[:2], cwd)

    open("tfc.desktop", "w+").write(entry)
    set_run_permissions("tfc.desktop")
    fix_ownership("tfc.desktop")

    if os.path.exists("/usr/share/applications/"):
        cmd("cp tfc.desktop /usr/share/applications")


def add_terminator_profile_and_layouts(program):
    """
    Create a config file for Terminator in file ~/.config/terminator/config.

    The function preserves existing configurations,
    inserting profile data if no previous ones exist.

    :pram program: Name of program to create profile for
    :return:       None
    """

    # Function is run while working directory is in TFC installation directory
    d = os.getcwd()

    titles = {"Tx.py": "TxM", "Rx.py": "RxM", "NH.py": "NH"}

    layouts_to_add = """\
[global_config]
[keybindings]
[layouts]
  [[default]]
    [[[child1]]]
      command = ""
      parent = window0
      profile = default
      type = Terminal
    [[[window0]]]
      parent = ""
      type = Window
  [[TFC-%s-layout]]
    [[[child0]]]
      fullscreen = False
      last_active_window = True
      maximised = False
      order = 0
      parent = ""
      position = 50:50
      size = 1000, 563
      title = %s
      type = Window
    [[[terminal1]]]
      command = "python '%s/%s'"
      order = 0
      parent = child0
      profile = TFC-%s-profile
      type = Terminal
[plugins]
[profiles]
  [[default]]
    background_color = "#3d3d3d"
    background_image = None
    foreground_color = "#a8bfcf"
    show_titlebar = False
    use_theme_colors = True
  [[TFC-%s-profile]]
    background_color = "#3d3d3d"
    background_image = None
    exit_action = hold
    foreground_color = "#a8bfcf"
    scrollbar_position = hidden
    show_titlebar = False""" % (program[:2], titles[program], d,
                                program, program[:2], program[:2])

    profile_to_add = """\
  [[TFC-%s-profile]]
    background_color = "#3d3d3d"
    background_image = None
    exit_action = hold
    foreground_color = "#a8bfcf"
    show_titlebar = False""" % program[:2]

    # Ensure config file directory exists
    home_dir = os.getenv("HOME")
    terminator_dir = "%s/.config/terminator/" % home_dir
    ensure_dir(terminator_dir)
    fix_ownership(terminator_dir)

    # If config file does not exist yet, create one
    config_file = "%s/.config/terminator/config" % home_dir
    if not os.path.isfile(config_file):
        open(config_file, "w+").write(layouts_to_add)
        fix_ownership(config_file)
        return None

    # If Terminator's config file exists, add TFC profile and layouts to it
    config_file_content_list = open(config_file).read().splitlines()

    # Split config strings above to lists
    profile_data_list = profile_to_add.splitlines()
    layouts_data_list = layouts_to_add.splitlines()

    # Strip default layouts etc
    layouts_data_list = layouts_data_list[12:][:-14]

    # Check config file for pre-existing TFC profile
    tfc_profile_found = False
    tfc_layout_found = False

    for line in config_file_content_list:

        if line == "  [[TFC-%s-profile]]" % program[:2]:
            print("\nProfile TFC-%s-profile already exists "
                  "in ~./config/terminator/config" % program[:2])
            tfc_profile_found = True

        if line == "  [[TFC-%s-layout]]" % program[:2]:
            print("\nLayout TFC-%s-layout already exists "
                  "in ~./config/terminator/config" % program[:2])
            tfc_layout_found = True

    if not tfc_profile_found:
        for line in config_file_content_list:
            if line == "[profiles]":
                index = config_file_content_list.index(line)
                config_file_content_list[index + 1:1] = profile_data_list
                break

    if not tfc_layout_found:
        tmp_layout_data_list = layouts_data_list
        for line in config_file_content_list:
            if line == "[layouts]":
                index = config_file_content_list.index(line)
                config_file_content_list[index + 1:1] = tmp_layout_data_list
                break

    open(config_file, "w+").write("\n".join(config_file_content_list))
    fix_ownership(config_file)


###############################################################################
#                            PRINT NOTIFICATIONS                              #
###############################################################################

def print_menu(system_os):
    """Display the menu with list of installation configurations."""

    print("TFC %s || setup.py" % str_version)

    try:
        options = {"raspbian": ["TxM", "RxM", "NH", "HWRNG"],
                   "ubuntu": ["TxM", "RxM", "NH", "Local testing"]}[system_os]
    except KeyError:
        print("Unsupported OS.")
        return None

    print("""
Select configuration for %s

   1. %s

   2. %s

   3. %s

   4. %s\n""" % (system_os.capitalize(),
          options[0], options[1],
          options[2], options[3]))


def print_local_tester_warning():
    """Display a warning about insecurity of local testing."""

    print("\n                             WARNING!                         \n"
          "  YOU HAVE SELECTED THE LOCAL TESTING CONFIGURATION FOR TFC.    \n"
          "  THIS VERSION IS INTENDED ONLY FOR TRYING OUT THE FEATURES AND \n"
          "  STABILITY OF THE SYSTEM. IN THIS CONFIGURATION, THE ENCRYPTION\n"
          "  KEYS ARE GENERATED, STORED AND HANDLED ON NETWORK-CONNECTED   \n"
          "  COMPUTER, SO ANYONE WHO BREAKS IN TO IT BY EXPLOITING A KNOWN \n"
          "  (OR UNKNOWN ZERO DAY) VULNERABILITY, CAN DECRYPT AND/OR FORGE \n"
          "  ALL MESSAGES YOU SEND AND RECEIVE!")


def print_local_test_install_finish():
    """Print message about where TFC was installed, and what to do next."""

    clear_screen()

    cwd = os.getcwd()
    print("\n  TFC has been installed into '%s' " % cwd)
    print("  Initiate OTR-conversation in Pidgin and start 'TFC' or 'TFC DD'."
          "\n")


def print_on_previous_line():
    """Next message will be printed on upper line."""

    cul = "\x1b[1A"         # Move cursor up 1 line
    cel = "\x1b[2K"         # Clear entire line
    print(cul + cel + cul)  # Trailing 'cursor up' as print adds new line


def clear_screen():
    """Clear terminal window."""

    ces = "\x1b[2J"  # Clear entire screen
    clc = "\x1b[H"   # Move cursor to upper left corner
    sys.stdout.write(ces + clc)


###############################################################################
#                                    MISC                                     #
###############################################################################

def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :return:       True if user types 'y' or 'yes'
                   False if user types 'n' or 'no'
    """

    string = "%s (y/n): " % prompt

    while string.startswith('\n'):
        print('')
        string = string[1:]

    while True:
        try:
            answer = raw_input(string)
        except KeyboardInterrupt:
            raise

        print_on_previous_line()

        if answer.lower() in ("yes", 'y'):
            print("%sYes" % string)
            return True

        elif answer.lower() in ("no", 'n'):
            print("%sNo" % string)
            return False

        else:
            continue


def shuffle_functions(functions):
    """
    Run a set of functions in order defined by CSPRNG.

    :param functions: List of functions to run
    :return:          None
    """

    r = random.SystemRandom()
    r.shuffle(functions)
    for f in functions:
        f()


def ensure_dir(directory):
    """
    Ensure directory exists.

    :param directory: Specified directory
    :return:          None
    """

    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


###############################################################################
#                              INSTALL ROUTINES                               #
###############################################################################

def raspbian_txm(fast_=False):
    """
    Install TxM configuration for Raspbian Jessie.

    :param fast_: If true, runs automatically until network is killed
    :return:      None
    """

    kill = True
    if not fast_:
        kill = yes("Disable networking from TxM after downloads complete?")

    move_to_install_directory("TxM")

    update_repositories()

    shuffle_functions(
        [install_build_essential,
         install_python_setuptools,
         install_python_dev,
         install_libffi_dev,
         install_libssl_dev,
         install_python_serial,
         install_tkinter])

    shuffle_functions([passlib_download,
                       simplesha3_download,
                       pynacl_download])

    get_files(["Tx.py", "test_tx.py", "logo.png"])

    pynacl_install()

    if kill:
        disable_network_interfaces()

    passlib_install()
    simplesha3_install()

    fix_ownership('.')

    rpi_serial_config()
    serial_config_raspbian("Tx.py")

    clear_screen()
    print("\nTxM installation complete.\nReboot the system before running.\n")
    exit()


def ubuntu_txm(fast_=False):
    """
    Install TxM configuration for for *buntu / Linux Mint.

    :param fast_: If true, runs automatically until network is killed
    :return:      None
    """

    kill = True
    if not fast_:
        kill = yes("Disable networking from TxM after downloads complete?")

    move_to_install_directory("TxM")

    add_terminator_repository()
    update_repositories()

    shuffle_functions(
        [install_python_setuptools,
         install_build_essential,
         install_python_dev,
         install_libffi_dev,
         install_libssl_dev,
         install_python_serial,
         install_tkinter,
         install_terminator])

    shuffle_functions(
        [passlib_download,
         pycrypto_download,
         ecdsa_download,
         paramiko_download,
         simplesha3_download,
         pynacl_download])

    get_files(["Tx.py", "test_tx.py", "logo.png"])

    pynacl_install()

    if kill:
        disable_network_interfaces()

    passlib_install()
    pycrypto_install()
    ecdsa_install()
    paramiko_install()
    simplesha3_install()

    fix_ownership('.')

    serial_config_integrated("Tx.py")
    set_serial_permissions()

    ssh_hwrng_connection()

    add_terminator_profile_and_layouts("Tx.py")
    add_desktop_entry("Tx.py")

    clear_screen()
    print("\nTxM installation complete.\nReboot the system before running.\n")
    exit()


def raspbian_hwrng(fast_=False):
    """
    Install HWRNG configuration for Raspbian Jessie.

    :param fast_: If true, runs automatically until network is killed
    :return:      None
    """

    get_files(["hwrng.py"])
    set_run_permissions("hwrng.py")
    static_ip_raspbian()

    clear_screen()
    print("\nHWRNG installation complete.\n\n"
          "Disconnect this Raspberry Pi from the Internet and\n"
          "connect it to TxM directly using an ethernet cable.")

    if not fast_:
        time.sleep(3)
    print("\nRebooting...\n")
    if not fast:
        time.sleep(2)

    cmd("sudo reboot")


def raspbian_rxm(fast_=False):
    """
    Install RxM configuration for Raspbian Jessie.

    :param fast_: If true, runs automatically until network is killed
    :return:      None
    """

    kill = True
    if not fast_:
        kill = yes("Disable networking from RxM after downloads complete?")

    move_to_install_directory("RxM")

    update_repositories()

    shuffle_functions(
        [install_python_setuptools,
         install_build_essential,
         install_python_dev,
         install_libffi_dev,
         install_libssl_dev,
         install_python_serial,
         install_tkinter])

    shuffle_functions(
        [passlib_download,
         simplesha3_download,
         pynacl_download])

    get_files(["Rx.py", "test_rx.py", "logo.png"])

    pynacl_install()

    if kill:
        disable_network_interfaces()

    passlib_install()
    simplesha3_install()

    fix_ownership('.')

    rpi_serial_config()
    serial_config_raspbian("Rx.py")

    clear_screen()
    print("\nRxM installation complete.\nReboot the system before running.\n")
    exit()


def ubuntu_rxm(fast_=False):
    """
    Install RxM configuration for *buntu / Linux Mint.

    :param fast_: If true, runs automatically until network is killed
    :return:      None
    """

    kill = True
    if not fast_:
        kill = yes("Disable networking from TxM after downloads complete?")

    move_to_install_directory("RxM")

    add_terminator_repository()
    update_repositories()

    shuffle_functions(
        [install_python_setuptools,
         install_build_essential,
         install_python_dev,
         install_libffi_dev,
         install_libssl_dev,
         install_python_serial,
         install_tkinter,
         install_terminator])

    shuffle_functions(
        [passlib_download,
         simplesha3_download,
         pynacl_download])

    get_files(["Rx.py", "test_rx.py", "logo.png"])

    pynacl_install()

    if kill:
        disable_network_interfaces()

    passlib_install()
    simplesha3_install()

    fix_ownership('.')

    serial_config_integrated("Rx.py")
    set_serial_permissions()

    add_terminator_profile_and_layouts("Rx.py")
    add_desktop_entry("Rx.py")

    clear_screen()
    print("\nRxM installation complete.\nReboot the system before running.\n")
    exit()


def raspbian_nh(_):
    """
    Install NH configuration for Raspbian.

    :return: None
    """

    move_to_install_directory("NH")

    update_repositories()

    install_python_qt4()
    install_python_qt4_dbus()
    install_python_serial()

    install_pidgin()
    install_pidgin_otr()

    get_files(["NH.py", "test_nh.py", "logo.png"])
    fix_ownership('.')

    rpi_serial_config()
    serial_config_integrated("NH.py")
    set_serial_permissions()

    clear_screen()
    print("\nNH installation complete.\nReboot the system before running.\n")
    exit()


def ubuntu_nh(_):
    """
    Install NH configuration for *buntu / Linux Mint.

    :return: None
    """

    move_to_install_directory("NH")

    add_terminator_repository()
    update_repositories()

    install_python_qt4()
    install_python_qt4_dbus()
    install_python_serial()

    install_terminator()
    install_pidgin()
    install_pidgin_otr()

    get_files(["NH.py", "test_nh.py", "logo.png"])
    fix_ownership('.')

    add_terminator_profile_and_layouts("NH.py")
    serial_config_integrated("NH.py")
    add_desktop_entry("NH.py")

    set_serial_permissions()

    clear_screen()
    print("\nNH installation complete.\nReboot the system before running.\n")
    exit()


def tails_nh(_):
    """
    Install NH configuration for Tails LiveCD / LiveUSB.

    :return: None
    """

    move_to_install_directory("NH")

    update_repositories()
    install_python_serial()
    install_python_qt4_dbus()

    get_files(["NH.py", "test_nh.py"])
    serial_config_integrated("NH.py")
    set_serial_permissions("amnesia")

    clear_screen()
    print("\nNH install complete. Initiate OTR-encrypted"
          "\nPidgin conversation and launch NH.py.\n"
          "\nExiting.\n")
    exit()


def local_testing(fast_):
    """
    Install insecure local testing configuration for *buntu / Linux Mint.

    :param fast_: If true, attempts to run everything automatically
    :return:      None
    """

    clear_screen()

    if not fast_:
        print_local_tester_warning()
        if not raw_input("\n  TYPE 'INSECURE' TO VERIFY "
                         "YOU UNDERSTAND THE RISKS: ").lower() == "insecure":
            return None

    clear_screen()
    move_to_install_directory("localtest")

    add_terminator_repository()
    update_repositories()

    install_python_setuptools()
    install_build_essential()
    install_python_dev()
    install_libffi_dev()
    install_libssl_dev()
    install_python_serial()
    install_tkinter()
    install_python_qt4()
    install_python_qt4_dbus()
    install_pidgin()
    install_pidgin_otr()
    install_terminator()

    passlib_download()
    pycrypto_download()
    ecdsa_download()
    paramiko_download()
    simplesha3_download()
    pynacl_download()

    passlib_install()
    pycrypto_install()
    ecdsa_install()
    paramiko_install()
    simplesha3_install()
    pynacl_install()

    get_files(["Tx.py", "test_tx.py",
               "Rx.py", "test_rx.py",
               "NH.py", "test_nh.py",
               "dd.py", "logo.png"])

    fix_ownership('.')
    cmd("sudo chown -R %s pynacl-tfc-mods/" % os.getenv("SUDO_USER"))
    add_terminator_local_testing_profile_and_layouts()
    add_local_desktop_entries()

    change_to_local("Tx.py")
    change_to_local("Rx.py")
    change_to_local("NH.py")

    if not fast:
        ssh_hwrng_connection(local=True)

    print_local_test_install_finish()
    print("  Exiting setup.py\n")
    exit()


###############################################################################
#                                  MAIN LOOP                                  #
###############################################################################

user_uid = int(os.getenv("SUDO_UID")) if os.geteuid() == 0 else os.geteuid()

if __name__ == "__main__":

    # Rescale terminal to fit menu
    sys.stdout.write("\x1b[8;20;87t")

    try:
        selection = int(sys.argv[1])
        if selection not in [1, 2, 3, 4]:
            print("\nError: Invalid argument. Exiting.\n")
            exit()
        fast = True
    except (IndexError, ValueError):
        fast = False

    # Get signature and public signature verification key
    shell("wget https://cs.helsinki.fi/u/oottela/tfc-pubkey.asc -N")
    shell("wget %ssetup.py.asc -N" % repository)
    fix_ownership("tfc-pubkey.asc")
    fix_ownership("setup.py.asc")

    # Determine platform
    try:
        os_id = subprocess.check_output(["grep", "^ID=", "/etc/os-release"])
        os_id = os_id[3:].strip('\n')
    except subprocess.CalledProcessError:
        try:
            os_id = subprocess.check_output(["grep", "ID=", "/etc/os-release"])
            if "TAILS" in os_id:
                if os.geteuid() == 0:
                    print("\nError: Tails NH-configuration "
                          "must not be as root.\nExiting.\n")
                    exit()

                tails_nh(fast)
            else:
                print("\nError: Unsupported OS. Exiting.\n")
                exit()
        except subprocess.CalledProcessError:
            print("\nError: Unsupported OS. Exiting.\n")
            exit()

    if os.geteuid() != 0:
        print("\nError: TFC installer must be run as root. Exiting.\n")
        exit()

    func_d = None

    while True:

        try:
            if not fast:
                print_menu(os_id)
                selection = int(raw_input("1..4: "))
                print('')

            if os_id == "raspbian":
                func_d = {1: (raspbian_txm, "TxM"),
                          2: (raspbian_rxm, "RxM"),
                          3: (raspbian_nh, "NH"),
                          4: (raspbian_hwrng, "HWRNG")}

            elif os_id == "ubuntu":
                func_d = {1: (ubuntu_txm, "TxM"),
                          2: (ubuntu_rxm, "RxM"),
                          3: (ubuntu_nh, "NH"),
                          4: (local_testing, "local testing")}

            else:
                print("\nError: Unsupported OS. Exiting.\n")
                exit()

            if fast:
                function = func_d[selection][0]
                function(fast)
            else:
                if yes("Install %s configuration for %s?"
                       % (func_d[selection][1], os_id.capitalize())):

                    function = func_d[selection][0]
                    function(fast)
                else:
                    print_on_previous_line()
                    print_on_previous_line()

        except ValueError:
            pass

        except (IndexError, KeyError):
            print_on_previous_line()
            pass

        except KeyboardInterrupt:
            print("\n\nExiting.\n")
            exit()

        for _ in range(13):
            print_on_previous_line()
