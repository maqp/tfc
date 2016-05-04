#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || setup.py

"""
GPL License

This software is part of the TFC application, which is free software: You can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details. For
a copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.
"""

import getpass
import os
import subprocess
import time


repository = "https://cs.helsinki.fi/u/oottela/tfc-nacl/"
str_version = "0.16.05"


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

kill_ifaces = True   # Kills network after downloading TxM/RxM configuration.


###############################################################################
#                                APT COMMANDS                                 #
###############################################################################

sagi = "sudo apt-get --yes install"


def cmd(command, message=''):
    """
    Display message and run command as subprocess.

    :param command: Command to run.
    :param message: Message to be displayed.
    :return:        None
    """
    if message:
        print("\n%s\n" % message)
    subprocess.Popen(command, shell=True).wait()
    return None


def update_repositories():
    cmd("sudo apt-get --yes update", "Updating repository list")


def install_python_serial():
    cmd("%s python-serial" % sagi, "Installing Python serial")


def install_python_qt4():
    cmd("%s python-qt4" % sagi, "Installing Python QT4")


def install_python_qt4_dbus():
    cmd("%s python-qt4-dbus" % sagi, "Installing Python QT4-DBus")


def install_pidgin():
    cmd("%s pidgin" % sagi, "Installing Pidgin")


def install_pidgin_otr():
    cmd("%s pidgin-otr" % sagi, "Installing Pidgin OTR")


def install_python_setuptools():
    cmd("%s python-setuptools" % sagi, "Installing Python Setuptools")


def install_python_dev():
    cmd("%s python-dev" % sagi, "Installing Python-Dev")


def install_libffi_dev():
    cmd("%s libffi-dev" % sagi, "Installing libffi")


def install_tkinter():
    cmd("%s python-tk" % sagi, "Installing Python Tkinter")


def install_libssl_dev():
    cmd("%s libssl-dev" % sagi, "Installing libssl-Dev")


def install_build_essential():
    cmd("%s build-essential" % sagi, "Installing Build-essential")


###############################################################################
#                            FILE HASH VERIFICATION                           #
###############################################################################

hash_list = ("""
8b0963956bef053454647af16765ca3178749c8a1e773d85a483971870791e74  tfc-mods.zip
a83d34f53dc9b17aa42c9a35c3fbcc5120f3fcb07f7f8721ec45e6a27be347fc  passlb.tar.gz
1898d64e22c03aadce9e6b2936897a4bdc125f17ebbd15a96bdc3f71d7f69cf6  sha3.tar.bz2
be2623c41873e8e8a512a77f93edb301f64377331714b71116f7c30ea4fe6e2a  pyc.zip
64cf1ee26d1cde3c73c6d7d107f835fed7c6a2904aef9eac223d57ad800c43fa  ecdsa.tar.gz
402c44cd30284a6acf80fdb4de56de44b879049f4d0342e28c84ef60223113bc  paramiko.zip
249db300d1fe395ac1c31d08e91a3a31b473214b5da06002503e01229e44ae03  dd.py
45f2c3b9790a0b831609b0cd0b28517c7d0fc5412d8cae3af4f01a99bed554e3  hwrng-nacl.py
fbbd1dac1c4bd63b7f3ede0f65881a8e28cf5a4212dc45b65c7cda35195353cd  NH.py
f55a2b8c84e81400a9c2ef1183deb791f6e8f48280853451fefd20e42e4d338b  Rx.py
e777f8034a924e8df184e5cde54a5a48f0356aa506f255d4dcbdbd3c849c4d1a  setup.py
6c3586d1cbd8f0a388a40c326faf4da2799dc3a88e235addb0efc819156fa211  test_nh.py
1200902f4569373597dc66f555c0a8fce087fcfd1392f2ea5367a0ace1858cb1  test_rx.py
3faf6d2a9ad83e314809605bc1d41bce58565fbe6bc346e5de225832ab610ddc  test_tx.py
6817de77dbf1c2c22dda6951c1c662899cca6e5ca34823bdf4e7a61fb46d5d38  Tx.py
""")


def check_file_hash(filename):
    """
    Verify that SHA-256 hash of file matches the one in installer.

                               WARNING!

    Downloading the installer through TLS-encrypted GitHub website is *NOT* a
    guarantee that a state adversary could not edit the downloaded source code
    on the fly with great ease.

    Unless you can verify the origin of *this* installer, you can NOT trust the
    hashes written above: in other words, the hashes only protect against
    unintentional transmission errors, NOT against malicious actor. You must
    obtain the GPG signing key to verify the authenticity of this installer.

    --------------------------------------------------------------------
    No TLS-MITM attack free way exists to obtain the signing key online.
    --------------------------------------------------------------------

    The only reasonably secure way to obtain the signing key is personal
    handout or GPG Web of Trust with respected and trustworthy members.

    :param filename: File to verify.
    :return:         None
    """

    f_hash = subprocess.check_output(["sha256sum", filename]).split()[0]

    h_list = hash_list.split('\n')
    for h in h_list:
        if filename in h:
            if f_hash not in h:
                os.system("clear")
                print("CRITICAL ERROR: SHA2-256 hash of %s was incorrect. \n"
                      "This might indicate a TLS-MITM attack, transmission\n"
                      "error or that this installer is outdated.\n" % filename)
                exit()

    print("\nSHA256 hash of %s was correct.\n" % filename)
    return None


###############################################################################
#                                CRYPTO LIBRARIES                             #
###############################################################################

def simplesha3_download():
    """
    Download SimpleSHA3 library.

    :return: None
    """

    cmd("wget https://pypi.python.org/packages/source/s/simplesha3/"
        "simplesha3-2015.09.22.post1.tar.bz2 -O sha3.tar.bz2",
        "Downloading SimpleSHA3 library")
    check_file_hash("sha3.tar.bz2")
    return None


def simplesha3_install():
    """
    Install SimpleSHA3 library.

    :return: None
    """

    app_root_directory = os.getcwd()
    cmd("tar -vxjf sha3.tar.bz2", "Unzipping SimpleSHA3")
    os.chdir("simplesha3-2015.09.22.post1/")
    cmd("sudo python setup.py install", "Installing SimpleSHA3")
    os.chdir(app_root_directory)
    cmd("rm sha3.tar.bz2", "Removing install files")
    cmd("sudo rm -r simplesha3-2015.09.22.post1/")
    os.system("clear")
    return None


def pynacl_download():
    """
    Download PyNaCl library.

    :return: None
    """

    cmd("wget https://github.com/maqp/pynacl/archive/tfc-mods.zip",
        "Downloading PyNaCl library")
    check_file_hash("tfc-mods.zip")
    return None


def pynacl_install():
    """
    Install PyNaCl library.

    :return: None
    """

    app_root_directory = os.getcwd()
    cmd("unzip tfc-mods.zip", "Unzipping PyNaCl library", )
    os.chdir("pynacl-tfc-mods/")
    cmd("sudo python setup.py install", "Installing PyNaCl library")
    os.chdir(app_root_directory)
    cmd("rm tfc-mods.zip", "Removing install files")
    os.system("clear")
    return None


def passlib_download():
    """
    Download Passlib.

    :return: None
    """

    cmd("wget https://pypi.python.org/packages/source/p/"
        "passlib/passlib-1.6.5.tar.gz -O passlb.tar.gz",
        "Downloading Passlib")
    check_file_hash("passlb.tar.gz")
    return None


def passlib_install():
    """
    Install Passlib.

    :return: None
    """

    app_root_directory = os.getcwd()
    cmd("tar -xf passlb.tar.gz", "Unzipping Passlib")
    os.chdir("passlib-1.6.5/")
    cmd("sudo python setup.py install", "Installing Passlib")
    os.chdir(app_root_directory)
    cmd("rm passlb.tar.gz", "Removing install files")
    cmd("sudo rm -r passlib-1.6.5/")
    os.system("clear")
    return None


def pycrypto_download():
    """
    Download Py-Crypto library (Paramiko dependency).

    :return: None
    """

    cmd("wget https://github.com/dlitz/pycrypto/archive/master.zip -O pyc.zip",
        "Downloading PyCrypto library")
    check_file_hash("pyc.zip")
    return None


def pycrypto_install():
    """
    Install PyCrypto library (Paramiko dependency).

    :return: None
    """

    app_root_dir = os.getcwd()
    cmd("unzip pyc.zip", "Unzipping PyCrypto Library")
    os.chdir("pycrypto-master/")
    cmd("sudo python setup.py install", "Installing PyCrypto Library")
    os.chdir(app_root_dir)
    cmd("rm pyc.zip", "Removing install files")
    cmd("sudo rm -rf pycrypto-master")
    os.system("clear")
    return None


def ecdsa_download():
    """
    Download ECDSA library (Paramiko dependency).

    :return: None
    """

    cmd("wget https://pypi.python.org/packages/"
        "source/e/ecdsa/ecdsa-0.13.tar.gz -O ecdsa.tar.gz")
    check_file_hash("ecdsa.tar.gz")


def ecdsa_install():
    """
    Install ECDSA library (Paramiko dependency).

    :return: None
    """

    app_root_directory = os.getcwd()
    cmd("tar xf ecdsa.tar.gz", "Unzipping PyNaCl library", )
    os.chdir("ecdsa-0.13/")
    cmd("sudo python setup.py install", "Installing ECDSA library")
    os.chdir(app_root_directory)
    cmd("rm ecdsa.tar.gz", "Removing install files")
    cmd("sudo rm -rf ecdsa-0.13")
    os.system("clear")


def paramiko_download():
    """
    Download Paramiko SSH library.

    :return: None
    """

    cmd("wget https://github.com/maqp/paramiko/"
        "archive/master.zip -O paramiko.zip",
        "Downloading Paramiko SSH Library")
    check_file_hash("paramiko.zip")
    return None


def paramiko_install():
    """
    Install Paramiko SSH library.

    :return: None
    """

    app_root_directory = os.getcwd()
    cmd("unzip paramiko.zip", "Unzipping Paramiko")
    os.chdir("paramiko-master/")
    cmd("sudo python setup.py install", "Installing Paramiko SSH Library")
    os.chdir(app_root_directory)
    cmd("rm paramiko.zip", "Removing install files")
    cmd("sudo rm -r paramiko-master/")
    os.system("clear")
    return None


###############################################################################
#                             DOWNLOAD TFC PROGRAMS                           #
###############################################################################

def get_tx():
    cmd("wget %sTx.py" % repository, "Downloading Tx.py (TxM)")
    check_file_hash("Tx.py")

    cmd("wget %sunittests/test_tx.py" % repository,
        "Downloading test_tx.py (TxM)")
    check_file_hash("test_tx.py")


def get_rx():
    cmd("wget %sRx.py" % repository, "Downloading Rx.py (RxM)")
    check_file_hash("Rx.py")

    cmd("wget %sunittests/test_rx.py" % repository,
        "Downloading test_rx.py (RxM)")
    check_file_hash("test_rx.py")


def get_nh():
    cmd("wget %sNH.py" % repository, "Downloading NH.py (NH)")
    check_file_hash("NH.py")

    cmd("wget %sunittests/test_nh.py" % repository,
        "Downloading test_nh.py (NH)")
    check_file_hash("test_nh.py")


def get_hwrng():
    cmd("wget %shwrng-nacl.py" % repository, "Downloading hwrng-nacl.py")
    check_file_hash("hwrng-nacl.py")


def get_dd():
    cmd("wget %sdd.py" % repository, "Downloading dd.py (NH)")
    check_file_hash("dd.py")


###############################################################################
#                               EDIT TFC PROGRAMS                             #
###############################################################################

def rasp_disable_boot_info():
    """
    Disable Boot info through serial port to keep input of NH serial interface
    only related to Tx.py output.

    :return: None
    """

    print("\nEditing file 'cmdline.txt'.\n")

    try:
        content = open("/boot/cmdline.txt").readline()
        content = content.replace(" console=ttyAMA0,115200", '')
        open("/boot/cmdline.txt", "w+").write(content)

    except IOError:
        print("CRITICAL ERROR! M(rasp_disable_boot_info):\n"
              "/boot/cmdline.txt could not be accessed.\n"
              "Exiting setup.py")
        exit()

    return None


def ssh_hwrng_connection():
    """
    Ask user whether they will use Raspbian over SSH to load entropy. If yes,
    enable SSH client for Tx.py.

    :return: None
    """

    if not yes("Will TxM load entropy from Raspberry Pi over SSH?"):
        return None

    print("\nEnabling SSH client during key generation\n")
    contents = open("Tx.py").read()
    contents = contents.replace("use_ssh_hwrng = False",
                                "use_ssh_hwrng = True")
    open("Tx.py", "w+").write(contents)

    ssh_config()

    return None


def ssh_config():
    """
    Configure Tx.py SSH settings

    :return: None
    """

    if yes("Configure HWRNG host/IP, username and password?"):

        host = "192.186.1.2"
        user = "pi"
        pswd = "raspberry"

        while True:
            os.system("clear")
            print("Configure TxM SSH login settings: ")
            host = raw_input("\nEnter Host/IP:    ")
            user = raw_input("Enter Username:   ")
            while True:
                pwd = getpass.getpass("Enter password:   ")
                pwd_again = getpass.getpass("Confirm password: ")
                if pwd == pwd_again:
                    break
                else:
                    print("\nError: Passwords did not match\n")

            if yes("Accept configuration?"):
                break

        content = open("Tx.py").read()
        content = content.replace('hwrng_host = "192.168.1.2"',
                                  'hwrng_host = "%s"' % host)

        content = content.replace('hwrng_name = "pi"',
                                  'hwrng_name = "%s"' % user)
        content = content.replace('hwrng_pass = "192.168.1.2"',
                                  'hwrng_pass = "%s"' % pswd)

        open("Tx.py", "w+").write(content)

    return None


def serial_config_raspbian(program):
    """
    Ask user whether they will use USB to serial adapter.
    Answering no enables Raspberry Pi's integrated interface /dev/ttyAMA0.

    :param program: Program the serial interface of which is changed.
    :return:        None
    """

    if program == "Tx.py":
        if yes("Will TxM connect to NH using USB to serial adapter?"):
            return None

    if program == "Rx.py":
        if yes("Will RxM connect to NH using USB to serial adapter?"):
            return None

    print("\nChanging %s's NH serial-interface to integrated.\n" % program)
    contents = open(program).read()
    contents = contents.replace("nh_usb_adapter = True",
                                "nh_usb_adapter = False")
    open(program, "w+").write(contents)
    return None


def serial_config_integrated(program):
    """
    Ask user whether they will use USB to serial adapter.
    Answering no enables integrated interface /dev/ttyS0.

    :param program: Program the serial interface of which is changed.
    :return:        None
    """

    if program == "NH.py":
        if yes("Will NH connect to TxM using USB to serial adapter?"):
            pass
        else:
            print("\nChanging NH.py's TxM serial-interface to integrated.\n")
            contents = open(program).read()
            contents = contents.replace("txm_usb_adapter = True",
                                        "txm_usb_adapter = False")
            open(program, "w+").write(contents)

        if yes("Will NH connect to RxM using USB to serial adapter?"):
            pass
        else:
            print("\nChanging NH.py's RxM serial-interface to integrated.\n")
            contents = open(program).read()
            contents = contents.replace("rxm_usb_adapter = True",
                                        "rxm_usb_adapter = False")
            open(program, "w+").write(contents)
        return None

    if program == "Tx.py":
        if yes("Will TxM connect to NH using USB to serial adapter?"):
            return None

    if program == "Rx.py":
        if yes("Will RxM connect to NH using USB to serial adapter?"):
            return None

    print("\nChanging %s's NH serial-interface to integrated.\n" % program)
    contents = open(program).read()
    contents = contents.replace("nh_usb_adapter = True",
                                "nh_usb_adapter = False")
    open(program, "w+").write(contents)
    return None


def change_to_local(file_name):
    """
    Configure {Tx,Rx,NH}.py local_testing boolean to True.

    :param file_name: Target program from which local_testing is enabled.
    :return:          None
    """

    print("\nEnabling 'local_testing' boolean in program '%s'.\n" % file_name)
    content = open(file_name).read()
    content = content.replace("local_testing = False",
                              "local_testing = True")
    open(file_name, "w+").write(content)
    return None


###############################################################################
#                                    MISC                                     #
###############################################################################

def set_serial_permissions(username=''):
    """
    Add username to 'dialout' group to allow operation
    of serial port without root privileges.

    :param username: Username to be added.
    :return:         None
    """

    if username == '':
        while True:
            print("\nType name of the user that will be running TFC to add\n"
                  "them to dialout group, that enables serial interfaces.")
            username = raw_input("\n  >")
            if yes("\n  Confirm user '%s'?" % username):
                break
    cmd("sudo gpasswd --add %s dialout" % username)

    return None


def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked.
    :return:       True if user types 'y' or 'yes', otherwise returns False.
    """

    while True:
        try:
            answer = raw_input("%s (y/n): " % prompt)

        except KeyboardInterrupt:
            raise

        if answer.lower() in ("yes", 'y'):
            return True

        elif answer.lower() in ("no", 'n'):
            return False


def print_menu():
    """
    Display the menu with list of installation configurations.

    :return: None
    """

    print("TFC-NaCl %s || setup.py" % str_version)
    print("""
Select a device-OS configuration (tested distros are listed):

   TxM
      1.  Raspbian Jessie (Run this installer as sudo)

      2.  Ubuntu 16.04 LTS
          Kubuntu 16.04 LTS
          Xubuntu 16.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

   HWRNG (over SSH from TxM)
      3.  Raspbian Jessie (Run this installer as sudo)

   RxM
      4.  Raspbian Jessie (Run this installer as sudo)

      5.  Ubuntu 16.04 LTS
          Kubuntu 16.04 LTS
          Xubuntu 16.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

    NH
      6.  Raspbian Jessie (Run this installer as sudo)

      7.  Ubuntu 16.04 LTS
          Kubuntu 16.04 LTS
          Xubuntu 16.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

      8.  Tails 2.2.1

    Local Testing (insecure)
      9.  Ubuntu  16.04 LTS
          Kubuntu 16.04 LTS
          Xubuntu 16.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa\n""")

    return None


def print_local_tester_warning():
    """
    Display a warning about insecurity of local testing.

    :return: None
    """

    print("\n                             WARNING!                         \n"
          "  YOU HAVE SELECTED THE LOCAL TESTING CONFIGURATION FOR TFC.    \n"
          "  THIS VERSION IS INTENDED ONLY FOR TRYING OUT THE FEATURES AND \n"
          "  STABILITY OF THE SYSTEM. IN THIS CONFIGURATION, THE ENCRYPTION\n"
          "  KEYS ARE GENERATED, STORED AND HANDLED ON NETWORK-CONNECTED   \n"
          "  COMPUTER, SO ANYONE WHO BREAKS IN TO IT BY EXPLOITING A KNOWN \n"
          "  (OR UNKNOWN ZERO DAY) VULNERABILITY, CAN DECRYPT AND/OR FORGE \n"
          "  ALL MESSAGES YOU SEND AND RECEIVE!")

    return None


def print_local_test_install_finish():

    print("\n  Test folder 'tfc-nacl' has been generated. Initiate \n"
          "  OTR-encrypted Pidgin conversation and run Tx.py, Rx.py\n"
          "  and NH.py in their own terminals.\n")


def disable_network_interfaces():
    """
    This will kill all active network interfaces from TxM / RxM to minimize the
    remote compromise time window of the TCB device.

    :return: None
    """

    cmd("ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' > tfc_ifaces")
    iface_list = open("tfc_ifaces").read().splitlines()
    os.remove("tfc_ifaces")

    for i in iface_list:
        cmd("sudo ifconfig %s down" % i, "Disabling %s network interface" % i)


###############################################################################
#                              INSTALL ROUTINES                               #
###############################################################################

def raspbian_txm():
    if yes("Install TxM configuration for Raspbian Jessie?"):

        if os.geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_build_essential()
        install_python_dev()
        install_libffi_dev()
        install_libssl_dev()
        install_python_serial()
        install_tkinter()

        passlib_download()
        simplesha3_download()
        pynacl_download()

        cmd("mkdir tfc-nacl")
        root_dir = os.getcwd()
        os.chdir("tfc-nacl/")
        get_tx()

        disable_network_interfaces()

        os.chdir(root_dir)
        passlib_install()
        simplesha3_install()
        pynacl_install()

        rasp_disable_boot_info()

        os.chdir("tfc-nacl/")
        serial_config_raspbian("Tx.py")
        set_serial_permissions()

        os.system("clear")
        print("\nTxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()


def ubuntu_txm():

    if yes("Install TxM configuration for *buntu / Linux Mint?"):

        if os.geteuid() != 0 and kill_ifaces:
            print("\nError: Ubuntu installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_build_essential()
        install_python_dev()
        install_libffi_dev()
        install_libssl_dev()
        install_python_serial()
        install_tkinter()

        passlib_download()
        pycrypto_download()
        ecdsa_download()
        paramiko_download()
        simplesha3_download()
        pynacl_download()

        cmd("mkdir tfc-nacl")
        root_dir = os.getcwd()
        os.chdir("tfc-nacl/")

        get_tx()

        disable_network_interfaces()

        os.chdir(root_dir)
        passlib_install()
        pycrypto_install()
        ecdsa_install()
        paramiko_install()
        simplesha3_install()
        pynacl_install()

        os.chdir("tfc-nacl/")
        serial_config_integrated("Tx.py")
        ssh_hwrng_connection()
        set_serial_permissions()

        os.system("clear")
        print("\nTxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def raspbian_hwrng():
    if yes("Install HWRNG configuration for Raspbian Jessie?"):

        if os.geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        get_hwrng()

        os.system("clear")
        print("\nHWRNG side installation complete.\n"
              "Disconnect this RasPi from Internet.\n"
              "Connect it to the TxM device")
        time.sleep(3)
        print("Rebooting...")
        time.sleep(2)
        cmd("sudo reboot")


def raspbian_rxm():
    if yes("Install RxM configuration for Raspbian Jessie?"):

        if os.geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_build_essential()
        install_python_dev()
        install_libffi_dev()
        install_libssl_dev()
        install_python_serial()
        install_tkinter()

        passlib_download()
        simplesha3_download()
        pynacl_download()

        cmd("mkdir tfc-nacl")
        root_dir = os.getcwd()
        os.chdir("tfc-nacl/")
        get_rx()

        disable_network_interfaces()

        os.chdir(root_dir)
        passlib_install()
        simplesha3_install()
        pynacl_install()

        rasp_disable_boot_info()

        os.chdir("tfc-nacl/")
        serial_config_raspbian("Rx.py")
        set_serial_permissions()

        os.system("clear")
        print("\nRxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def ubuntu_rxm():
    if yes("Install RxM configuration for *buntu / Linux Mint?"):

        if os.geteuid() != 0 and kill_ifaces:
            print("\nError: Ubuntu installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_build_essential()
        install_python_dev()
        install_libffi_dev()
        install_libssl_dev()
        install_python_serial()
        install_tkinter()

        passlib_download()
        simplesha3_download()
        pynacl_download()

        cmd("mkdir tfc-nacl")
        root_dir = os.getcwd()
        os.chdir("tfc-nacl/")
        get_rx()

        disable_network_interfaces()

        os.chdir(root_dir)
        passlib_install()
        simplesha3_install()
        pynacl_install()

        os.chdir("tfc-nacl/")
        serial_config_integrated("Rx.py")
        set_serial_permissions()

        os.system("clear")
        print("\nRxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def raspbian_nh():
    if yes("Install NH configuration for Raspbian?"):

        if os.geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()
        install_python_qt4()
        install_python_qt4_dbus()
        install_python_serial()

        if yes("\nInstall Pidgin with OTR-plugin?"):
            install_pidgin()
            install_pidgin_otr()

        get_nh()
        serial_config_integrated("NH.py")
        set_serial_permissions()

        os.system("clear")
        print("\nNH side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def ubuntu_nh():
    if yes("Install NH configuration for *buntu / Linux Mint?"):

        update_repositories()
        install_python_qt4()
        install_python_qt4_dbus()
        install_python_serial()

        if yes("\nInstall Pidgin with OTR-plugin?"):
            install_pidgin()
            install_pidgin_otr()

        get_nh()
        serial_config_integrated("NH.py")
        set_serial_permissions()

        os.system("clear")
        print("\nNH side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def tails_nh():
    if yes("Install NH configuration for Tails LiveCD / LiveUSB?"):

        update_repositories()
        install_python_serial()
        install_python_qt4_dbus()

        get_nh()
        serial_config_integrated("NH.py")
        set_serial_permissions("amnesia")

        os.system("clear")
        print("\nNH install script completed. Initiate OTR-encrypted\n"
              "Pidgin conversation and launch NH.py.\n\nExiting.\n")
        exit()

    else:
        return None


def local_testing():
    os.system("clear")
    print_local_tester_warning()

    if not raw_input("\n  TYPE 'INSECURE' TO VERIFY "
                     "YOU UNDERSTAND THE RISKS: ") == "INSECURE":
        return None

    os.system("clear")

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

    if yes("\n  Install Pidgin with OTR-plugin?"):
        install_pidgin()
        install_pidgin_otr()

    subprocess.Popen("mkdir tfc-nacl", shell=True).wait()
    os.chdir("tfc-nacl/")

    get_tx()
    get_rx()
    get_nh()
    get_dd()

    change_to_local("Tx.py")
    change_to_local("Rx.py")
    change_to_local("NH.py")

    ssh_hwrng_connection()

    os.system("clear")
    print_local_test_install_finish()
    print("  Exiting setup.py\n")
    exit()


######################################################################
#                              MAIN LOOP                             #
######################################################################

while True:
    try:
        os.system("clear")
        print_menu()
        selection = int(raw_input("1..9: "))

        if selection == 1:
            raspbian_txm()

        if selection == 2:
            ubuntu_txm()

        if selection == 3:
            raspbian_hwrng()

        if selection == 4:
            raspbian_rxm()

        if selection == 5:
            ubuntu_rxm()

        if selection == 6:
            raspbian_nh()

        if selection == 7:
            ubuntu_nh()

        if selection == 8:
            tails_nh()

        if selection == 9:
            local_testing()

    except (ValueError, IndexError):
        continue

    except KeyboardInterrupt:
        print("\n\nExiting.\n")
        exit()
