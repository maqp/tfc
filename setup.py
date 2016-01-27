#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.01 beta || setup.py

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

from os import chdir, getcwd, system, geteuid
from subprocess import Popen, check_output

str_version = "0.16.01 beta"
int_version = 1601

repository = "https://raw.githubusercontent.com/maqp/tfc-nacl/master/"


###############################################################################
#                                APT COMMANDS                                 #
###############################################################################

sagi = "sudo apt-get --yes install"


def cmd(message, command):
    """
    Display message and run command as subprocess.

    :param message: Message to be displayed.
    :param command: Command to run.
    :return:        None
    """

    print("\n%s\n" % message)
    Popen(command, shell=True).wait()
    return None


def update_repositories():
    cmd("Updating repository list", "sudo apt-get --yes update")


def install_python_serial():
    cmd("Installing Python serial", "%s python-serial" % sagi)


def install_python_qt4():
    cmd("Installing Python QT4", "%s python-qt4" % sagi)


def install_python_qt4_dbus():
    cmd("Installing Python QT4-DBus", "%s python-qt4-dbus" % sagi)


def install_pidgin():
    cmd("Installing Pidgin", "%s pidgin" % sagi)


def install_pidgin_otr():
    cmd("Installing Pidgin OTR", "%s pidgin-otr" % sagi)


def install_python_pip():
    cmd("Installing Python pip", "%s python-pip" % sagi)


def install_python_setuptools():
    cmd("Installing Python Setuptools", "%s python-setuptools" % sagi)


def install_python_dev():
    cmd("Installing Python-Dev", "%s python-dev" % sagi)


def install_libffi_dev():
    cmd("Installing libffi", "%s libffi-dev" % sagi)


def install_tkinter():
    cmd("Installing Python Tkinter", "%s python-tk" % sagi)


###############################################################################
#                                PIP COMMANDS                                 #
###############################################################################

def pip_passlib():
    cmd("Installing PassLib", "sudo pip install passlib")


def pip_simplesha3():
    cmd("Installing SimpleSHA3", " sudo pip install simplesha3")


def pip_paramiko():
    cmd("Installing SimpleSHA3", " sudo pip install paramiko")


###############################################################################
#                            FILE HASH VERIFICATION                           #
###############################################################################

hash_list = ("""
b7093331d65eaf36b218f105a0b7a710ade5cf520b96da4f4b580600adf4ad71  tfc-mods.zip
c76c6ec69dc7b233dc58aff42b45d87e8ec8f8e4e32ecf790260ca9e436ec42f  dd.py
264889d2d2f06d258035bec8baa2e1300f42805d2d6b1987faf1c5cb6e72bbf7  hwrng.py
142cb4cb8ba803880015ccd3a82d5428a4480f4e7e463245977ba797ebf72565  NH.py
d101d5a1308a09a79824d2652dcad0319c504e50a71d96fee9d3d189df50a946  Rx.py
af392c14f4390103ab9f28d042b8dc353b1d9f5590aff01d9a456047c6babd4d  test_nh.py
acd7ca80c2b7b3f15c5a588d0dfc858246f1675456d787d655e7af093d5ab2ed  test_rx.py
73a01d9176f883e16b48858ee62ae847f09b9ab0e663db5a4f8628081638a0b9  test_tx.py
1553911611f2ebdd54c55d8c2d9ef822378169a0c3ea8e66495c2d6ae73346d5  Tx.py
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
    handout of key or GPG Web of Trust with respected and trustworthy members.

    :param filename: File to verify.
    :return:         None
    """

    f_hash = check_output(["sha256sum", filename]).split()[0]

    h_list = hash_list.split('\n')
    for h in h_list:
        if filename in h:
            if f_hash not in h:
                system("clear")
                print("CRITICAL ERROR: SHA2-256 hash of %s was incorrect. \n"
                      "This might indicate a TLS-MITM attack, transmission\n"
                      "error or that this installer is outdated.\n") % filename
                exit()

    print("\nSHA256 hash of %s was correct.\n" % filename)
    return None


###############################################################################
#                            CRYPTO LIBRARIES COMMANDS                        #
###############################################################################

def pynacl_install():
    """
    Install the PyNaCl library.

    :return: None
    """

    app_root_directory = getcwd()

    cmd("Downloading PyNaCl Library", "wget https://github.com/maqp/"
                                      "pynacl/archive/tfc-mods.zip")

    check_file_hash("tfc-mods.zip")

    cmd("Unzipping PyNaCl Library", "unzip tfc-mods.zip")

    chdir("pynacl-tfc-mods/")

    cmd("Installing PyNaCl Library", "sudo python setup.py install")

    chdir(app_root_directory)

    cmd("Removing PyNaCl (tfc-mods.zip)", "rm tfc-mods.zip")

    Popen("sudo rm -r pynacl-master/", shell=True).wait()

    system("clear")

    if not yes("\n  Keep PyNaCl source files?\n"):
        Popen("sudo rm -rf pynacl-tfc-mods", shell=True).wait()

    return None


###############################################################################
#                             DOWNLOAD TFC PROGRAMS                           #
###############################################################################

def get_tx():
    cmd("Downloading Tx.py (TxM)", "wget %sTx.py" % repository)
    check_file_hash("Tx.py")

    cmd("Downloading test_tx.py (TxM)", "wget %sunittests/test_tx.py"
        % repository)
    check_file_hash("test_tx.py")


def get_hwrng():
    cmd("Downloading hwrng.py", "wget %shwrng.py" % repository)
    check_file_hash("hwrng.py")


def get_rx():
    cmd("Downloading Rx.py (RxM)", "wget %sRx.py" % repository)
    check_file_hash("Rx.py")

    cmd("Downloading test_rx.py (RxM)", "wget %sunittests/test_rx.py"
        % repository)
    check_file_hash("test_rx.py")


def get_nh():
    cmd("Downloading NH.py (NH)", "wget %sNH.py" % repository)
    check_file_hash("NH.py")

    cmd("Downloading test_nh.py (NH)", "wget %sunittests/test_nh.py"
        % repository)
    check_file_hash("test_nh.py")


def get_dd():
    cmd("Downloading dd.py (NH)", "wget %sdd.py" % repository)
    check_file_hash("dd.py")


###############################################################################
#                               EDIT TFC PROGRAMS                             #
###############################################################################

def rasp_disable_boot_info():
    """
    Disable Boot info through serial port to keep NH's TxM serial interface's
    input only related to Tx.py output.

    :return: None
    """

    print("\nEditing file 'cmdline.txt'.\n")

    try:
        content = open('/boot/cmdline.txt').readline()
        content = content.replace(" console=ttyAMA0,115200", '')
        open('/boot/cmdline.txt', 'w+').write(content)

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

    return None


def serial_config_raspbian(program):
    """
    Ask user whether they will use USB serial interface.
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
    cmd('', "sudo gpasswd --add %s dialout" % username)

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

      2.  Ubuntu 14.04 LTS
          Kubuntu 14.04 LTS
          Xubuntu 14.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

   HWRNG (over SSH from TxM)
      3.  Raspbian Jessie (Run this installer as sudo)

   RxM
      4.  Raspbian Jessie (Run this installer as sudo)

      5.  Ubuntu 14.04 LTS
          Kubuntu 14.04 LTS
          Xubuntu 14.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

    NH
      6.  Ubuntu 14.04 LTS
          Kubuntu 14.04 LTS
          Xubuntu 14.04 LTS
          Lubuntu 15.04
          Linux Mint 17.3 Rosa

      7.  Tails 2.0

    Local Testing (insecure)
      8.  Ubuntu  14.04 LTS
          Kubuntu 14.04 LTS
          Xubuntu 14.04 LTS
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


###############################################################################
#                              INSTALL ROUTINES                               #
###############################################################################

def raspbian_txm():
    if yes("Install TxM configuration for Raspbian Jessie?"):

        if geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_python_dev()
        install_libffi_dev()

        install_python_pip()
        pip_passlib()
        pip_simplesha3()
        pynacl_install()

        rasp_disable_boot_info()

        Popen("mkdir tfc-nacl", shell=True).wait()
        chdir("tfc-nacl/")

        get_tx()
        serial_config_raspbian("Tx.py")
        set_serial_permissions()

        system("clear")
        print("\nTxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()


def raspbian_hwrng():
    if yes("Install HWRNG configuration for Raspbian Jessie?"):
        
        if geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_python_dev()
        install_libffi_dev()    

        install_python_pip()
        pip_simplesha3()

        get_hwrng()

        system("clear")
        print("\nHWRNG side installation complete.\n"
              "Reboot the system before running.\n")
        exit()


def ubuntu_txm():
    if yes("Install TxM configuration for *buntu / Linux Mint?"):

        update_repositories()
        install_python_serial()
        install_tkinter()

        install_python_setuptools()
        install_python_dev()
        install_libffi_dev()

        install_python_pip()
        pip_passlib()
        pip_simplesha3()
        pip_paramiko()
        pynacl_install()

        Popen("mkdir tfc-nacl", shell=True).wait()
        chdir("tfc-nacl/")

        get_tx()
        serial_config_integrated("Tx.py")
        ssh_hwrng_connection()
        set_serial_permissions()

        system("clear")
        print("\nTxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def raspbian_rxm():
    if yes("Install RxM configuration for Raspbian Jessie?"):

        if geteuid() != 0:
            print("\nError: Raspbian installer requires root privileges.\n"
                  "\nExiting.\n")
            exit()

        update_repositories()

        install_python_setuptools()
        install_python_dev()
        install_libffi_dev()

        install_python_pip()
        pip_passlib()
        pip_simplesha3()
        pynacl_install()

        rasp_disable_boot_info()

        Popen("mkdir tfc-nacl", shell=True).wait()
        chdir("tfc-nacl/")

        get_rx()
        serial_config_raspbian("Rx.py")
        set_serial_permissions()

        system("clear")
        print("\nRxM side installation complete.\n"
              "Reboot the system before running.\n")
        exit()

    else:
        return None


def ubuntu_rxm():
    if yes("Install RxM configuration for *buntu / Linux Mint?"):

        update_repositories()
        install_python_serial()

        install_python_setuptools()
        install_python_dev()
        install_libffi_dev()

        install_python_pip()
        pip_passlib()
        pip_simplesha3()
        pynacl_install()

        Popen("mkdir tfc-nacl", shell=True).wait()
        chdir("tfc-nacl/")

        get_rx()
        serial_config_integrated("Rx.py")
        set_serial_permissions()

        system("clear")
        print("\nRxM side installation complete.\n"
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

        system("clear")
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

        set_serial_permissions("amnesia")
        get_nh()
        serial_config_integrated("NH.py")

        system("clear")
        print("\nNH install script completed. Initiate OTR-encrypted\n"
              "Pidgin conversation and launch NH.py.\n\nExiting.\n")
        exit()

    else:
        return None


def local_testing():
    system("clear")
    print_local_tester_warning()

    if not raw_input("\n  TYPE 'INSECURE' TO VERIFY "
                     "YOU UNDERSTAND THE RISKS: ") == "INSECURE":
        return None

    system("clear")

    update_repositories()

    install_python_qt4()
    install_python_qt4_dbus()
    install_python_serial()
    install_tkinter()

    install_python_setuptools()
    install_python_dev()
    install_libffi_dev()

    install_python_pip()
    pip_passlib()
    pip_simplesha3()
    pip_paramiko()
    pynacl_install()

    if yes("\n  Install Pidgin with OTR-plugin?"):
        install_pidgin()
        install_pidgin_otr()

    Popen("mkdir tfc-nacl", shell=True).wait()
    chdir("tfc-nacl/")

    get_tx()
    get_nh()
    get_rx()
    get_dd()

    change_to_local("Tx.py")
    change_to_local("Rx.py")
    change_to_local("NH.py")
    ssh_hwrng_connection()

    system("clear")
    print_local_test_install_finish()
    print("  Exiting.\n")
    exit()


######################################################################
#                              MAIN LOOP                             #
######################################################################

while True:
    try:
        system("clear")
        print_menu()
        selection = int(raw_input("1..8: "))

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
            ubuntu_nh()

        if selection == 7:
            tails_nh()

        if selection == 8:
            local_testing()

    except (ValueError, IndexError):
        continue

    except KeyboardInterrupt:
        print("\n\nExiting.\n")
        exit()
