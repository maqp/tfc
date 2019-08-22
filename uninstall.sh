#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2019  Markus Ottela
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


function yn_prompt {
    echo "${1} (Y/N): "
    read -s -n 1 REPLY

    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        eval $2
    fi
}


function remove_prompt {
    echo ''
    if [[ $(dpkg-query -W -f='${Status}' '$1' 2>/dev/null | grep -c "ok installed") -eq 0 ]]; then
        yn_prompt "Remove ${1} ?" "sudo apt remove ${1} -y"
    fi
}


sudo rm -f /usr/share/pixmaps/tfc.png
sudo rm -f /usr/share/applications/TFC-Dev.desktop
sudo rm -f /usr/share/applications/TFC-Local-test.desktop
sudo rm -f /usr/share/applications/TFC-RP.desktop
sudo rm -f /usr/share/applications/TFC-RP-Tails.desktop
sudo rm -f /usr/share/applications/TFC-RxP.desktop
sudo rm -f /usr/share/applications/TFC-TxP.desktop
sudo rm -rf /opt/tfc/

yn_prompt "Remove user data?" "rm -rf $HOME/tfc/"

clear
echo "The uninstaller will next prompt you to select APT dependencies to uninstall."
echo "If you're unsure about whether you need it, select No."
echo ''

remove_prompt "git"
remove_prompt "libssl-dev"
remove_prompt "net-tools"
remove_prompt "python3-pip"
remove_prompt "python3-setuptools"
remove_prompt "python3-tk"
remove_prompt "terminator"
remove_prompt "tor"

echo ''
echo "TFC has been uninstalled."
