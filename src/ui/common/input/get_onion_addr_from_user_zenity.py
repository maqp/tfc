#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

import os
import subprocess

from typing import TYPE_CHECKING, Optional as O

from src.common.exceptions import CheckInputError, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact, OnionPublicKeyUser
from src.common.utils.validators import validate_onion_addr

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


class GetAccountFromUser:
    """Get correct account of contact from the user via Zenity prompt."""

    def __init__(self,
                 queues             : 'RelayQueue',
                 onion_pub_key_user : OnionPublicKeyUser
                 ) -> None:
        """Prompt the user for an account and store the result in the queue."""
        self.queue              = queues.from_gui_to_diff_comp_user_selected_account
        self.onion_address_user = onion_pub_key_user.onion_address
        self.prompt_account()

    @staticmethod
    def _has_gui_display() -> bool:
        """Return True when a graphical session is available for Zenity."""
        return any(os.environ.get(var) for var in ('DISPLAY', 'WAYLAND_DISPLAY'))

    @staticmethod
    def _run_zenity(command: list[str]) -> O[subprocess.CompletedProcess[str]]:
        """Run Zenity and return its completed process, or None when unavailable."""
        try:
            return subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError:
            return None

    def prompt_account(self) -> None:
        """Display Zenity prompt until a valid account is entered or the dialog is dismissed."""
        if not self._has_gui_display():
            self.dismiss_window()
            return

        prompt_msg = ('Could not determine the account being added.\n'
                      'Please paste the account here to see diffs\n'
                      'or press Cancel to dismiss this prompt.')
        entry_text = ''

        while True:
            completed = self._run_zenity(['zenity',
                                          '--entry',
                                          '--title=Contact account entry',
                                          f'--text={prompt_msg}',
                                          f'--entry-text={entry_text}',
                                          '--width=540'])

            if completed is None or completed.returncode != 0:
                self.dismiss_window()
                return

            purp_acco = completed.stdout.rstrip('\r\n')

            if self.evaluate_account(purp_acco):
                return

            entry_text = purp_acco

    def evaluate_account(self, purp_acco: str) -> bool:
        """Check if the input is a valid TFC account."""
        try:
            validate_onion_addr(purp_acco, onion_address_user=self.onion_address_user)
        except (CheckInputError, ValidationError) as exc:
            self.show_error(str(exc))
            return False

        validated_pub_key = OnionPublicKeyContact.from_onion_address(purp_acco)
        self.queue.put(validated_pub_key)
        return True

    def show_error(self, error_msg: str) -> None:
        """Display Zenity error dialog for invalid account input."""
        self._run_zenity(['zenity',
                          '--error',
                          '--title=Invalid account',
                          f'--text={error_msg}',
                          '--width=420'])

    def dismiss_window(self) -> None:
        """Dismiss the account input window."""
        self.queue.put(None)
