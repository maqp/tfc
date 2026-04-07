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

import nacl.exceptions

from typing import Optional as O, TYPE_CHECKING

from src.common.exceptions import CriticalError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.statics import ProgramID
from src.common.types_custom import BoolRekeyDB, BoolReplaceDB
from src.common.utils.strings import separate_trailer
from src.common.utils.io import ensure_dir, get_working_dir
from src.common.statics import CryptoVarLength, DatabaseLiterals, DataDir


if TYPE_CHECKING:
    from src.database.db_masterkey import MasterKey


class TFCDatabase:
    """
    Base-class for TFC's simple atomic databases.
    """

    def __init__(self,
                 database_name : str,
                 program_id    : 'ProgramID'
                 ) -> None:
        """Create new TFCDatabase object."""
        self.__database_name = database_name
        self.__program_id    = program_id

        ensure_dir(self.database_dir)


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            File Names and Paths                           │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def program_id(self) -> 'ProgramID':
        """Return the owning program identifier."""
        return self.__program_id

    @property
    def raw_database_name(self) -> str:
        """Return the unprefixed database name."""
        return self.__database_name

    @property
    def database_name(self) -> str:
        """Return the database name."""
        return f'{self.__program_id}_{self.__database_name}'

    @property
    def database_dir(self) -> str:
        """Return the database directory."""
        return f'{get_working_dir()}/{DataDir.USER_DATA}'

    @property
    def path_to_db(self) -> str:
        """Return the path to the database."""
        return f'{self.database_dir}/{self.database_name}'

    @property
    def path_to_temp_db(self) -> str:
        """Return the path to the temporary database used when replacing database."""
        return f'{self.path_to_db}_temp'

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            Database Protection                            │
    # └───────────────────────────────────────────────────────────────────────────┘

    def protect_database(self, data_to_write: bytes) -> bytes:
        """Protect the database."""
        raise NotImplementedError

    def validate_database(self,
                          file_data  : bytes,
                          path_to_db : O[str] = None
                          ) -> O[bytes]:
        """Validate the database content integrity."""
        raise NotImplementedError

    def verify_file(self, path_to_file: str) -> bool:
        """Verify integrity of database content."""
        with open(path_to_file, 'rb') as f:
            purp_data = f.read()

        return self.validate_database(purp_data) is not None

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Store to Database                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def store_database(self,
                       data_to_write : bytes,
                       replace       : BoolReplaceDB = BoolReplaceDB(True)
                       ) -> None:
        """Encrypt and store data into database."""
        ensure_dir(self.database_dir)

        protected_data = self.protect_database(data_to_write)

        self.ensure_temp_write(protected_data)

        if replace:
            self.replace_database()

    def ensure_temp_write(self, ct_bytes: bytes) -> None:
        """Ensure data is written to a temp file."""
        self.write_to_file(self.path_to_temp_db, ct_bytes)

        retries = 0
        while not self.verify_file(self.path_to_temp_db):
            retries += 1
            if retries >= DatabaseLiterals.DB_WRITE_RETRY_LIMIT:
                raise CriticalError(f"Writing to database '{self.path_to_temp_db}' failed after {retries} retries.")

            self.write_to_file(self.path_to_temp_db, ct_bytes)

    @staticmethod
    def write_to_file(path_to_file: str, data: bytes) -> None:
        """Write data to file."""
        with open(path_to_file, 'wb+') as f:
            f.write(data)

            # Write data from program buffer to operating system buffer.
            f.flush()

            # Run the fsync syscall to ensure operating system buffer is
            # synchronized with storage device, i.e. write the data on disk.
            # https://docs.python.org/3/library/os.html#os.fsync
            # http://man7.org/linux/man-pages/man2/fdatasync.2.html
            os.fsync(f.fileno())

    def replace_database(self) -> None:
        """Replace database with temporary database.

        Replace the original file with a temp file. (`os.replace` is atomic as per
        POSIX requirements): https://docs.python.org/3/library/os.html#os.replace
        """
        if os.path.isfile(self.path_to_temp_db):
            os.replace(self.path_to_temp_db, self.path_to_db)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                               Load Database                               │
    # └───────────────────────────────────────────────────────────────────────────┘

    def load_database(self) -> bytes:
        """Load data from database.

        This function first checks if a temporary file exists from
        previous session. The integrity of the temporary file is
        verified with the Poly1305 MAC before the database is
        replaced.

        The function then reads the up-to-date database content
        and decrypts it.
        """
        if os.path.isfile(self.path_to_temp_db):
            if self.verify_file(self.path_to_temp_db):
                self.replace_database()
            else:
                # If temp file is not authentic, the file is most likely corrupt, so
                # we delete it and continue using the old file to ensure atomicity.
                os.remove(self.path_to_temp_db)

        with open(self.path_to_db, 'rb') as f:
            database_data = f.read()

        validated_data = self.validate_database(database_data, self.path_to_db)
        if validated_data is None:
            raise CriticalError(f'Invalid data in database {self.path_to_db}')

        return validated_data


# ----------------------------------------------------------------------------------------------------------------------


class TFCEncryptedDatabase(TFCDatabase):
    """Encrypted TFC database."""

    def __init__(self,
                 database_name : str,
                 master_key    : 'MasterKey',
                 program_id    : 'ProgramID',
                 rekey         : BoolRekeyDB = BoolRekeyDB(False)
                 ) -> None:
        """Create new TFCEncryptedDatabase object."""
        super().__init__(database_name, program_id)

        self.__master_key     : 'MasterKey'             = master_key
        self.__rekey_database : O[TFCEncryptedDatabase] = None
        self.__rekey_db       : BoolRekeyDB             = rekey

    def set_database_key(self, master_key: 'MasterKey') -> None:
        """Set the database encryption key."""
        self.__master_key = master_key

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            File Names and Paths                           │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def rekey_filename(self) -> str:
        """Return the rekey filename."""
        return f'{self.database_name}_rekey'

    @property
    def path_to_rekey_db(self) -> str:
        """Return the path to the rekey database."""
        return f'{self.database_dir}/{self.rekey_filename}'

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            Database Protection                            │
    # └───────────────────────────────────────────────────────────────────────────┘

    def protect_database(self, data_to_write: bytes) -> bytes:
        """Protect the database"""
        return self.__master_key.encrypt_and_sign(data_to_write, rekey=self.__rekey_db)

    def validate_database(self, file_data: bytes, path_to_db: O[str]=None) -> O[bytes]:
        """Validate the database."""
        try:
            if path_to_db is None:
                return self.__master_key.auth_and_decrypt(file_data, rekey=self.__rekey_db)
            return self.__master_key.auth_and_decrypt(file_data, database=path_to_db, rekey=self.__rekey_db)
        except nacl.exceptions.CryptoError:
            if path_to_db is None:
                return None
            raise CriticalError(f'Invalid data in database {path_to_db}')

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Rekeying                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey', data_to_write: bytes) -> None:
        """Rekey the database to a temporary file."""
        self.__rekey_database = TFCEncryptedDatabase(f'{self.raw_database_name}_rekey',
                                                     new_master_key,
                                                     self.program_id,
                                                     rekey=BoolRekeyDB(True))

        self.__rekey_database.store_database(data_to_write=data_to_write)

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        os.replace(self.path_to_rekey_db, self.path_to_db)


# ----------------------------------------------------------------------------------------------------------------------


class TFCUnencryptedDatabase(TFCDatabase):
    """
    The unencrypted database is used for storing login data.
    """

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            Database Protection                            │
    # └───────────────────────────────────────────────────────────────────────────┘

    def protect_database(self, data_to_write: bytes) -> bytes:
        """Protect the database with simple hash."""
        return data_to_write + blake2b(data_to_write)

    def validate_database(self,
                          file_data  : bytes,
                          path_to_db : O[str] = None
                          ) -> O[bytes]:
        """Validate the database."""

        purp_data, digest = separate_trailer(file_data, CryptoVarLength.BLAKE2_DIGEST)

        if blake2b(purp_data) == digest:
            return purp_data
        if path_to_db is None:
            return None
        raise CriticalError(f'Invalid data in database {path_to_db}')
