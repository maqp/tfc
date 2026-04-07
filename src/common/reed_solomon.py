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

---

This code is an LLM generated Rust port of the public domain Reed-Solomon library

https://github.com/lrq3000/reedsolomon/blob/master/LICENSE
https://github.com/tomerfiliba/reedsolomon/blob/master/LICENSE

It has been checked to produce identical output with the original source code.

Cursory tests showed it's about 85 times faster than the pure Python
implementation. Since all data fed to it is protected by the time its
called, and since it works identically in practice, we see no reason
not to use it.
"""

import importlib.machinery
import importlib.util
import sys

from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Optional

PROJECT_DIR = Path(__file__).resolve().parents[2] / 'reed_solomon'
MODULE_NAME = 'reed_solomon'
BytesLike   = bytes | bytearray | memoryview


class ReedSolomonError(Exception):
    """Raised for Reed-Solomon encode/decode/check failures."""
    pass


def _get_loaded_extension() -> Optional[ModuleType]:
    module = sys.modules.get(MODULE_NAME)
    if module is not None and hasattr(module, 'RSCodec'):
        return module

    if module is not None:
        sys.modules.pop(MODULE_NAME, None)

    return None


def _iter_extension_candidates(project_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    suffixes = list(importlib.machinery.EXTENSION_SUFFIXES)

    for build_dir in ('release', 'debug'):
        target_dir = project_dir / 'target' / build_dir
        deps_dir   = target_dir / 'deps'

        for suffix in suffixes:
            candidates.append(target_dir / f'reed_solomon{suffix}')
            candidates.append(target_dir / f'libreed_solomon{suffix}')
            candidates.extend(sorted(deps_dir.glob(f'reed_solomon*{suffix}')))
            candidates.extend(sorted(deps_dir.glob(f'libreed_solomon*{suffix}')))

        candidates.append(target_dir / 'libreed_solomon.so')

    deduped : list[Path] = []
    seen    : set[Path]  = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)

    return deduped


def _load_extension_from(project_dir: Path) -> Optional[ModuleType]:
    for candidate in _iter_extension_candidates(project_dir):
        if not candidate.is_file():
            continue

        spec = importlib.util.spec_from_file_location(MODULE_NAME, candidate)
        if spec is None or spec.loader is None:
            continue

        sys.modules.pop(MODULE_NAME, None)
        module = importlib.util.module_from_spec(spec)
        sys.modules[MODULE_NAME] = module
        spec.loader.exec_module(module)
        return module

    return None


def _load_reed_solomon_module() -> ModuleType:
    module = _get_loaded_extension()
    if module is not None:
        return module

    if PROJECT_DIR.is_dir():
        module = _load_extension_from(PROJECT_DIR)
        if module is not None:
            return module

    raise ModuleNotFoundError(
        f'Unable to locate the compiled Reed-Solomon extension under {PROJECT_DIR}. '
        'Build it with the installer or run cargo build in reed_solomon/.'
    )


reed_solomon = _load_reed_solomon_module()


def _as_bytes(data: BytesLike | str) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode('latin-1')
    raise TypeError('data must be bytes-like or str')


def _translate_error(exc: Exception) -> ReedSolomonError:
    message = str(exc)
    if message.startswith('ReedSolomonError: '):
        message = message[len('ReedSolomonError: '):]
    return ReedSolomonError(message)


@dataclass(slots=True)
class RSCodec:
    """Bindings wrapper for the vendored Rust Reed-Solomon implementation."""

    nsym       : int  = 10
    nsize      : int  = 255
    fcr        : int  = 0
    prim       : int  = 0x11D
    generator  : int  = 2
    c_exp      : int  = 8
    single_gen : bool = True

    _codec: object = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.c_exp != 8:
            raise ReedSolomonError('this Rust wrapper currently only supports c_exp == 8')
        if not self.single_gen:
            raise ReedSolomonError('this Rust wrapper currently only supports single_gen == True')

        self._reset_codec()

    def _reset_codec(self) -> None:
        try:
            self._codec = reed_solomon.RSCodec(nsym      = int(self.nsym),
                                               nsize     = int(self.nsize),
                                               fcr       = int(self.fcr),
                                               prim      = int(self.prim),
                                               generator = int(self.generator))
        except ValueError as exc:
            raise _translate_error(exc) from None

    def __getstate__(self) -> tuple[int, int, int, int, int, int, bool]:
        """Serialize wrapper configuration without the native PyO3 handle."""
        return (int(self.nsym),
                int(self.nsize),
                int(self.fcr),
                int(self.prim),
                int(self.generator),
                int(self.c_exp),
                bool(self.single_gen))

    def __setstate__(self, state: tuple[int, int, int, int, int, int, bool]) -> None:
        (self.nsym,
         self.nsize,
         self.fcr,
         self.prim,
         self.generator,
         self.c_exp,
         self.single_gen) = state
        self._reset_codec()

    def _validate_nsym(self, nsym: Optional[int]) -> None:
        if nsym is not None and int(nsym) != int(self.nsym):
            raise ReedSolomonError('this Rust wrapper currently only supports nsym == self.nsym')

    def encode(self,
               data : BytesLike | str,
               nsym : Optional[int] = None
               ) -> bytearray:
        """\
        Encode a message (i.e., add the ecc symbols) using Reed-Solomon,
        whatever the length of the message because we use chunking.
        """
        self._validate_nsym(nsym)

        try:
            ret_val = bytearray(self._codec.encode(_as_bytes(data)))  # type: ignore[attr-defined]
            return ret_val
        except ValueError as exc:
            raise _translate_error(exc) from None

    def decode(self,
               data          : BytesLike,
               nsym          : Optional[int]       = None,
               erase_pos     : Optional[list[int]] = None,
               only_erasures : bool = False
               ) -> tuple[bytearray, bytearray]:
        """\
        Repair a message, whatever its size is, by using chunking. May
        return a wrong result if number of errors > nsym. Note that it
        returns a couple of vars: the repaired messages, and the
        repaired messages+ecc (useful for checking).
        """
        self._validate_nsym(nsym)
        erasures = None if erase_pos is None else [int(index) for index in erase_pos]

        try:
            decoded, corrected = self._codec.decode(_as_bytes(data),  # type: ignore[attr-defined]
                                                    erase_pos     = erasures,
                                                    only_erasures = bool(only_erasures))
            return bytearray(decoded), bytearray(corrected)
        except ValueError as exc:
            raise _translate_error(exc) from None

    def check(self, data: BytesLike, nsym: Optional[int] = None) -> list[bool]:
        """\
        Check if a message+ecc stream is not corrupted (or fully repaired).
        Note: may return a wrong result if number of errors > nsym.
        """
        self._validate_nsym(nsym)

        try:
            return list(self._codec.check(_as_bytes(data)))  # type: ignore[attr-defined]
        except ValueError as exc:
            raise _translate_error(exc) from None


__all__ = ['RSCodec', 'ReedSolomonError']
