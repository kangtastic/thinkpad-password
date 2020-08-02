#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# thinkpad-password: Lenovo ThinkPad HDD Password Algorithm
# Copyright (C) 2020  James Seo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import getpass
import os
import re
import sys
from hashlib import sha256
from typing import Any, AnyStr, ByteString, Optional

_SCAN_CHAR = "1234567890", "qwertyuiop", "asdfghjkl;", "zxcvbnm", " "
_SCAN_CODE = range(2, 12), range(16, 26), range(30, 40), range(44, 51), (57,)
SCANCODE_MAP = {k: v for kv in zip(_SCAN_CHAR, _SCAN_CODE) for k, v in zip(*kv)}

# cf. ACS-4 7.12.3 (et al.; previous versions of ACS say the same)
ATA_IDENTIFY_DEVICE_SIZE = 512
ATA_IDENTIFY_DEVICE_CMD = 0xEC

if sys.platform == "win32":
    from ctypes import (
        WINFUNCTYPE,
        Structure,
        WinError,
        byref,
        create_string_buffer,
        sizeof,
        windll,
    )
    from ctypes.wintypes import BOOL, BYTE, DWORD, HANDLE, LPCWSTR, LPDWORD, LPVOID

    # fileapi.h, handleapi.h, ntdddisk.h, winioctl.h, winnt.h
    FILE_SHARE_READ = 0x00000001
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    ID_CMD = ATA_IDENTIFY_DEVICE_CMD
    INVALID_HANDLE_VALUE = HANDLE(-1).value
    OPEN_EXISTING = 3
    SMART_RCV_DRIVE_DATA = 0x7C088

    # for converting /dev/sd[a-z] to \\.\PhysicalDrive[0, 25]
    DISK_ID_MAP = dict(zip("abcdefghijklmnopqrstuvwxyz", range(1, 27)))

    class IDEREGS(Structure):
        _fields_ = [
            ("bFeaturesReg", BYTE),
            ("bSectorCountReg", BYTE),
            ("bSectorNumberReg", BYTE),
            ("bCylLowReg", BYTE),
            ("bCylHighReg", BYTE),
            ("bDriveHeadReg", BYTE),
            ("bCommandReg", BYTE),
            ("bReserved", BYTE),
        ]

    class DRIVERSTATUS(Structure):
        _pack_ = 1
        _fields_ = [
            ("bDriverError", BYTE),
            ("bIDEError", BYTE),
            ("bReserved", BYTE * 2),
            ("dwReserved", DWORD * 2),
        ]

    class SENDCMDINPARAMS(Structure):
        _pack_ = 1
        _fields_ = [
            ("cBufferSize", DWORD),
            ("irDriveRegs", IDEREGS),
            ("bDriveNumber", BYTE),
            ("bReserved", BYTE * 3),
            ("dwReserved", DWORD * 4),
            ("bBuffer", BYTE),
        ]

    class SENDCMDOUTPARAMS(Structure):
        _pack_ = 1
        _fields_ = [
            ("cBufferSize", DWORD),
            ("DriverStatus", DRIVERSTATUS),
            ("bBuffer", BYTE),
        ]

    CreateFile = WINFUNCTYPE(
        HANDLE, LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE
    )(
        ("CreateFileW", windll.kernel32),
        (
            (1, "lpFileName"),
            (1, "dwDesiredAccess", GENERIC_READ | GENERIC_WRITE),
            (1, "dwShareMode", FILE_SHARE_READ),
            (1, "lpSecurityAttributes", None),
            (1, "dwCreationDisposition", OPEN_EXISTING),
            (1, "dwFlagsAndAttributes", 0),
            (1, "hTemplateFile", None),
        ),
    )

    CloseHandle = WINFUNCTYPE(BOOL, HANDLE)(
        ("CloseHandle", windll.kernel32), ((1, "hObject"),)
    )

    DeviceIoControl = WINFUNCTYPE(
        BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID
    )(
        ("DeviceIoControl", windll.kernel32),
        (
            (1, "hDevice"),
            (1, "dwIoControlCode"),
            (1, "lpInBuffer"),
            (1, "nInBufferSize"),
            (1, "lpOutBuffer"),
            (1, "nOutBufferSize"),
            (1, "lpBytesReturned"),
            (1, "lpOverlapped", None),
        ),
    )
elif sys.platform == "linux":
    from fcntl import ioctl

    # linux/hdreg.h
    HDIO_DRIVE_CMD = 0x31F
    WIN_IDENTIFY = ATA_IDENTIFY_DEVICE_CMD


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_help(sys.stderr)
        self.exit(2, "{0}: error: {1}\n".format(self.prog, message))


class ATAString(bytearray):
    def __init__(self, data: AnyStr, length: int = None, swap: bool = None) -> None:
        if isinstance(data, str):
            # String fields in IDENTIFY DEVICE data are handled as "ATA strings".
            # cf. ACS-4 3.4.9, 7.12.6.10, 7.12.6.14 (et al.)
            #   - Only ASCII characters within [0x20, 0x7e] are allowed.
            #   - The string is right-padded with ASCII 0x20 to the field width.
            #   - The field is treated as uint16be's and stored as uint16le's.
            data = bytearray(ord(c) for c in data if 0x20 <= ord(c) <= 0x7E)
            swap = True
        elif isinstance(data, bytes):
            data = bytearray(data)

        if length:
            if len(data) > length:
                fmt = "'{0}' exceeds the maximum allowed length of {1}"
                raise ValueError(fmt.format(data.decode("ascii"), length))
            data.extend(b" " * max(0, length - len(data)))
        if swap:
            data = ATAString.swab(data)

        super().__init__()
        self[:] = data

    def __str__(self) -> str:
        return ATAString.swab(self).decode("ascii")

    @staticmethod
    def swab(data: ByteString) -> bytearray:
        if len(data) & 1:
            raise ValueError("will not swab() an odd-length bytestring")
        result = bytearray(data)
        for i in range(0, len(result), 2):
            result[i], result[i + 1] = result[i + 1], result[i]
        return result


class ATAIdentifyDevice(bytearray):
    def __init__(self, file: str, swap: bool = None) -> None:
        super().__init__(self)
        self.file = file
        self.swap = swap
        self._big = 0
        self._little = 0
        self._valid = None
        self._has_valid_checksum = None

        self._load()
        self._check_byte_order()
        self._validate()

    @property
    def is_valid(self) -> bool:
        byte_order_checked = self._big > 0 or self._little > 0
        byte_order_consensus = bool(self._big) ^ bool(self._little)
        swap_was_forced = self.swap is not None and not byte_order_checked
        return (
            self._valid
            and self._has_valid_checksum
            and (byte_order_consensus or swap_was_forced)
        )

    def dump(self) -> str:
        def _chr(c: int) -> str:
            # cf. linux/lib/hexdump.c
            # something like `return (isascii(c) && isprint(c)) ? c : '.';`
            return chr(c) if c <= 0x7F and c & 0x17 else "."

        fmt = "{0:04x} {1:04}: {2:<41} {3}"
        lines = ["ATA IDENTIFY DEVICE data from {0}".format(self.file), "xofs word"]
        for i in range(0, len(self), 16):
            j = min(i + 16, len(self))
            str_repr = "".join(_chr(self[k]) for k in range(i, j))
            hex_repr = " ".join(self[k : k + 2].hex() for k in range(i, j, 2))
            lines.append(fmt.format(i, i >> 1, hex_repr, str_repr))
        return "\n".join(lines)

    def state(self) -> str:
        def _str(val: Optional[bool]) -> str:
            return "yes" if val is True else "no" if val is False else "unknown"

        lines = [
            "ATAIdentifyDevice state",
            "  will swap?           {0}".format(_str(self.swap)),
            "  big-endian score     {0}".format(self._big),
            "  little-endian score  {0}".format(self._little),
            "  seems valid?         {0}".format(_str(self._valid)),
            "  has valid checksum?  {0}".format(_str(self._has_valid_checksum)),
        ]
        return "\n".join(lines)

    def serial(self) -> ATAString:
        return ATAString(self[20:40], swap=self.swap)

    def model(self) -> ATAString:
        return ATAString(self[54:94], swap=self.swap)

    def _load_from_device(self) -> None:
        if sys.platform == "win32":
            # Use SMART_RCV_DRIVE_DATA ioctl instead of ATA_PASS_THROUGH.
            # May be more compatible with some ATA controller drivers.
            # cf. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_sendcmdoutparams
            handle = CreateFile(self.file)
            if handle == INVALID_HANDLE_VALUE:
                raise WinError()
            try:
                in_buf = SENDCMDINPARAMS(
                    cBufferSize=ATA_IDENTIFY_DEVICE_SIZE,
                    irDriveRegs=IDEREGS(bCommandReg=ID_CMD),
                )
                out_buf = create_string_buffer(
                    sizeof(SENDCMDOUTPARAMS) - 1 + ATA_IDENTIFY_DEVICE_SIZE
                )
                out_size = DWORD()
                if not DeviceIoControl(
                    handle,
                    SMART_RCV_DRIVE_DATA,
                    byref(in_buf),
                    sizeof(in_buf),
                    byref(out_buf),
                    sizeof(out_buf),
                    byref(out_size),
                ):
                    raise WinError()
                elif out_size.value != sizeof(out_buf):
                    fmt = "reply from {0} has unexpected length"
                    raise OSError(fmt.format(self.file))
                self[:] = bytearray(out_buf.raw[-ATA_IDENTIFY_DEVICE_SIZE:])
            finally:
                CloseHandle(handle)
        elif sys.platform == "linux":
            # cf. Linux doc/Documentation/ioctl/hdio.txt
            buf = bytearray(4 + ATA_IDENTIFY_DEVICE_SIZE)
            buf[0], buf[1], buf[3] = WIN_IDENTIFY, 1, 1
            fd = os.open(self.file, os.O_RDONLY)
            try:
                ioctl(fd, HDIO_DRIVE_CMD, buf)
                self[:] = buf[-ATA_IDENTIFY_DEVICE_SIZE:]
            finally:
                os.close(fd)
        else:
            fmt = "we don't know how to send ATA commands on {0}"
            raise RuntimeError(fmt.format(sys.platform))

    def _load_from_file(self) -> None:
        with open(self.file, "rb") as f:
            raw = f.read(4 * ATA_IDENTIFY_DEVICE_SIZE)

        # Could be binary IDENTIFY DEVICE data?
        if len(raw) == ATA_IDENTIFY_DEVICE_SIZE:
            self[:] = bytearray(raw)
            return

        # Ends with a hexstring of the appropriate length?
        # e.g. hdparm --Istdout, /sys/class/ata_device/dev<x.y>/id
        hex_len = 2 * ATA_IDENTIFY_DEVICE_SIZE
        str_raw = re.sub(r"\s", "", raw.decode("ascii").lower())
        match = re.search("[a-f0-9]{{{0}}}$".format(hex_len), str_raw)
        if match:
            self[:] = bytearray.fromhex(str_raw[-hex_len:])
            return

        raise ValueError("this doesn't seem to be ATA IDENTIFY DEVICE data")

    def _load(self) -> None:
        device_prefix = "\\\\.\\PhysicalDrive" if sys.platform == "win32" else "/dev/"
        if self.file.startswith(device_prefix):
            self._load_from_device()
        else:
            self._load_from_file()

    def _check_byte_order(self) -> None:
        if self.swap is not None:
            return

        # cf. ACS-4/ACS-3/ACS-2/ACS Tables 50/45/30/21
        # Word 0
        # - CompactFlash devices: Word 1 is 0x848a.
        lo, hi = self[0], self[1]
        if lo == 0x84 and hi == 0x8A:
            self._big += 1
        elif lo == 0x8A and hi == 0x84:
            self._little += 1
        # Word 47
        # - Obsolete in ACS-4. Otherwise:
        # - High order byte must be 0x80.
        # - Low order byte value 0x00 is reserved (should not be 0).
        lo, hi = self[94], self[95]
        if lo != hi:  # Also handle the ACS-4 case (both would be 0).
            if lo == 0x80 and hi != 0x00:
                self._big += 1
            elif lo != 0x00 and hi == 0x80:
                self._little += 1
        # Word 50
        # - Bits 15:14 must be 0 and 1; bits 13:2 are reserved.
        lo, hi = self[100], self[101]
        if lo & 0x40 and not hi & 0x40:
            self._big += 1
        elif not lo & 0x40 and hi & 0x40:
            self._little += 1
        # Word 75
        # - Bits 15:5 are reserved.
        lo, hi = self[150], self[151]
        if hi & 0x1F:
            self._big += 1
        elif lo & 0x1F:
            self._little += 1
        # Word 255
        # - If bits 7:0 contain 0xa5, bits 15:8 contain a checksum.
        lo, hi = self[510], self[511]
        if lo != 0xA5 and hi == 0xA5:
            self._big += 1
        elif lo == 0xA5 and hi != 0xA5:
            self._little += 1

        # In case of a tie, `self.swap` remains falsy at `None`.
        diff = self._little - self._big
        self.swap = True if diff < 0 else False if diff > 0 else None

    def _validate(self) -> None:
        # cf. ACS-4/ACS-3/ACS-2/ACS Tables 50/45/30/21
        # Word 0
        # - Always present; "shall be valid".
        # - Normal ATA devices: Bit 15 must be 0; bit 0 is reserved.
        lo, hi = self[0], self[1]
        word = ((hi << 8) | lo) if self.swap else ((lo << 8) | hi)
        if word != 0x848A and word & 0x8001:
            self._valid = False
        # Word 2
        # - If present, "shall be valid".
        # - One of the values 0x37c8, 0x738c, 0x8c73, 0xc837.
        word = (self[4] << 8) | self[5]
        if word and word not in (0x37C8, 0x738C, 0x8C73, 0xC837):
            self._valid = False
        # Word 255
        # - If bits 7:0 contain 0xa5, bits 15:8 contain a checksum.
        indicator = self[511] if self.swap else self[510]
        checksum = self[510] if self.swap else self[511]
        if indicator == 0xA5:
            # cf. ACS-4 7.12.6.91 (et al.)
            byte_sum = sum(self[:510]) + indicator
            if ((checksum + byte_sum) & 0xFF) == 0:
                self._has_valid_checksum = True
            else:
                self._valid = self._has_valid_checksum = False

        if self._valid is None:
            self._valid = True


class ThinkPadPassword:
    def __init__(self, password: str, serial: AnyStr, model: AnyStr) -> None:
        self.password = password
        self.serial = ATAString(serial, 20)
        self.model = ATAString(model, 40)

        self._scancodes = None
        self._password_hash = sha256()
        self._hash = sha256()
        self._compute_password()

    @property
    def has_null_characters(self) -> bool:
        return b"\x00" in self._hash.digest()

    def state(self) -> str:
        lines = [
            "ThinkPadPassword state",
            "  scancodes  {0}".format(self._scancodes[:17].hex()),
            "  serial     '{0}'".format(self.serial),
            "  model      '{0}'".format(self.model),
        ]
        return "\n".join(lines)

    def _compute_password(self) -> None:
        chars = (c for c in self.password.lower() if c in SCANCODE_MAP)
        self._scancodes = bytearray(SCANCODE_MAP[c] for c in chars)
        self._scancodes += bytearray(max(0, 64 - len(self._scancodes)))
        self._password_hash.update(self._scancodes[:64])
        self._hash.update(self._password_hash.digest()[:12])
        self._hash.update(self.serial)
        self._hash.update(self.model)

    def digest(self) -> bytes:
        return self._hash.digest()

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, **kwargs, file=sys.stderr)


def parse_args() -> argparse.Namespace:
    little_opts = "--little", "--machine" if sys.byteorder == "little" else "--reverse"
    big_opts = "--big", "--machine" if sys.byteorder == "big" else "--reverse"

    parser = ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=(
            "\n{0} [-h] [-v] [-p PASSWORD] [--little] [--big] FILE"
            "\n{0} [-h] [-v] [-p PASSWORD] SERIAL MODEL"
            "\n{0} [--help]"
        ).format(sys.argv[0]),
    )
    parser.add_argument("pargs", metavar="FILE", nargs="+", help=argparse.SUPPRESS)
    password_group = parser.add_argument_group(title="Input arguments")
    password_group.add_argument(
        "-p", "--password", help="Do not prompt for password; use PASSWORD.",
    )
    output_arguments_group = parser.add_argument_group(title="Output arguments")
    output_arguments_group.add_argument(
        "-h",
        "--hex",
        action="store_true",
        help="Output password hash in hexadecimal form.",
    )
    output_arguments_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print additional information to standard error.",
    )
    first_usage_form_group = parser.add_argument_group(
        title="First usage form",
        description=(
            "FILE points to ATA IDENTIFY DEVICE data containing the drive's\n"
            "serial and model numbers. This may be one of the following:\n"
            "\n"
            "  - A file containing IDENTIFY DEVICE data in raw or hexadecimal format.\n"
            "    hdparm may be used with the --Istdout option to create this data.\n"
            "    Linux may also cache this data at /sys/class/ata_device/dev<x.y>/id.\n"
            "\n"
            "  - A Linux or Windows block device, e.g. /dev/sda, \\\\.\\PhysicalDrive0.\n"
            "    Root/administrator privileges are needed to send an IDENTIFY DEVICE \n"
            "    command to the drive. For convenience, Linux-style names are allowed\n"
            "    on Windows; /dev/sd[a-z] are interpreted as \\\\.\\PhysicalDrive[0-25].\n"
        ),
    )
    first_usage_form_group.add_argument(
        *little_opts,
        action="store_true",
        help="Force interpreting data as little-endian.",
    )
    first_usage_form_group.add_argument(
        *big_opts, action="store_true", help="Force interpreting data as big-endian.",
    )
    second_usage_form_group = parser.add_argument_group(
        title="Second usage form",
        description=(
            "SERIAL and MODEL are the drive's serial and model numbers.\n"
            "These are up to 20 and 40 characters long, respectively.\n"
            "Allowed characters are from ASCII 0x20 to 0x7E.\n"
        ),
    )
    help_group = parser.add_argument_group("Help")
    help_group.add_argument(
        "--help", action="help", help="Show this help message and exit."
    )
    args = parser.parse_args()

    # Fake handling nargs="{1,2}".
    args.file = args.serial = args.model = None
    if len(args.pargs) == 1:
        args.file = args.pargs[0]
        if sys.platform == "win32" and re.match(r"^/dev/sd[a-z]+$", args.file):
            n = 0
            for char in args.file[7:]:
                n = 26 * n + DISK_ID_MAP[char]
            file = "\\\\.\\PhysicalDrive{0}".format(n - 1)
            if args.verbose:
                eprint("interpreting FILE {0} as {1}".format(args.file, file))
            args.file = file
    elif len(args.pargs) == 2:
        args.serial, args.model = args.pargs
    else:
        parser.error("unrecognized arguments: {0}".format(" ".join(args.args[2:])))

    # Fake handling a mutually exclusive group.
    if args.little and args.big:
        fmt = "argument {0}: not allowed with argument {1}"
        parser.error(fmt.format("/".join(little_opts), "/".join(big_opts)))

    return args


def main() -> None:
    args = parse_args()

    if args.file:
        swap = True if args.big else False if args.little else None
        try:
            ident = ATAIdentifyDevice(args.file, swap)
        except (OSError, RuntimeError, ValueError):
            eprint("ERROR: Cannot open {0}".format(args.file))
            raise

        if args.verbose or not ident.is_valid:
            if not ident.is_valid:
                eprint("WARNING: ATA IDENTIFY DEVICE data may be invalid")
            eprint(ident.dump())
            eprint(ident.state())

        serial, model = ident.serial(), ident.model()
    else:
        serial, model = args.serial, args.model

    if args.password:
        password = args.password
    else:
        sys.stderr.buffer.flush()
        eprint("Enter the password used to lock the drive in the ThinkPad's BIOS.")
        password = getpass.getpass()

    try:
        thinkpad_password = ThinkPadPassword(password, serial, model)
    except ValueError:
        eprint("ERROR: Cannot compute password digest")
        raise
    if args.verbose:
        eprint(thinkpad_password.state())
    if thinkpad_password.has_null_characters:
        eprint("WARNING: Password digest contains null characters.")
        eprint("hdparm versions below 9.46 cannot unlock this drive.")
        if not args.hex:
            eprint("Furthermore, you must run this script with the -h/--hex option.")

    sys.stderr.buffer.flush()
    if args.hex:
        print("hex:{0}".format(thinkpad_password.hexdigest()))
    else:
        sys.stdout.buffer.write(thinkpad_password.digest())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)  # 0x80 | SIGINT
