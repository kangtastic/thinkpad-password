# Lenovo ThinkPad HDD Password Algorithm
This is an implementation in pure Python 3 of the hard disk password algorithm ([previously described](https://github.com/jethrogb/lenovo-password) by Jethro Beekman, to whom all reverse-engineering credit is due) used by certain older Lenovo ThinkPad laptop computers.

Like the original, its purpose is to allow unlocking hard disks which were locked by such a ThinkPad on another computer.

It is released in the hope that it may be useful in environments in which Python 3 is present but Ruby is not, e.g. many (most?) recent Linux LiveCD/LiveUSBs.

## Usage
| :warning:WARNING:warning: | Before proceeding any further, connect the disk to the closest thing to a standard native motherboard SATA port you have available.<br><br> Running `hdparm` on disks connected to weird or special SATA ports *can brick them*. Avoid RAID controllers, add-in cards, buggy motherboard ports, and *especially* USB-to-SATA bridges.<br><br> YOU HAVE BEEN WARNED. |
| --- | --- |

The command-line options of this script are compatible with those of [the original](https://github.com/jethrogb/lenovo-password#usage). It may therefore be used in an almost identical fashion:

| Effect | Command |
| --- | --- |
| Read ATA `IDENTIFY DEVICE` data from `/dev/sda`.<br> Save it to `sda.ata_identify`. | `$ sudo hdparm --Istdout /dev/sda > sda.ata_identify` |
| Run the script.<br> `sda.ata_identify` is given as `IDENTIFY DEVICE` data.<br> (You will be prompted to enter the drive's password.)<br> Save the result in the environment variable `P`. | `$ P=$(python3 thinkpad-password.py sda.ata_identify)` 
| Unlock the drive using `hdparm`. | `$ sudo hdparm --security-unlock "$P" /dev/sda` |
| If unlocking worked, disable the drive password.<br> (See the [FAQ](#why-might-unlocking-a-drive-fail) for why it might not.) | `$ sudo hdparm --security-disable "$P" /dev/sda` |


More advanced usage is also possible, e.g.:

| Effect | Command |
| --- | --- |
| Run the script.<br> `A12345678Z` is given as the serial number. <br> `MFG DRVMODEL 9000` is given as the model number.<br> (You will be prompted to enter the drive's password.)<br> Save the result in the environment variable `P`. | `$ P=$(python3 thinkpad-password.py 'A12345678Z' 'MFG DRVMODEL 9000')` |
| Unlock the drive using `hdparm`. | `$ sudo hdparm --security-unlock "$P" /dev/sda` |

or e.g.:

| Effect | Command |
| --- | --- |
| Run the script.<br> `IDENTIFY DEVICE` data is directly read from `/dev/sda`.<br> `p a s s w 0 r d` is given as password.<br> Directly feed the result into `hdparm` and unlock the drive. | `$ sudo hdparm --security-unlock "$(sudo python3 thinkpad-password.py -p 'p a s s w 0 r d' /dev/sda)" /dev/sda`

See the [help text](#help-text) below for more details.

## Feasibly Asked Questions (FAQ)
### Do I need to run this script as root/admin?
Only if you're using it to read `IDENTIFY DEVICE` data from a drive.
###  What's the point of reading `IDENTIFY DEVICE` data using this script instead of `hdparm`?
There is none. You still need `hdparm` or the like to actually unlock the drive, and I haven't built in any special handling for nonstandard drive controllers or USB-to-SATA bridges at all.
### Do I need root/admin permissions to read `IDENTIFY DEVICE` data and send `SECURITY UNLOCK` and `SECURITY DISABLE PASSWORD` commands in general?
**Technically, no.** You only need `CAP_SYS_RAWIO` capabilities on Linux or the equivalent on Windows, so you can grab a read/write handle to a disk's block device file.

**Practically, yes.**

One minor exception: on Linux, you can probably find cached copies of `IDENTIFY DEVICE` data for all currently connected ATA/SATA devices at `/sys/class/ata_device/dev<x.y>/id`, and if you can figure out what `x.y` is for the drive in question, you can feed the relevant path to this script as `FILE` without needing additional permissions.
### What's the deal with Windows support?
There exists [a 2007 port](http://axh.mbnet.fi/hdparm-win32.html) by Jussi Kivilinna of `hdparm` for Windows (apparently repackaged by a third party into an [installer](https://sites.google.com/site/disablehddapm/)) that can read `IDENTIFY DEVICE` data from a drive and output it with `--Istdout`. While it doesn't support sending ATA `SECURITY UNLOCK` and `SECURITY DISABLE PASSWORD` commands to a drive, there exist other utilities that do, e.g. [Victoria](http://hdd.by/victoria/) (download link at bottom), and someone may release an updated port in the future.
### Why might unlocking a drive fail?
Some possibilities in descending order of anticipated likelihood:

| Cause | Resolution(s) |
| --- | --- |
| Your model of ThinkPad doesn't use this HDD password algorithm. | Sorry. |
| Your computer's BIOS set the disk's security state to `FROZEN` on startup. | See #4, #5, and #6 on [this page](https://grok.lsu.edu/Article.aspx?articleid=16716) for a possible fix (tl;dr: put the computer to sleep and wake it up again).<br><br> Some BIOSes actually freeze connected disks again upon waking up. Try again on a different computer. |
| The result of the script contained null characters. | Like the warning message said, provide `-h` or `--hex` and use `hdparm` version >= 9.46. |
| You provided an `IDENTIFY DEVICE` data file.<br><br> Unbeknownst to you, the software you used to create it swapped the byte order of string fields (including the serial and model number fields) in the data file during its creation, but left all the other fields untouched.<br><br> (See the [draft ACS-2 specification](http://www.t13.org/Documents/UploadedDocuments/docs2009/d2015r2-ATAATAPI_Command_set_-_2_ACS-2.pdf) §3.3.10 for why the authors of the software thought this was a good idea.) | Provide `--big`, then `--little`. One of them should work. |
| You provided `SERIAL` and `MODEL`.<br><br>Unbeknownst to you, the drive's serial and/or model number, as they existed in its `IDENTIFY DEVICE` data, had leading spaces that were silently removed by the software you used to discover them. | Provide an `IDENTIFY DEVICE` data file instead.<br><br> Carefully examine a hexdump of the `IDENTIFY DEVICE` data file and count the leading spaces so you can include them in `SERIAL` and `MODEL` enclosed in quotes. (Don't worry about trailing spaces.) |
| The drive is connected via a USB-to-SATA bridge or an otherwise nonstandard/buggy SATA controller. | Try again on a different computer. Your data is probably still fine. |
### Can you help me with my ThinkPad-specific question?
I would, but I don't have one, I don't know anything about them, and if I'm being perfectly honest, I wrote this script as a coding exercise. Good luck!

## Help text
```
thinkpad-password.py [-h] [-v] [-p PASSWORD] [--little] [--big] FILE
thinkpad-password.py [-h] [-v] [-p PASSWORD] SERIAL MODEL
thinkpad-password.py [--help]

Input arguments:
  -p PASSWORD, --password PASSWORD
                        Do not prompt for password; use PASSWORD.

Output arguments:
  -h, --hex             Output password hash in hexadecimal form.
  -v, --verbose         Print additional information to standard error.

First usage form:
  FILE points to ATA IDENTIFY DEVICE data containing the drive's
  serial and model numbers. This may be one of the following:

    - A file containing IDENTIFY DEVICE data in raw or hexadecimal format.
      hdparm may be used with the --Istdout option to create this data.
      Linux may also cache this data at /sys/class/ata_device/dev<x.y>/id.

    - A Linux or Windows block device, e.g. /dev/sda, \\.\PhysicalDrive0.
      Root/administrator privileges are needed to send an IDENTIFY DEVICE
      command to the drive. For convenience, Linux-style names are allowed
      on Windows; /dev/sd[a-z] are interpreted as \\.\PhysicalDrive[0-25].

  --little, --machine   Force interpreting data as little-endian.
  --big, --reverse      Force interpreting data as big-endian.

Second usage form:
  SERIAL and MODEL are the drive's serial and model numbers.
  These are up to 20 and 40 characters long, respectively.
  Allowed characters range from ASCII 0x20 to 0x7E.
```
## See also
- [https://github.com/jethrogb/lenovo-password](https://github.com/jethrogb/lenovo-password)
- [https://jbeekman.nl/blog/2015/03/lenovo-thinkpad-hdd-password/](https://jbeekman.nl/blog/2015/03/lenovo-thinkpad-hdd-password/)
## Legal
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
