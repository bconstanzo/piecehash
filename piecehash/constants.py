# piecehash
# Copyright (C) 2014 Bruno Constanzo
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not,
# write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# ==================================================================================================

import hashlib

# A bit of version numbers...
C_VER_MAJOR = 7
C_VER_MINOR = 0
C_VER_MICRO = 0
C_VER_BUILD = 39  # more like "working code version", since there's no build per se
C_VERSTRING = "%d.%d.%d" % (C_VER_MAJOR, C_VER_MINOR, C_VER_MICRO)
C_BUILDSTRING = C_VERSTRING + " build %d" % (C_VER_BUILD)
# ...and something for tests...
DEBUG_BENCHMARK = True

# A few constants for simplicity...
KILO = 1024
MEGA = 1024 * KILO
GIGA = 1024 * MEGA

# ... and some real constants. Lets start with some file format constants.
# (to understand some of this you might need to refer to the format definition a few lines ahead)
C_APPNAMELEN = 31
C_FORMATHEADER = "PHASH\x00"
C_FORMATFOOTER = "PHEND\x00"
C_BASENAME = "Piecehash Python"
C_AUTHORS = "Bruno Constanzo"
C_YEARS = "2014"
C_APPNAME = "%s %s" % (C_BASENAME, C_VERSTRING)
C_APPLONGNAME = "%s %s - %s, %s" % (C_BASENAME, C_BUILDSTRING, C_AUTHORS, C_YEARS)
C_HEADERLEN = 48
C_READSIZE = 1 * MEGA
C_FOOTER_WILDCARD = C_FORMATFOOTER[:4]
C_SEGIDS = [
    "SEG\x10",
    C_FOOTER_WILDCARD,  # not really a segment, but a hack to simplify PHashFile.Load
    ]
C_SEGIDLEN = 4
C_FLAGS = {
    "origin": 0b00000001,
    }

# Now the algorithm list, and the dict that maps algorithms names to the correct index

HashList = [
    hashlib.md5,
    hashlib.sha1,
    hashlib.sha256,
    hashlib.sha512,
    ]

HashTypes = {
    "md5": 0,
    "sha1": 1,
    "sha256": 2,
    "sha512": 3,
    }

HashLengths = []
for h in HashList:
    HashLengths.append(h().digest_size)