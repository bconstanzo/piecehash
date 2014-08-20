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
#===================================================================================================
# Introduction
#===================================================================================================
# piecehash is a program for calculating many MD5 (or other algorithm) hashes for a file, and also
# the reference implementation and definition of a file format that stores the calculated hashes.
# Once finished it should be able to perform hashing and comparisons.
#===================================================================================================
# Why?
#===================================================================================================
# Based on a problem a forensic examiner friend of mine has, I had the thought of calculating and
# storing not one, but a lot of MD5/SHA-1/etc hashes of a file, calculating a hash for the whole
# file and also one every 1 MiB of data.
# The idea was expanded, and arbitrarily sized segments considered. Also a file format defined to
# store in a simple, storage-efficient, carving-friendly binary format.
#===================================================================================================
# Notes
#===================================================================================================
#
# Note 2014-07-08:
#   I just found out of Jesse Kornblum's work on hashdeep, md5deep and dc3dd with piecewise hashes
#   which provide the same functionality I was aiming for with p-hash (partial-hashes). P still
#   stands in the name, now for piecewise. Will do some work to provide compatibility with
#   Kornblums implementation, and focus work more in the binary file format.
#
# Note 2014-0713:
#   Name changed from "PHash" to "piecehash" to avoid confusion with pHash, and also recognize
#   Nick Harbour's and Jesse Kornblum's previous work on this topic.
#   There might still be some references to PHash arround.
#
# Bruno Constanzo, 2014
#===================================================================================================
# Brief changelog:
#===================================================================================================
# Version 0.3:
#   * Hash mode works with 1 MiB sizes and a single file
#   * PHash file format works
# Version 0.2:
#   * See Note 2014-07-08 and Note 2014-07-13
# Version 0.1:
#   * Structure layout
#   * Most functions are dummys
#   * Work in progress!
#===================================================================================================
# Roadmap:
#===================================================================================================
# Version 0.4:
#   * Hash mode works on arbitrary sizes and multiple files
#   * Better error handling when opening PHash files.
# Version 0.5:
#   * Compare mode works
# Version 0.6:
#   * Convert mode works
# Version 0.7:
#   * SHA-1, SHA-256 and SHA-512 hashes tested.
#===================================================================================================
# Afterword
#===================================================================================================
# Special thanks to Fernando Greco, Ana Di Iorio, Hugo Curti, Juan Iturriaga, Marcos Vivar and
# Javier Constanzo for ideas, comments and advice.
#===================================================================================================

import argparse
import hashlib
import struct
import sys
import zlib

# A few constants for simplicity...
KILO = 1024
MEGA = 1024 * KILO
GIGA = 1024 * MEGA

# ... and some real constants. Lets start with some file format constants
C_APPNAMELEN = 31
C_FORMATHEADER = "PHASH\x00"
C_FORMATFOOTER = "PHEND\x00"
C_APPNAME = "P-Hash Python 0.3"
C_HEADERLEN = 48
C_READSIZE = 1 * MEGA
C_FOOTER_WILDCARD = 'PHEN'
C_SEGIDS = [
    "SEG\x10",
    C_FOOTER_WILDCARD,     # not really a segment, but a hack to simplify PHashFile.Load
    ]
C_SEGIDLEN = 4
C_FLAGS = {
    'origin': 0b00000001,
}

HashList = [
    hashlib.md5,
    hashlib.sha1,
    hashlib.sha256,
    hashlib.sha512,
    ]
HashTypes = {
    "md5":0,
    "sha1":1,
    "sha256":2,
    "sha512":3,
    }

# Summary of the Partial-Hash File Format:
# The structure of a .phash file is as follows:
#   Segment                 Notes
#   [ header     ]          Metadata on the file and the hashes contained within itself.
#       [ segment 1  ]      Path and hashes of a file.
#       [ segment 2  ]
#       ...
#       [ segment N  ]
#   [ footer     ]
# Footer is the 6-byte string "PHEND\x00".
# Header contains the following fields:
#   * Magic Number (6 bytes)        PHASH\x00
#   * Hash algorithm (1 byte)       unsigned short, index of HashList
#   * Segment size (8 bytes)        unsigned long, size in bytes
#   * Flags:
#      * Hash origin (1 byte)       unsigned short, tells if a PHash file comes from a PHash program
#                                   or if it was made through conversion from md5deep. Converted
#                                   files don't have a fullhash at the end.
#                                   0 == converted, 1 == PHash Complete
#   * Appname (32 bytes)            31 char string + \x00 - might be all zeros. Identifies which
#                                   program made the file.
# A PHash File is thought as a container of the hashes of one or more files. In that thought, after
# the header you can find N segments. As it stands now (0.2) there's only one segment type: a file
# entry, that holds information on a file, its path and hashes. However, the need for another type
# of segment might arise, so it is thought to be extended in the future.
# A segment has the following structure:
#   [ ID | Length | (data)  ... | CRC-32 ]
#   * ID (4 bytes)          ID as defined in the List of Segment Type IDs
#   * Length (8 bytes)      Length of segment data
#   * (data)                Length bytes of data. Content depends on Segment type
#   * CRC-32 (4 bytes)      CRC-32 of data, to verify file integrity
# List of Segment Type IDs:
#   * File Info Segment             SEG\x10
# Each Segment Type follows its own structure.
# + File Info Segment:
#   * filepath              File path, stored as a \x00 terminated string
#   * hashes                All the hashes of the file, binary digest.
#                           The last hash is special, in a PHash Complete file, it is the full hash,
#                           that is, the same as calculating the hash on the whole file. In a
#                           Converted PHash file, it is a full string of zeros, of the same length
#                           a valid hash (of the appropriate type) is.

class PHashFile(object):
    """
    Class that handles a PHash Container in memory, maintains information about algorithm, segment
    size and files to hash.
    
    The usage is to instantiate a PHashFile, add files to it, and then save it. On the Save method,
    FileInfo.GetHashes() is called for each file and the information is stored to disk.
    """
    def __init__(self, path, hashtype, segsize):
        # First we take care of the parameters...
        self.path = path
        # ...and now of some constants
        self.header_template = C_FORMATHEADER + "%s%s%s%s"
        self.footer = C_FORMATFOOTER
        self.hashtype = hashtype
        self.hash = HashList[hashtype]
        self.segsize = segsize
        self.flags = C_FLAGS['origin']
        self.appname = C_APPNAME
        self.files = []
    
    def AddFile(self, path):
        """
        Adds a file to the internal list. Hashes are NOT calculated at this stage.
        """
        fe = FileInfo(path, self)
        self.files.append(fe)
        return True
    
    def GetFiles(self):
        return self.files
    
    def Save(self):
        h_hashtype = struct.pack("<B", self.hashtype)
        h_segsize = struct.pack("<Q", self.segsize)
        h_flags = struct.pack("<B", self.flags)
        h_appname = (self.appname + "\x00" * (C_APPNAMELEN - len(self.appname)))[:C_APPNAMELEN] + "\x00"
        header = self.header_template % (h_hashtype, h_segsize, h_flags, h_appname)
        footer = self.footer
        fd = open(self.path, "wb")
        fd.write(header)
        segid = C_SEGIDS[0]
        for f in self.files:
            data = f.GetPath() + "\x00"
            data += "".join(f.CalculateHashes())
            crc = struct.pack("<i", zlib.crc32(data))
            fd.write(segid)
            fd.write(struct.pack("<Q", len(data)))
            fd.write(data)
            fd.write(crc)
        fd.write(footer)
        fd.close()
        return True
    
    def Load(self):
        fd = open(self.path, "rb")
        unpack = struct.unpack
        raw_header = fd.read(C_HEADERLEN)
        header = raw_header[0:6]
        algorithm = raw_header[6]
        size = raw_header[7:15]
        flags = raw_header[15]
        app = raw_header[16:]
        if header != C_FORMATHEADER:
            fd.close()
            raise Exception("Non valid file header.")
            return False
        # For the moment, let's assume everyone is nice and only tries to open PHash files...
        self.hashtype, = unpack("<B", algorithm)
        self.segsize, = unpack("<Q", size)
        self.flags, = unpack("<B", flags)
        self.appname = filter(lambda x: x != "\x00", app)
        read_segments = True
        hash_base = HashList[self.hashtype]
        hash_len = hash_base().digestsize
        while read_segments:
            seg_id = fd.read(C_SEGIDLEN)
            if not(seg_id in C_SEGIDS):
                fd.close()
                if seg_id:
                    raise Exception("Non valid SegID.")
                    return False
                else:
                    raise Exception("Unexpected End-of-File.")
                    return False
                break # not really necesary, this is unreachable
            if seg_id == C_FOOTER_WILDCARD:
                seg_id += fd.read(2)
                if seg_id != C_FORMATFOOTER:
                    print "Warning: incomplete footer at EOF!"
                break
            seg_len, = unpack("<Q", fd.read(8))
            seg_data = fd.read(seg_len)
            seg_crc, = unpack("<i", fd.read(4))
            val_crc = zlib.crc32(seg_data)
            path_end = seg_data.find("\x00")
            path_data = ''
            if path_end < -1:
                print "Warning: wrong path information."
            else:
                path_data = seg_data[:path_end]
                seg_data = seg_data[path_end + 1:]
            hashes = []
            corrupt = True
            if (seg_crc == val_crc) and path_data:
                hashes = [seg_data[x * hash_len : (x * hash_len) + hash_len] for x in xrange(seg_len / hash_len)]
                corrupt = False
            else:
                print "Warning: corrupt CRC."
            f = FileInfo(path_data, self, hashes, corrupt)
            self.files.append(f)
        fd.close()
        
        return True
        

class FileInfo(object):
    def __init__(self, path, container, rhashes = None, corrupt = False):
        self.path = path
        self.container = container
        self.corrupt = corrupt
        if rhashes:
            self.read_hashes = rhashes
        else:
            self.read_hashes = []
    
    def CalculateHashes(self):
        ret = []
        hash = self.container.hash
        segsize = self.container.segsize
        fd = open(self.path, "rb")
        g_hash = hash()
        p_hash = hash()
        data = fd.read(C_READSIZE)
        while data:
            g_hash.update(data)
            p_hash.update(data)
            ret.append(p_hash.digest())
            p_hash = hash()
            data = fd.read(C_READSIZE)
        ret.append(g_hash.digest())
        return ret
    
    def GetHashes(self):
        return self.read_hashes
    
    def GetPath(self):
        return self.path

def ArgParse():
    # parse command line arguments
    parser = argparse.ArgumentParser(description='steg: applies steganography to an image.')
    parser.add_argument("ifile",
                        help = "Input file.")
    parser.add_argument("-m",
                        dest = "mode",
                        choices = ["hash", "compare", "convert", "show"], 
                        default = "hash",
                        help = "Mode of operation.")
    parser.add_argument("-o", 
                        dest = "ofile",
                        default = "hashes.phash",
                        help = "Output file.")
    parser.add_argument("-a", 
                        dest = "hash",
                        choices = ["md5", "sha-1", "sha-256", "sha-512"], 
                        default = "md5",
                        help = "The hash algorithm to be used.")
    parser.add_argument("-s", 
                        dest = "segsize",
                        type = int, 
                        default = 1 * MEGA,
                        help = "The segment size to calculate partial hashes.")
    args = parser.parse_args()
    return args

def Hash(args):
    print "Hash mode."
    hash = HashTypes[args.hash]
    container = PHashFile(args.ofile, hash, args.segsize)
    container.AddFile(args.ifile)
    container.Save()
    
    return True

def Compare(args):
    container = PHashFile(args.ifile, 0, 0)
    # Not entirely sure about what the best option is, but I feel the best should be letting the
    # real comparison to be made between the read hashes and the calculated hashes, so its actually
    # a responsibility left to this function what to do with each value and how to present the 
    # results to the user.
    container.Load()
    for f in container.GetFiles():
        print "Comparing {0}...".format((f.GetPath()))
        print "Results: ",
        hashes1 = f.GetHashes()
        hashes2 = f.CalculateHashes()
        for t in zip(hashes1, hashes2):
            if t[0] == t[1]:
                print "\b.",
            else:
                print "\bX", 
    return True

def Convert(args):
    print "Convert mode."
    return True

def Show(args):
    print "Show mode."
    return True

def main():
    args = ArgParse()
    calls = {
        "hash":Hash,
        "compare":Compare,
        "convert":Convert,
        "show":Show, 
        }
    op = calls[args.mode]
    op(args)
    
if __name__ == "__main__":
    main()