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

import argparse
import datetime     # for some timings and measures
import hashlib
import struct
#import sys
import zlib

# A bit of version numbers...
C_VER_MAJOR = 6
C_VER_MINOR = 1
C_VER_MICRO = 0
C_VER_BUILD = 35  # more like "working code version", since there's no build per se
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

# Description of the Piecewise-Hash File Format:
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
#      * Hash origin (1 bit)        unsigned short, tells if a PHash file comes from a PHash program
#                                   or if it was made through conversion from md5deep. Converted
#                                   files don't have a full hash at the end.
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

    def __init__(self, path, hashtype, segsize, flags=C_FLAGS["origin"]):
        # First we take care of the parameters...
        self.path = path
        # ...and now of some constants
        self.header_template = C_FORMATHEADER + "%s%s%s%s"
        self.footer = C_FORMATFOOTER
        self.hashtype = hashtype
        self.hash = HashList[hashtype]
        self.segsize = segsize
        self.flags = flags
        self.appname = C_APPNAME
        self.files = []

    def AddFile(self, path, rhashes=None):
        """
        Adds a file to the internal list. Hashes are NOT calculated at this stage.
        """
        fe = FileInfo(path, self, rhashes)
        self.files.append(fe)
        return True

    def GetFiles(self):
        """
        Returns the internal file list.
        """
        return self.files

    def Save(self, lazy = False):
        """
        Saves a PHashFile container to a PHash Format File. Calculates the appropriate hashes for
        every file that was added to the Files List, and stores the results in the container file.

        :param lazy indicates that hashes are not calculated, but read through f.GetHashes()
        """
        # Let's document a bit here...
        pack = struct.pack  # for code shortness. It may give a tiny improvement in performance too.
        # Now we have to pack all the information of the Object to save it into the binary file
        h_hashtype = pack("<B", self.hashtype)
        h_segsize = pack("<Q", self.segsize)
        h_flags = pack("<B", self.flags)
        # Also we clip and adapt the appname, so that it will fit in its allocated space in the
        # file header:
        h_appname = (self.appname + "\x00" * (C_APPNAMELEN - len(self.appname)))[:C_APPNAMELEN] + "\x00"
        #...and now we replace the values directly into the header, and prepare the footer
        header = self.header_template % (h_hashtype, h_segsize, h_flags, h_appname)
        footer = self.footer
        # (A single struct.pack could be used to pack and save all the values directly, but I have
        # prioritized code clarity here.)
        fd = open(self.path, "wb")
        fd.write(header)
        # We saved the file header, and now we will write the segments that describe all the files
        # that were added to the PHashFile Container.
        segid = C_SEGIDS[0]
        for f in self.files:
            data = f.GetPath() + "\x00"
            if lazy:
                data += "".join(f.GetHashes())
            else:
                data += "".join(f.CalculateHashes())
            crc = pack("<i", zlib.crc32(data))
            fd.write(segid)
            fd.write(pack("<Q", len(data)))
            fd.write(data)
            fd.write(crc)
            # Again, this 4 writes can be compacted into a single write -- code clarity.
            # Will change it for a more compact write later on and leave this version commented for
            # clarity.
        fd.write(footer)
        fd.close()
        return True

    def Load(self):
        """
        Loads the contents of a PHash Format File into a PHashFile container object.
        """
        # This still needs a lot of work for bad files.
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
        # For the moment, let's assume everyone is nice and only tries to open PHash files...
        self.hashtype, = unpack("<B", algorithm)
        self.hash = HashList[self.hashtype]
        self.segsize, = unpack("<Q", size)
        self.flags, = unpack("<B", flags)
        self.appname = filter(lambda x: x != "\x00", app)
        read_segments = True
        hash_base = HashList[self.hashtype]
        hash_len = hash_base().digestsize
        # Now we are ready to read the hash values directly from the file into the in memory list.
        # Inside this while loop, we follow the description of Segment from the Partial-Hash File
        # Format Definition (around line 73 onwards, might be a bit off).
        while read_segments:
            # We read a Segment ID and check if it's valid
            seg_id = fd.read(C_SEGIDLEN)
            if not (seg_id in C_SEGIDS):
                fd.close()
                if seg_id:
                    raise Exception("Non valid SegID.")
                else:
                    raise Exception("Unexpected End-of-File.")
            # As a simple hack, we put a part of the file format footer as a valid SegID. Now we
            # have to check if it is a footer. If its not complete, we give a warning but stop
            # reading the file anyway (so we assume its marking the EOF).
            if seg_id == C_FOOTER_WILDCARD:
                seg_id += fd.read(2)
                if seg_id != C_FORMATFOOTER:
                    print "Warning: incomplete footer at EOF!"
                break
            # So we have a valid SegID and its not EOF. Better get the data!
            # Block-split-reads have not been implemented here because, for the use case we
            # thought of this tool, data as large as 1 million hashes should take about 16 to 32mb
            # of memory.
            seg_len, = unpack("<Q", fd.read(8))
            seg_data = fd.read(seg_len)
            seg_crc, = unpack("<i", fd.read(4))
            val_crc = zlib.crc32(seg_data)
            path_end = seg_data.find("\x00")
            path_data = ""
            if path_end < -1:
                print "Warning: wrong path information."
            else:
                path_data = seg_data[:path_end]
                seg_data = seg_data[path_end + 1:]
            hashes = []
            corrupt = True
            if (seg_crc == val_crc) and path_data:
                hashes = [seg_data[x * hash_len: (x * hash_len) + hash_len] for x in xrange(len(seg_data) / hash_len)]
                corrupt = False
            else:
                print "Warning: corrupt CRC."

            fe = FileInfo(path_data, self, hashes, corrupt)
            self.files.append(fe)
        fd.close()

        return True

class FileInfo(object):
    """
    Class that holds a file information inside the container. A container can have 0-N FileInfo
    objects that save save hashes and path information. The FileInfo object is the responsible for
    calculating and holding read (from an opened Container File) hashes.
    """

    def __init__(self, path, container, rhashes=None, corrupt=False):
        self.path = path
        self.container = container
        self.corrupt = corrupt
        if rhashes:
            self.read_hashes = rhashes
        else:
            self.read_hashes = []

    def CalculateHashes(self, save=False):
        """
        Calculates the piecewise hashes, and global hash, for the file.

        save parameter tells us to keep the ret value as the self.read_hashes attribute. By default,
        save is set to False.
        """
        ret = []
        hash_alg = self.container.hash
        segsize = self.container.segsize
        fd = open(self.path, "rb")  # what if the file doesn't exist any more?
        g_hash = hash_alg()
        data = fd.read(C_READSIZE)
        remainder = ""  # here we'll have some remaining info for the case that the segment doesn't
        # align nicely with the read block.
        while data:
            data = remainder + data
            # here we split data into data_segs to easily calculate piecewise hashes
            data_segs = [data[x * segsize: (x * segsize) + segsize] for x in xrange(len(data) / segsize)]
            # there might be some data that doesn't fit (segsize doesn't align with C_READSIZE), so
            # we keep it, either for the next loop or for when we finish.
            remainder = data[len(data) - (len(data) % segsize):]
            g_hash.update(data)
            # this for-loop can be turned into a list comprehension, but for the moment I think it
            # would hurt code clarity. It could speed up processing of files, will check later on.
            for ds in data_segs:
                p_hash = hash_alg()
                p_hash.update(ds)
                ret.append(p_hash.digest())
            data = fd.read(C_READSIZE)
        # I had forgotten about fd.close()! there goes another point to "with" constructs!
        fd.close()
        # If we have a remainder, we need to update the last hash and append it.
        if remainder:
            p_hash = hash_alg()
            p_hash.update(remainder)
            ret.append(p_hash.digest())
        ret.append(g_hash.digest())
        if save:
            self.read_hashes = ret
        return ret

    def GetHashes(self):
        """
        Returns the read_hashes attribute. By convention, this are the values read from the
        Container file at the moment of PHashFile.Load(), and may be different from
        FileInfo.Calculate() values.
        """
        return self.read_hashes

    def SetHashes(self, hashes):
        """
        Sets the read_hashes attribute. Provided both for symmetry and eventual need for it.
        """
        self.read_hashes = hashes
        return True

    def GetPath(self):
        """
        Returns the path of the file.
        """
        return self.path


####################################################################################################
# Up to here, its mostly the classes that implement the PHash File Format behaviour. From here on
# its mostly functions to support the CLI. In a future release, the file should be split to separate
# classes from CLI-functions. This should provide a more library-like experience and encourage
# someone else to write another CLI, GUI or integrate the format into another tool.
####################################################################################################

def ArgParse():
    # parse command line arguments
    parser = argparse.ArgumentParser(
        description="piecehash: calculates piecewise hashes for a file.")
    parser.add_argument("ifile",
                        nargs="+",
                        help="Input file.")
    parser.add_argument("-m",
                        dest="mode",
                        choices=["hash", "compare", "convert", "show"],
                        default="hash",
                        help="Mode of operation.")
    parser.add_argument("-o",
                        dest="ofile",
                        default="hashes.phash",
                        help="Output file.")
    parser.add_argument("-a",
                        dest="hash",
                        choices=["md5", "sha1", "sha256", "sha512"],
                        default="md5",
                        help="The hash algorithm to be used.")
    parser.add_argument("-s",
                        dest="segsize",
                        type=int,
                        default=1 * MEGA,
                        help="The segment size to calculate partial hashes.")
    args = parser.parse_args()
    return args


def Hash(args):
    """
    Reads a file from the specified path, calculates the hashes and stores all the information in
    the PHash File container (output option
    """
    hash_alg = HashTypes[args.hash]
    print "Generating PHash file..."
    container = PHashFile(args.ofile, hash_alg, args.segsize)
    for i in args.ifile:
        print "...adding %s..." % (i)
        container.AddFile(i)
    print "Calculating hashes..."
    container.Save()
    print "Done!"

    return True

def Compare(args):
    """
    Compares the hashes of the PHash File against the paths in the disk. This validates the files
    against the stored hashes.
    If the global hash matches, a match is reported. When global hash doesn't match, detailed
    per-block information is shown to represent every block.
    A dot . tells us blocks match in the stored hash and the file.
    A letter X tells us blocks don't match.
    A plus sign + tells us the file in disk has additional blocks the original file didn't have.
    A minus sign - tels us the file in disk is missing blocks the original file did have.
    """
    ifile = args.ifile[0]  # for the moment we'll work with the first element only, although it
    # could work with multiple PHash Containers at a time
    container = PHashFile(ifile, 0, 0)
    # Responsibility of actually comparing hashes and showing results is left to this function.
    # An alternative implementation could show results on the go, I prefer it this way to produce
    # simpler code in the classes.
    container.Load()
    for f in container.GetFiles():
        print "* %s..." % (f.GetPath()),
        hashes1 = f.GetHashes()
        hashes2 = f.CalculateHashes()
        algname = container.hash().name
        complete = bool(container.flags & C_FLAGS["origin"])
        val1, val2 = hashes1[-1], hashes2[-1]
        hashes1, hashes2 = hashes1[:-1], hashes2[:-1]
        #if False: # this is a replacement for the next line to test some cases.
        if val1 == val2:
            print "match. %s: %s " % (algname, val1.encode("hex"))
        else:
            if complete:
                print "no match, showing block results:"
            else:
                print "container misses a global hash, showing block results:"
            for t in zip(hashes1, hashes2):
                if t[0] == t[1]:
                    print "\b.",
                else:
                    print "\bX",
            # We might have some missing blocks at the end, or some new blocks. So we must account
            # for them in the output.
            lendiff = len(hashes1) - len(hashes2)
            if lendiff < 0:
                print "\b%s" % ("+" * abs(lendiff))
            if lendiff > 0:
                print "\b%s" % ("-" * lendiff)
    return True


def Convert(args):
    """
    Converts a dc3dd/md5deep/hashdeep file to PHash Format.
    """
    ifile = args.ifile[0]
    # Example input of ifile:
    # 01674af2b0313f1976e6b6ac3c54a76d  c:\Test\crim\memoria.dd offset 0-1048575
    # 473b4cacf4d6ba9fd9aa926c1bd5dd29  c:\Test\crim\memoria.dd offset 1048576-2097151
    # 5500f139f8b13b840090c47522822145  c:\Test\crim\memoria.dd offset 2097152-3145727
    # 86a1791377c52139d4211a9639dd8519  c:\Test\crim\memoria.dd offset 3145728-4194303
    # 76f55a568473f0c55fc796c78bec3c30  c:\Test\crim\memoria.dd offset 4194304-5242879
    # 5a0c226f7d49a8f1600086aed2714d6a  c:\Test\crim\memoria.dd offset 5242880-6291455
    # fceebf33424f29d98150bf9ce6f36499  c:\Test\crim\memoria.dd offset 6291456-7340031
    # ...
    fd = open(ifile, "r")
    # Thought I'd be able to pull it with a simple line.split(" "), but paths with spaces are a
    # mess. Will have to do it the ugly way...
    hashes = []
    po_list = [] # short for path-offset-list
    for line in fd:
        line = line.strip() # there shouldn't be any spaces ahead or before, but...
        pos = line.find("  ")
        hashes.append(line[:pos].decode("hex"))
        po_list.append(line[pos + 2:])
    fd.close()
    line = po_list[0] # we take the first line back to get path and seg_size
    pos = line.find(" offset")
    path = line[:pos]
    line = line[pos + len(" offset "):]
    s1, s2 = map(int, line.split("-"))
    hash_len = len(hashes[0])
    if not(hash_len in HashLengths):
        print "Error: hash-type could not be recognized through length. Probable bad input file."
        return False
    hashtype = HashLengths.index(hash_len)
    segsize = s2 - s1 + 1 # this errs in shorter-than-segsize files, but its unavoidable.
    # Now we have all the information we need to instantiate the PHashFile Container and save it
    # to disk.
    container = PHashFile(args.ofile, hashtype, segsize, 0)
    # we need to add a fictitious global hash -- will look into it and see if we can generate the
    # global hash from the segment hashes.
    hashes.append("\x00" * hash_len)
    container.AddFile(path, hashes)
    container.Save(lazy = True)
    print "* %s converted successfully to %s!" % (ifile, args.ofile)

    return True


def Show(args):
    """
    Shows the hashes of a PHash File through the screen.
    This hasn't been extensively tested and will need further work once the PHash File Format
    classes and the CLI functions are split into different files.
    """
    # Like in compare, for the moment Show mode works with the first element of the args.ifile list
    ifile = args.ifile[0]
    container = PHashFile(ifile, 0, 0)
    container.Load()
    segsize, algorithm = container.segsize, container.hash().name
    hashlen = container.hash().digest_size
    print "Container %s" % (ifile)
    print "Segment size: %10d bytes" % (segsize)
    print "Hashing algorithm: %s" % (algorithm)
    complete = bool(container.flags & C_FLAGS["origin"])
    for f in container.GetFiles():
        hashes = f.GetHashes()
        seg = 0
        name = f.GetPath()
        if complete:
            print "Global hash: %s" % hashes[-1].encode("hex")
        else:
            print "(converted .phash file, global hash missing)"
        hashes = hashes[:-1]
        cliout = "Hash".ljust(hashlen * 2) + "  File                         Segment"
        print "\n%s" % cliout
        for h in hashes:
            if len(name) > 29:
                val = "..." + name[-25:] + " "
            else:
                val = name.ljust(29)
            val = h.encode("hex") + "  " + val + "%d-%d" % (seg, seg + segsize - 1)
            print val
            seg += segsize

    return True


def main():
    args = ArgParse()
    calls = {
        "hash": Hash,
        "compare": Compare,
        "convert": Convert,
        "show": Show,
        }
    op = calls[args.mode]
    t1 = datetime.datetime.now()
    op(args)
    dt = datetime.datetime.now() - t1
    if DEBUG_BENCHMARK:
        print "\nTime taken: %s" % dt


if __name__ == "__main__":
    main()
