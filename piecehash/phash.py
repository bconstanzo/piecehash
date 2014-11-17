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

import piecehash

from constants import *

def ArgParse():
    """
    Parses the command line arguments

    :return: argparse dictionary
    """
    # parse command line arguments
    parser = argparse.ArgumentParser(
        description="piecehash: calculates piecewise hashes for a file.")
    parser.add_argument("ifile",
                        nargs="+",
                        help="Input file(s).")
    parser.add_argument("-m",
                        dest="mode",
                        choices=["hash", "compare", "forcecompare", "convert", "show"],
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
    the PHash File container (output option)

    :param args: argparse dictionary (dictionary)
    """
    hash_alg = HashTypes[args.hash]
    print "Generating PHash file..."
    container = piecehash.PHashFile(args.ofile, hash_alg, args.segsize)
    for i in args.ifile:
        print "...adding %s..." % (i)
        container.AddFile(i, lazy = False) # we calculate as we add the file...
        print "Saving PHash File..."
    container.Save(lazy = True) # ...and now we can use a lazy Save.
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

    :param args: argparse dictionary (dictionary)
    """
    ifile = args.ifile[0]  # for the moment we'll work with the first element only, although it
    # could work with multiple PHash Containers at a time
    container = piecehash.PHashFile(ifile, 0, 0)
    force_compare = args.mode == "forcecompare"
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
        if val1 == val2 and not force_compare:
            print "match. %s: %s " % (algname, val1.encode("hex"))
        else:
            if complete:
                if force_compare:
                    print " - forced comparison:"
                else:
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
            print "\b"
    return True


def Convert(args):
    """
    Converts a dc3dd/md5deep/hashdeep file to PHash Format.

    :param args: argparse dictionary (dictionary)
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
    container = piecehash.PHashFile(args.ofile, hashtype, segsize, 0)
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

    :param args: argparse dictionary (dictionary)
    """
    # Like in compare, for the moment Show mode works with the first element of the args.ifile list
    ifile = args.ifile[0]
    container = piecehash.PHashFile(ifile, 0, 0)
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
        "forcecompare": Compare,
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