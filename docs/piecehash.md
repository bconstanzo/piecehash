Piecewise-Hash File Format
==========================

This document
-------------
This document describes the Piecewise-Hash File Format as implemented by piecehash. It is meant to
be a simple reference with nice formatting, alternative to reading the comments and docstrings in
the code.

On some aspects, it may be clearer or lengthier than de comments in the code for two reasons:

* The comments are meant to clarify what the code does, so they are complementary of something. This
document however should be enough on its own to understand the format.
* This is _documentation_, it is meant to be clear.

As of version 0.7.1 of piecehash, both the code and this document describe the same. If any commit
breaks this compatibility, it will be noted in the changelog. If you find a mismatch between both,
please be kind and report it so it can be fixed.


1 - Description
---------------

Piecewise-Hash File Format (PHash file format for short) is a binary format we propose for storing a
large amount of hashes about one or ore files. Similar to ZIP being an archival file format for
files, PHash is an archival file format for hashes.

A PHash file follows this structure:

|Segment  |Notes                                                                             |
|---------|----------------------------------------------------------------------------------|
|Header   | Metadata on the file and the hashes contained within itself. View "2.1 - Header".|
|Segment 1| Segment ID and Segment Data. View "2.2 - Segments".                              |
|Segment 2|                                                                                  |
|...      |                                                                                  |
|Segment N|                                                                                  |
|Footer   | End of file signature. View "2.3 - Footer".                                      |

2 - Details of Structures
-------------------------

###2.1 - Header
The header of the PHash file contains information and metadata to correctly interpret and process
the file. It has the following fields:

|Field         |Length  |Details                                                               |
|--------------|--------|----------------------------------------------------------------------|
|Magic string  |6 bytes |"PHASH\x00" string.                                                   |
|Hash algorithm|1 byte  |Unsigned short, index of HashList, view HashList.                     |
|Segment size\*|8 bytes |Unsigned quad, size in bytes.                                         |
|Flags         |1 byte  |0 means its a Converted files, 1 PHash Complete. View Converted Files.|
|Appname       |32 bytes|31 char string with "\x00" trail. Padded with "\x00" to 32 bytes.     |
|              |48 bytes|                                                                      |

\* Segment size is not to be confused with file Segments. This size refers to the piecewise parts of
which the hash digest is calculated.

HashList:

|Index|Algorithm|
|-----|---------|
|0    |MD5      |
|1    |SHA-1    |
|2    |SHA 256  |
|3    |SHA 512  |

####2.1.1 - Converted Files
Converted Files are PHash Files that come from an application which is not PHash Complete. That
means the application is not aware of the PHash file format, for example Jesse Kornblum's hashdeep
or dc3dd.

Specifically, it means there is no Global Hash available at the end of the list of hashes in a File
Segment, so it is ignored. As the format expects information there, phash.py fills the slot with
"\x00" chars.

###2.2 - Segments
A PHash File is thought as a container of the hashes of one or more files. In that thought, after
the header you can find N segments. As it stands now (0.7.1) there's only one segment type: a file
entry, that holds information on a file, its path and hashes. However, the need for another type
of segment might arise, so it is thought to be extensible.

A segment has the following structure of fields:

|Field         |Length       |Details                                  |
|--------------|-------------|-----------------------------------------|
|Segment ID    |4 bytes      |ID from Segment Type List.               |
|Segment length|8 bytes      |Length of segment data.                  |
|(data)        |N bytes      |Segment data, N = Segment length.        |
|CRC-32        |4 bytes      |CRC-32 of data, to verify file integrity.|
|              |N + 16 bytes |                                         |

Segment Type List:

|Segment ID|Segment info     |
|----------|-----------------|
|SEG\x10   |File Info Segment|

####2.2.1 - File Info Segment
A File Info Segment contains the data about a file that has been processed and stores the hashes.
The data stored in a File Info Segment is as follows:

* **filepath** is the path (OS dependent) for the file, and is terminated with a \x00 char
* **hashes** is an array of the binary digests of the file. There are (file?size / segment_size) + 1
hashes in this part, one hash for every segment and the Global Hash. If the PHash File is PHash
Complete, the Global Hash has the MD5 (or corresponding algorithm) digest of the whole file. If it
is not a PHash Complete file, its contents are ignored.

###2.3 - Footer
The footer of the file consists of the string "PHEND\x00".

Appendix A - A simple example
--------------------

We will see the contents of a PHash file created with the following command:

    phash.py -s 4096 -o piecehash.phash piecehash.py

This is the PHash file of the Sep 18, 2014 version of piecehash.py. We will analyze in detail every
section of the file, and finally see the full file.

###A.1 - Example: Header
The header comprises the first 48 bytes of the file, in our example:

    50 48 41 53 48 00 00 00 10 00 00 00 00 00 00 01 50 69 65 63 65 68 61 73 68 20 50 79 74 68 6f 6e
    20 30 2e 37 2e 31 00 00 00 00 00 00 00 00 00 00

Which maps to the following fields and meaning:

* `50 48 41 53 48 00` is the Magic string "PHASH\x00" which indicates this is a PHash File.
* `00` is the Hash algorithm byte, in this case its telling is its using MD5.
* `00 10 00 00 00 00 00 00` is the Segment size, in our example 4096
* `01` is the Flags byte, telling us it is a PHash Complete file.
* `50 69 65 63 65 68 61 73 68 20 50 79 74 68 6f 6e 20 30 2e 37 2e 31 00 00 00 00 00 00 00 00 00 00`
is the Appname string, zero-padded to 31 bytes long + zero-terminator. It says "Piecehash Python
0.7.1".

###A.2 - Example: Segments
Immediately after the header comes the first segment of the file. In our example we have only one
segment, that corresponds to the only file we hashed:

    53 45 47 10 5d 00 00 00 00 00 00 00 70 69 65 63 65 68 61 73 68 2e 70 79 00 c9 f6 51 67 39 1d 1e
    05 c7 90 d5 ad b5 78 77 c9 da 2e 0c 08 ad 25 ef d0 ef fb 2c c3 bd 0b 23 4c 32 7d da fc 78 b3 b9
    35 59 99 22 5a 8e 53 7e 9e be f4 07 37 3b 37 dc 92 87 85 bc 9b 49 d7 89 ab 81 9e df d2 5e 87 95
    ca 8f f9 c4 42 bd 38 11 ad 1b 7d df e6

Intepreting the fields of the segment gives us the following information:

* `53 45 47 10` is the Segment ID, indicating a File Info Segment.
* `5d 00 00 00 00 00 00 00` is the segment length (id, length and CRC not included), 93 bytes.
* Segment data is long and has to be correctly interpreted. We have a string with the file path
(zero-terminated) and then the remaining bytes form the list of hashes, which is N / M entries long,
where N is the number of remaining bytes and M the hash length in bytes:
    * `70 69 65 63 65 68 61 73 68 2e 70 79 00` is the file path. It says "piecehash.py".
    * At this point we have 93 - 13 = 80 remaining bytes and MD5 is a 16 bytes-long hash. That means
    we have 5 entries in our list of hashes for piecehash.py:
    * `c9 f6 51 67 39 1d 1e 05 c7 90 d5 ad b5 78 77 c9` is the MD5 hash of the 1st segment.
    * `da 2e 0c 08 ad 25 ef d0 ef fb 2c c3 bd 0b 23 4c` is the MD5 hash of the 2nd segment.
    * `32 7d da fc 78 b3 b9 35 59 99 22 5a 8e 53 7e 9e` is the MD5 hash of the 3rd segment.
    * `be f4 07 37 3b 37 dc 92 87 85 bc 9b 49 d7 89 ab` is the MD5 hash of the 4th segment.
    * `81 9e df d2 5e 87 95 ca 8f f9 c4 42 bd 38 11 ad` is the MD5 of the file as a whole.
* `1b 7d df e6` is the CRC-32 of the data.

In a more complex file, subsequent segments would be following after this one. As of this version,
there is only one segment type (File Info Segments), so the structure would be the same as we just
analyzed.

###A.3 - Example: Footer
At the end of the file, we find the footer

* `50 48 45 4e 44 00` 6 byte string which reads "PHEND\x00".

###A.4 - Example: full file
The complete file is just 163 bytes long, and its hex dump is the following:

    50 48 41 53 48 00 00 00 10 00 00 00 00 00 00 01 50 69 65 63 65 68 61 73 68 20 50 79 74 68 6f 6e
    20 30 2e 37 2e 31 00 00 00 00 00 00 00 00 00 00 53 45 47 10 5d 00 00 00 00 00 00 00 70 69 65 63
    65 68 61 73 68 2e 70 79 00 c9 f6 51 67 39 1d 1e 05 c7 90 d5 ad b5 78 77 c9 da 2e 0c 08 ad 25 ef
    d0 ef fb 2c c3 bd 0b 23 4c 32 7d da fc 78 b3 b9 35 59 99 22 5a 8e 53 7e 9e be f4 07 37 3b 37 dc
    92 87 85 bc 9b 49 d7 89 ab 81 9e df d2 5e 87 95 ca 8f f9 c4 42 bd 38 11 ad 1b 7d df e6 50 48 45
    4e 44 00
