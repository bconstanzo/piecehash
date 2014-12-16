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

|Field         |Length  |Details                                  |
|--------------|--------|-----------------------------------------|
|Segment ID    |4 bytes |ID from Segment Type List.               |
|Segment length|8 bytes |Length of segment data.                  |
|(data)        |N bytes |Segment data, N = Segment length.        |
|CRC-32        |4 bytes |CRC-32 of data, to verify file integrity.|

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
