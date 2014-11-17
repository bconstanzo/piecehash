Changelog:
==========
##Version 0.7.1:
* CHANGELOG is now Markdown.
* Added /docs folder, where you can find the docs describing the file format. This should be a
saner/simpler way to read and understand it than having to dig the Python code and comments.
* /docs/piecehash.md describes the file format. It is based on the comments that can be found in
the code.
* Added "forcecompare" mode to spot files which report the same MD5 but are different -- there have
been lately reports and tools made to force MD5 collisions and this mode helps to spot them.
    * In a following update a file-size check could be made to spot this kind of attack
    automatically, but that would require changing the File Info Segment format and storing the
    original filesize.
    * Before breaking the format, it must be decided if it is a valuable feature in the first place.

##Version 0.7:
* Split classes from CLI functions:
    * piecehash.py now holds the classes that implement the Piecewise Hash File Format. If you
    want to make a program that uses PHash Files, import this.
    * phash.py now hold all the command line related functions, and has become the program you
    call from the CLI.
    * constants.py holds the constants and variables that are used by both pieciehash.py and
    phash.py. Will try to move the more specific ones to their corresponding file.
* Added lazy param to PHashFile.AddFile() and add the logic to make lazy and non-lazy inserts.
* (Hopefully) better docstrings all around.

##Version 0.6.1:
* Added DEBUG_BENCHMARK for timings.
* Small fixes all around for code style consistency.
* This is a cleanup before 0.7, which will split the classes and CLI into separate files.
* SHA-1, SHA-256 and SHA-512 were tested, and everything apparently works.

##Version 0.6:
* Convert mode works. Convert mode is aimed at taking the output of another Piecehash Capable
Program (eg: Kornblum's dc3dd, md5deep, hashdeep, others?) and translate that into a PHash File.
* Small changes to the methods of PHashFile and FileInfo to have better supprot for Convert mode.
* Changes should also allow different (new) modes of operation.

##Version 0.5:
* Compare mode works. It already worked, but needed more testing with further changes -- still
an objective, there's always something to fix!
* Multiple files per container tested. The file format and classes supported it, but the CLI
tool was lacking support.
* Better error handling when opening (bad) PHash files.

##Version 0.4.1:
* Show mode works.

##Version 0.4:
* Hash mode works on arbitrary segment sizes.

##Version 0.3.2:
* If a file is longer than the hashed-original, (and additional content was added after a
segment aligned border (eg: we had a 1 MB file, and then we add 100 more bytes), piecehash can
recognize the now-longer file and reports additions correctly.
* It can also recognize a shorter-than-original file, and indicates the missing blocks at the
end.
* In both cases, unless the changes are aligned to a segment-border, the last block present in
both lists will have a different hash value.

##Version 0.3.1:
* Slight improvements in code.
* Small changes in CLI behaviour.
* Hopefully better/clearer code.

##Version 0.3:
* Hash mode works with 1 MiB sizes and a single file
* PHash file format works

##Version 0.2:
* See Note 2014-07-08 and Note 2014-07-13

##Version 0.1:
* Structure layout
* Most functions are dummys
* Work in progress!

#Roadmap:
##Version 0.7+ (undefined version number):
* Log file for verbose details.
* Observer interface for communication with the "outer world". This should bring cleaner code in
the CLI functions and provide a better interface for "interactivity". Specially useful when
working with large files!
* Provide iterator equivalents of FileInfo.GetHashes() and FileInfo.CalculateHashes().