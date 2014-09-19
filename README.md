piecehash
=========

A program for calculating piecewise hashes of files.

Introduction
============

piecehash is a program for calculating many MD5 (or other algorithm) hashes for a file, and also has
the definition and reference implementation of a file format that stores the calculated hashes.
Although it is not finished, it is already able to perform hashing and comparisons.

Why?
====

A friend, who is a forensic expert, had a problem with large disk image files. We came to the
conclusion that a viable solution to his problem was to calculate an MD5 hash every MB or so. With a
little more thought, we defined a set of requirements, both for the program and for the file format
that would store all that information.

Then we found out about Kornblum's and Harbour's work, and I set to implement the original idea,
while also bringing compatibility with the previous work.

In particular, the file format avoids a lot of redundancy that appears in md5deep and hashdeep files
-- that means the .phash files are smaller, a lot smaller, usually between 75 to 80% smaller than
the raw md5deep file. Even if you compress an md5deep, the phash equivalent is usualy 20 to 25%
smaller. Also, in the eventual case that you get a smaller file compressing an md5deep file, you
can still compress the .phash file.

The format was defined to be "low-level friendly", even though its been all implemented in Python so
far. You are invited to write your own PHash Compatible Program.

Notes
=====

* Note 2014-07-08:
I just found out of Jesse Kornblum's work on hashdeep, md5deep and dc3dd with piecewise hashes
which provide the same functionality I was aiming for with p-hash (partial-hashes). P still
stands in the name, now for piecewise. Will do some work to provide compatibility with
Kornblums implementation, and focus work more in the binary file format.

* Note 2014-0713:
Name changed from "PHash" to "piecehash" to avoid confusion with pHash, and also recognize
Nick Harbour's and Jesse Kornblum's previous work on this topic.
There are still some references to PHash arround, but it should be clear enough by now.

Bruno Constanzo, 2014

Afterword
=========

Special thanks to Fernando Greco, Ana Di Iorio, Hugo Curti, Juan Iturriaga, Marcos Vivar, Javier
Constanzo and Ariel Podesta for ideas, comments and advice.