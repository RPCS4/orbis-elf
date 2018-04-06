# Used to install the files
# in another temporary location first.
# This variable is added before PREFIX
# and should contain a trailing slash.
DESTDIR ?=
# Specifies where to create the '/lib',
# '/include', and '/bin' directories.
# Should not contain a trailing slash.
PREFIX ?= /usr/local
