More detailed description to follow...

For deployment in an app
-----------

1. Build using standard NDK toolchain
2. Place files in res/raw as libs/<arch>/tcptester --> res/raw/tcptester_<arch>

Currently also relying on com.stericson.RootTools package for Root-related functionality, included in src/

The rest of the code is made to be compatible with ICSI's netalyzr, no fragments of which are included.