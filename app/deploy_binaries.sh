#!/bin/bash

ndk-build && \
  cp obj/local/armeabi/tcptester res/raw/tcptester_armeabi && \
  cp obj/local/armeabi-v7a/tcptester res/raw/tcptester_armeabi_v7a && \
  cp obj/local/x86/tcptester res/raw/tcptester_x86 
