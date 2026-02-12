# Makefile for sm-ext-Voice SourceMod Extension
# Compatible with MetaMod:Source 1.12 and CS:S

# -----------------------------
# Configurable paths
# -----------------------------
ENGINE ?= css

# Paths to include directories
CURDIR         = .
SM_PUBLIC      = ../../public
SP_INCLUDE     = ../../sourcepawn/include
AMTL_INCLUDE   = ../../public/amtl
HL2SDK_PUBLIC  = ../../../hl2sdk-css/public
HL2SDK_SERVER  = ../../../hl2sdk-css/public/game/server
HL2SDK_ENGINE  = ../../../hl2sdk-css/public/engine
HL2SDK_TIER0   = ../../../hl2sdk-css/public/tier0
HL2SDK_TIER1   = ../../../hl2sdk-css/public/tier1
MMSOURCE_CORE  = ../../../mmsource-1.12/core
MMSOURCE_PUBLIC= ../../../mmsource-1.12/public
SOURCEHOOK     = ../../../mmsource-1.12/core/sourcehook

# -----------------------------
# Compiler flags
# -----------------------------
CXX      = g++
CXXFLAGS = -m32 -O3 -DNDEBUG -DSOURCE_ENGINE=6 -DPOSIX \
           -msse -DHAVE_STDINT_H \
           -Dstricmp=strcasecmp -D_stricmp=strcasecmp \
           -Dstrnicmp=strncasecmp -Dstrnicmp=strncasecmp \
           -D_snprintf=snprintf -D_vsnprintf=vsnprintf \
           -D_alloca=alloca -DCOMPILER_GCC -DSOURCEMOD_BUILD \
           -fno-strict-aliasing -fvisibility-inlines-hidden \
           -std=c++11 -fno-exceptions -fno-rtti \
           -Wall -Wno-overloaded-virtual -Wno-switch -Wno-unused \
           -I$(CURDIR) \
           -I$(SM_PUBLIC) \
           -I$(SP_INCLUDE) \
           -I$(AMTL_INCLUDE) \
           -I$(AMTL_INCLUDE)/amtl \
           -I$(HL2SDK_SERVER) \
		   -I$(HL2SDK_PUBLIC) \
           -I$(HL2SDK_ENGINE) \
           -I$(HL2SDK_TIER0) \
           -I$(HL2SDK_TIER1) \
           -I$(MMSOURCE_PUBLIC) \
           -I$(MMSOURCE_CORE) \
           -I$(SOURCEHOOK)

SRC = smsdk_ext.cpp
OBJ = Release/smsdk_ext.o
OUT = Release/sm-ext-Voice.ext.so

# -----------------------------
# Build rules
# -----------------------------
all: $(OUT)

Release:
	mkdir -p Release

$(OBJ): $(SRC) | Release
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	$(CXX) $(CXXFLAGS) -shared $^ -o $@

clean:
	rm -rf Release/*.o
	rm -rf Release/*.so

.PHONY: all clean
