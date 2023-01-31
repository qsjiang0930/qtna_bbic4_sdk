#
# (C) Copyright 2007 Quantenna Communications Inc.
#

modules := utilities pktlogger-ng
modules_clean := $(patsubst %, %_clean, $(modules)) umsdl_clean qcsapi-client_clean pktlogger grabber_clean
modules_distclean := $(patsubst %, %_distclean, $(modules)) umsdl_distclean qcsapi-client_distclean grabber_distclean

.PHONY: umsdl stat_parser struct-extract qcsapi-client qevt-client qregcheck grabber \
$(modules) $(modules_clean) $(modules_distclean)

POST_ANALYSIS=pktlogger/post_analysis_tools.tar

all: umsdl stat_parser struct-extract qcsapi-client qevt-client $(modules)

clean: $(modules_clean)

distclean: $(modules_distclean)

umsdl:
	make -C umsdl BUILD_TARBALL=y

qcsapi-client:
	make -C qcsapi-client clean zips

qregcheck grabber:
	if [ -d "$@" ]; then make -C "$@" all; fi

qevt-client:
	make -C qevt-client

ifneq ($(modules),)
$(modules):
	if [ -d "$@" ]; then make -C "$@"; fi
endif

$(modules_clean):
	dir=$(patsubst %_clean,%,$@); if [ -d "$$dir" ]; then make -C $$dir clean; fi

$(modules_distclean):
	dir=$(patsubst %_distclean,%,$@); if [ -d "$$dir" ]; then make -C $$dir distclean; fi

stat_parser: ${POST_ANALYSIS}
	if [ -d pktlogger ]; then make -C pktlogger all; fi

struct-extract:
	if [ -d struct-extract ] ; then make -C struct-extract clean se_prepro nodeps ; fi

ll_trace:
	if [ -d ll_trace ] ; then
		echo "LL trace"
	fi

${POST_ANALYSIS}: struct-extract
	if [ -d struct-extract -a -d ${@D} ] ; then tar cfv $@ struct-extract/ ; fi

