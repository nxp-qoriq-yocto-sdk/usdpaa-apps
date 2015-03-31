# Copyright (c) 2015 Freescale Semiconductor, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
#
#
# ALTERNATIVELY, this software may be distributed under the terms of the
# GNU General Public License ("GPL") as published by the Free Software
# Foundation, either version 2 of that License or (at your option) any
# later version.
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

bin_PROGRAMS = dpa_offload

dist_DATA = dpa_offload_config_b4860.xml \
	    dpa_offload_pcd_b4.xml \
	    dpa_offload_policy.xml \
	    dpa_offload_swp.xml

AM_CFLAGS := $(FMC_CFLAGS) $(FMLIB_CFLAGS) $(LIBXML2_CFLAGS) \
	     $(LIBNL_CFLAGS) $(DPAOFFLOAD_CFLAGS) $(LIBXML2_CFLAGS) \
	     $(LIBEDIT_CFLAGS) -Wall -Wextra

$(bin_PROGRAMS)_SOURCES := pfkey_utils.c \
			   nl_events.c \
			   xfrm_events.c \
			   dpa_offload.c \
			   cli_cmd.c \
			   nf_init.c

$(bin_PROGRAMS)_LDADD := usdpaa_syscfg

$(bin_PROGRAMS)_LDFLAGS := -lusdpaa_qbman -lusdpaa_dma_mem -lusdpaa_mm \
			   -lusdpaa_fman -lusdpaa_of -lusdpaa_process \
			   $(LIBNL_LDFLAGS) $(DPAOFFLOAD_LDFLAGS) \
			   $(FMC_LDFLAGS) $(FMLIB_LDFLAGS) \
			   $(LIBXML2_LDFLAGS) $(LIBEDIT_LDFLAGS)
