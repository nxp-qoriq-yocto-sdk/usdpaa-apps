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

bin_PROGRAMS = srio_ipsec_offload

dist_DATA =  srio_ipsec_offload_config_b4860.xml srio_ipsec_offload_pcd_b4.xml \
             srio_ipsec_offload_policy.xml srio_ipsec_offload_swp.xml

AM_CFLAGS := -I$(TOP_LEVEL)/src/srio_ipsec_offload/srio/include\
	     $(FMC_CFLAGS) $(FMLIB_CFLAGS) $(LIBRTA_CFLAGS) $(LIBXML2_CFLAGS) \
	     $(DPAOFFLOAD_CFLAGS) -D$(SOC)

srio_ipsec_offload_SOURCES := srio_ipsec_offload.c pcd_init.c \
			srio_ipsec_init.c xfrm_km.c \
			pfkey_utils.c neigh_utils.c \
			route_utils.c stats_init.c \
			srio/rman.c srio/rman_interface.c \
			srio/rman_fq_interface.c \
			srio/srio.c

srio_ipsec_offload_LDADD := usdpaa_ppac usdpaa_syscfg

srio_ipsec_offload_LDFLAGS := -lusdpaa_qbman -lusdpaa_fman -lusdpaa_dma_mem \
			-lusdpaa_of -lusdpaa_process -lusdpaa_rman \
			-lusdpaa_srio -lusdpaa_dma -lusdpaa_sec \
			$(LIBXML2_LDFLAGS) $(LIBEDIT_LDFLAGS) \
			$(FMC_LDFLAGS) $(FMLIB_LDFLAGS) \
			$(DPAOFFLOAD_LDFLAGS) \
			-T $(TOP_LEVEL)/src/ppac/ppac.lds
