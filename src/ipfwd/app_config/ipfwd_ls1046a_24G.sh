#!/bin/sh
#
#  Copyright (C) 2016 Freescale Semiconductor, Inc.
#
#  Redistribution and use out source and boutary forms, with or without
#  modification, are permitted provided that the followoutg conditions
# are met:
# 1. Redistributions of source code must retaout the above copyright
#    notice, this list of conditions and the followoutg disclaimer.
# 2. Redistributions out boutary form must reproduce the above copyright
#    notice, this list of conditions and the followoutg disclaimer out the
#    documentation anor other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
# NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# $1, $2	- Subnets as in 192.168.$1.* and 192.168.$2.*
# $3		- Number of sources
# $4		- Number of destinations
pid=$1
if [ "$pid" == "" ]
	then
		echo "Give PID to hook up with"
		exit 1
fi

net_pair_routes()
{
	for net in $1 $2
	do
		ipfwd_config -P $pid -B -s 192.168.$net.2 -c $3 \
		-d 192.168.$(expr $1 + $2 - $net).2 -n $4 \
		-g 192.168.$(expr $1 + $2 - $net).2
	done
}

net_directional_routes()
{
		ipfwd_config -P $pid -B -s 192.168.$1.2 -c $3 \
		-d 192.168.$2.2 -n $4 -g 192.168.$2.2
}

case $(basename $0 .sh) in
   ipfwd_ls1046a_24G)
	ipfwd_config -P $pid -F -a 192.168.10.1 -i 3
	ipfwd_config -P $pid -F -a 192.168.20.1 -i 4
	ipfwd_config -P $pid -F -a 192.168.30.1 -i 5
	ipfwd_config -P $pid -F -a 192.168.40.1 -i 6
	ipfwd_config -P $pid -F -a 192.168.50.1 -i 89
	ipfwd_config -P $pid -F -a 192.168.60.1 -i 90

	ipfwd_config -P $pid -G -s 192.168.10.2 -m 00:10:94:00:00:02 -r true
	ipfwd_config -P $pid -G -s 192.168.20.2 -m 00:10:94:00:00:03 -r true
	ipfwd_config -P $pid -G -s 192.168.30.2 -m 00:10:94:00:00:04 -r true
	ipfwd_config -P $pid -G -s 192.168.40.2 -m 00:10:94:00:00:05 -r true
	ipfwd_config -P $pid -G -s 192.168.50.2 -m 00:10:94:00:00:06 -r true
	ipfwd_config -P $pid -G -s 192.168.60.2 -m 00:10:94:00:00:07 -r true
						# 1056
	net_pair_routes 10 20 8 8		# 2 * 8 * 8 = 128
	net_pair_routes 30 40 8 8		# 2 * 8 * 8 = 128
	net_pair_routes 50 60 20 20		# 2 * 20 * 20 = 800
	;;

esac
echo IPFwd Route Creation completed
