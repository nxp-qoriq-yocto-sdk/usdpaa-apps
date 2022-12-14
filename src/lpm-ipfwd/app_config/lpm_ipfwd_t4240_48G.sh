#!/bin/sh
#
#  Copyright (C) 2014 Freescale Semiconductor, Inc.
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
net=0
	while [ "$net" -le $5 ]
	do
		lpm_ipfwd_config -P $pid -B -c $2 -d $1.$net.24.2 -n $3 -g \
		192.168.$4.2
		net=`expr $net + 1`
	done
}

lpm_ipfwd_config -P $pid -F -a 192.168.10.1 -i 1
lpm_ipfwd_config -P $pid -F -a 192.168.20.1 -i 2
lpm_ipfwd_config -P $pid -F -a 192.168.30.1 -i 3
lpm_ipfwd_config -P $pid -F -a 192.168.40.1 -i 4
lpm_ipfwd_config -P $pid -F -a 192.168.50.1 -i 89
lpm_ipfwd_config -P $pid -F -a 192.168.60.1 -i 90
lpm_ipfwd_config -P $pid -F -a 192.168.100.1 -i 101
lpm_ipfwd_config -P $pid -F -a 192.168.110.1 -i 102
lpm_ipfwd_config -P $pid -F -a 192.168.120.1 -i 103
lpm_ipfwd_config -P $pid -F -a 192.168.130.1 -i 104
lpm_ipfwd_config -P $pid -F -a 192.168.140.1 -i 189
lpm_ipfwd_config -P $pid -F -a 192.168.150.1 -i 190

lpm_ipfwd_config -P $pid -G -s 192.168.10.2 -m 02:00:c0:a8:a:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.20.2 -m 02:00:c0:a8:14:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.30.2 -m 02:00:c0:a8:1e:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.40.2 -m 02:00:c0:a8:28:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.50.2 -m 02:00:c0:a8:32:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.60.2 -m 02:00:c0:a8:3c:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.100.2 -m 02:00:c0:a8:64:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.110.2 -m 02:00:c0:a8:6e:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.120.2 -m 02:00:c0:a8:78:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.130.2 -m 02:00:c0:a8:82:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.140.2 -m 02:00:c0:a8:8c:02 -r true
lpm_ipfwd_config -P $pid -G -s 192.168.150.2 -m 02:00:c0:a8:96:02 -r true


					# 1024
net_pair_routes 190 1 16 10 63		# 64
net_pair_routes 191 1 16 20 63		# 64
net_pair_routes 192 1 16 30 63		# 64
net_pair_routes 193 1 16 40 63		# 64
net_pair_routes 194 1 16 50 127		# 128
net_pair_routes 195 1 16 60 127		# 128
net_pair_routes 196 1 16 100 63		# 64
net_pair_routes 197 1 16 110 63		# 64
net_pair_routes 198 1 16 120 63		# 64
net_pair_routes 199 1 16 130 63		# 64
net_pair_routes 200 1 16 140 128	# 128
net_pair_routes 201 1 16 150 128	# 128

echo LPM-IPFwd Route Creation completed
