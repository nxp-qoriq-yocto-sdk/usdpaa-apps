/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <argp.h>
#include <error.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <readline.h>
#include <unistd.h>
#include <flib/rta.h>

#include "compat.h"
#include "fsl_qman.h"
#include "usdpaa_netcfg.h"
#include "nf_init.h"
#include "app_common.h"
#include "nl_events.h"
#include "xfrm_events.h"
#include "cli_cmd.h"

enum rta_sec_era rta_sec_era;

struct app_conf app_conf;
const char args_doc[] = "Offloading demo application";
static const struct argp_option options[] = {
	{"ib-loop", 'l', 0, 0, "Loopback on inbound Ethernet port", 0},
#if 0 /* Inbound policy verification is not yet supported */
	{"ib-pol-check", 'p', 0, 0, "Enable inbound policy verification", 0},
#endif
	{"vipsec", 'u', "FILE", 0 , "IPsec interface name", 0},
	{"vif", 'v', "FILE", 0 , "Virtual inbound interface name", 0},
	{"vof", 'w', "FILE", 0 , "Virtual outbound interface name", 0},
	{"outer-tos", 'x', "INT", 0, "Outer header TOS field", 0},
	{"disable-ib-ecn", 'y', 0, 0, "Disable inbound ECN tunneling", 0},
	{"disable-ob-ecn", 'z', 0, 0, "Disable outbound ECN tunneling", 0},
	{0}
};

static volatile sig_atomic_t main_quit = 0;

static void handle_sigint(int s)
{
	TRACE("signal catched: %d; SIGINT is %d\n", s, SIGINT);
	if (s == SIGINT)
		main_quit = 1;
}

static int setup_listeners(void)
{
	int ret;

	ret = setup_xfrm_msg_loop(gbl_init->ipsec.dpa_ipsec_id);
	if (ret < 0) {
		error(0, ret, "XFRM message loop start failed");
		return ret;
	}
	TRACE("Started XFRM messages processing.\n");

	ret = setup_nl_events_loop();
	if (ret < 0) {
		error(0, ret, "NEIGH message loop start failed");
		return ret;
	}
	TRACE("Started NL EVENTS messages processing.\n");

	return 0;
}

static int teardown_listeners(void)
{
	int ret;

	ret = teardown_xfrm_msg_loop();
	if (ret < 0) {
		error(0, ret, "XFRM message loop finish failed");
		return ret;
	}
	TRACE("Finished XFRM messages processing.\n");

	ret = teardown_nl_events_loop();
	if (ret < 0) {
		error(0, ret, "NEIGH message loop start failed");
		return ret;
	}
	TRACE("Finished NL EVENTS messages processing.\n");

	return 0;
}

static error_t parse_opts(
		int key,
		char *arg,
		struct argp_state *state __maybe_unused)
{
	switch (key) {
		case 'l':
			app_conf.ib_loop = true;
			break;
#if 0 /* Inbound policy verification is not yet supported */
		case 'p':
			app_conf.ib_policy_verification = true;
			break;
#endif
		case 'u':
			strncpy(app_conf.vipsec, arg, sizeof(app_conf.vipsec));
			break;
		case 'v':
			strncpy(app_conf.vif, arg, sizeof(app_conf.vif));
			break;
		case 'w':
			strncpy(app_conf.vof, arg, sizeof(app_conf.vof));
			break;
		case 'x':
			app_conf.outer_tos = atoi(arg);
			break;
		case 'y':
			app_conf.ib_ecn = false;
			break;
		case 'z':
			app_conf.ob_ecn = false;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static struct argp argp = {options, parse_opts, 0, args_doc, 0, 0, 0};

const char *argp_program_version = "ipsec_offload 1.0";

#ifdef ENABLE_TRACE
static void dump_conf(void)
{
	TRACE("Inbound loop .................. %s\n",
			app_conf.ib_loop ? "true" : "false");
	TRACE("Inbound policy verification ... %s\n",
			app_conf.ib_policy_verification ? "true" : "false");
	TRACE("VIPSEC ........................ '%s'\n",
			app_conf.vipsec);
	TRACE("VIF ........................... '%s'\n",
			app_conf.vif);
	TRACE("VOF ........................... '%s'\n",
			app_conf.vof);
	TRACE("Outer TOS ..................... %s\n",
			app_conf.outer_tos ? "true" : "false");
	TRACE("Inbound ECN ................... %s\n",
			app_conf.ib_ecn ? "true" : "false");
	TRACE("Outbound ECN .................. %s\n",
			app_conf.ob_ecn ? "true" : "false");
}
#endif /* ENABLE_TRACE */

int main(int argc, char *argv[])
{
	struct nf_user_data ui;
	int ret, i;
	int cli_argc = 0;
	char *cli = NULL, **cli_argv = NULL;

	/* Get application configuration from command line arguments */
	memset(&app_conf, 0, sizeof(app_conf));
	app_conf.ib_loop = false;
	app_conf.ib_policy_verification = false;
	app_conf.ib_ecn = true;
	app_conf.ob_ecn = true;
	ret = argp_parse(&argp, argc, argv, 0, 0, &app_conf);
	if (ret) {
		error(0, ret, "Fail to parse command line arguments");
		exit(EXIT_FAILURE);
	}
#ifdef ENABLE_TRACE
	dump_conf();
#endif

	/* Install ctrl-c handler */
	if (signal(SIGINT, handle_sigint) == SIG_ERR) {
		perror("Fail to install signal handler for SIGINT.");
		exit(EXIT_FAILURE);
	}

	/* alloc and set user info */
	ui.ipsec_user_data = malloc(sizeof(*ui.ipsec_user_data));
	if (!ui.ipsec_user_data) {
		error(0, ENOMEM, "Fail to allocate ipsec_user_data");
		exit(EXIT_FAILURE);
	}

	/* This should be retrieved from xml? */
	ui.ipsec_user_data->max_sa =
		NUM_SETS * NUM_WAYS * DPA_IPSEC_MAX_SA_TYPE;
	ui.ipsec_user_data->bpid = IF_BPID;
	ui.ipsec_user_data->bufsize = DMA_MEM_IF_SIZE;

	ui.ipfwd_user_data = malloc(sizeof(*ui.ipfwd_user_data));
	if (!ui.ipfwd_user_data) {
		error(0, ENOMEM, "Fail to allocate ipsec_user_data");
		exit(EXIT_FAILURE);
	}
	ui.ipfwd_user_data->init_ipv4 = true;
	ui.ipfwd_user_data->init_ipv6 = true;

	/* Initialize NFAPI */
	ret = nf_init(&ui);
	if (ret < 0) {
		error(0, ret, "Failed to init NFAPI");
		return -1;
	}

	sleep(1);
	/* Start XFRM and Netlink listneners */
	ret = setup_listeners();
	if (ret < 0) {
		error(0, ret, "Failed to setup listeners");
		goto nf_finish;
	}

	/* Enable loopback if necessary */
	if (app_conf.ib_loop)
		fman_if_loopback_enable(gbl_init->ipsec.ifs_by_role[IB]);

	printf("Hit Ctrl+C, send SIGINT or write quit to terminate.\n");
	fflush(stdout);
	fflush(stdin);
	while(!main_quit) {
		cli = readline("> ");
		if (cli == NULL) {
			fprintf(stderr, "Error while reading command.\n");
			break;
		}
		if (cli[0] == '\0') {
			free(cli);
			continue;
		}

		/* Compute arguments for command. */
		cli_argv = history_tokenize(cli);
		if (cli_argv == NULL) {
			fprintf(stderr, "Error while parsing command '%s'.\n",
				cli);
			free(cli);
			continue;
		}
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++);

		/* Call appropiate function. */
		ret = 0;
		if (!strcmp(cli_argv[0], "quit"))
			break;

		if (!strcmp(cli_argv[0], "help")) {
			fprintf(stderr, "\nAvailable commands:\n");
			fprintf(stderr, "\thelp\n");
			fprintf(stderr, "\tquit\n");
			i = 0;
			while ((i < MAX_CLI_COMMANDS) &&
						(cli_command[i].name[0])) {
				fprintf(stderr, "\t%s\n",
							cli_command[i++].name);
			}
			fprintf(stderr, "\n");
		} else {
			i = 0;
			while ((i < MAX_CLI_COMMANDS) &&
						(cli_command[i].name[0])) {
				if (!strcmp(cli_argv[0], cli_command[i].name)) {
					ret = cli_command[i].func(cli_argc,
								cli_argv);
					break;
				}
				i++;
			}
			if ((i >= MAX_CLI_COMMANDS) ||
						(!cli_command[i].name[0])) {
				fprintf(stderr, "Command not found: %s\n\n",
					cli_argv[0]);
				ret = -ENOENT;
			}
		}

		if (ret)
			error(0, -ret, "Error on command");
		else
			add_history(cli);

		/* Free command. */
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++)
			free(cli_argv[cli_argc]);
		free(cli_argv);
		free(cli);
	}

	TRACE("Terminating program...\n");
	ret = teardown_listeners();
	if (ret < 0)
		error(0, ret, "Failed to teardown listeners");

nf_finish:
	nf_finish();

	return 0;
}
