/* Copyright (c) 2008-2010 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include "private.h"

/*************/
/* constants */
/*************/

#define CGR_ID		27
#define POOL_ID		12
#define FQ_FLAGS	QMAN_FQ_FLAG_DYNAMIC_FQID
#define NUM_ENQUEUES	100
#define NUM_PARTIAL	4
#define PORTAL_SDQCR	(QM_SDQCR_SOURCE_CHANNELS | \
			QM_SDQCR_TYPE_PRIO_QOS | \
			QM_SDQCR_TOKEN_SET(0x98) | \
			QM_SDQCR_CHANNELS_DEDICATED | \
			QM_SDQCR_CHANNELS_POOL(POOL_ID))
#define PORTAL_OPAQUE	(void *)0xf00dbeef
#define VDQCR_FLAGS	(QMAN_VOLATILE_FLAG_WAIT | QMAN_VOLATILE_FLAG_FINISH)
#define PORTAL_FLAGS	QMAN_PORTAL_FLAG_IRQ

/*************************************/
/* Predeclarations (eg. for fq_base) */
/*************************************/

static enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *,
					struct qman_fq *,
					const struct qm_dqrr_entry *);
static void cb_ern(struct qman_portal *, struct qman_fq *,
			const struct qm_mr_entry *);
static void cb_dc_ern(struct qman_portal *, struct qman_fq *,
			const struct qm_mr_entry *);
static void cb_fqs(struct qman_portal *, struct qman_fq *,
			const struct qm_mr_entry *);

/***************/
/* global vars */
/***************/

static __thread struct qm_fd fd, fd_dq;
static __thread struct qman_fq fq_base = {
	.cb.dqrr = cb_dqrr,
	.cb.ern = cb_ern,
	.cb.dc_ern = cb_dc_ern,
	.cb.fqs = cb_fqs
};
static __thread DECLARE_WAIT_QUEUE_HEAD(waitqueue);
static __thread int retire_complete, sdqcr_complete;

/**********************/
/* internal functions */
/**********************/

/* Helpers for initialising and "incrementing" a frame descriptor */
static void fd_init(struct qm_fd *__fd)
{
	__fd->addr_hi = 0xab;		/* high 16-bits */
	__fd->addr_lo = 0xdeadbeef;	/* low 32-bits */
	__fd->format = qm_fd_contig_big;
	__fd->length29 = 0x0000ffff;
	__fd->cmd = 0xfeedf00d;
}

static void fd_inc(struct qm_fd *__fd)
{
	__fd->addr_lo++;
	__fd->addr_hi--;
	__fd->length29--;
	__fd->cmd++;
}

/* The only part of the 'fd' we can't memcmp() is the ppid */
static int fd_cmp(const struct qm_fd *a, const struct qm_fd *b)
{
	int r = a->addr_hi - b->addr_hi;
	if (!r)
		r = a->addr_lo - b->addr_lo;
	if (!r)
		r = a->format - b->format;
	if (!r)
		r = a->opaque - b->opaque;
	if (!r)
		r = a->cmd - b->cmd;
	return r;
}

/********/
/* test */
/********/

static void do_enqueues(struct qman_fq *fq)
{
	unsigned int loop;
	for (loop = 0; loop < NUM_ENQUEUES; loop++) {
		if (qman_enqueue(fq, &fd, QMAN_ENQUEUE_FLAG_WAIT |
				(((loop + 1) == NUM_ENQUEUES) ?
				QMAN_ENQUEUE_FLAG_WAIT_SYNC : 0)))
			panic("qman_enqueue() failed\n");
		fd_inc(&fd);
	}
}

void qman_test_high(thread_data_t *tdata)
{
	struct qman_cgrs cgrs;
	int res;
	u32 flags;
	struct qman_fq *fq = &fq_base;

	pr_info("QMAN:  --- starting high-level test (cpu %d) ---\n",
		tdata->cpu);
	sync_all();
	fd_init(&fd);
	fd_init(&fd_dq);
	qman_cgrs_init(&cgrs);
	qman_cgrs_set(&cgrs, CGR_ID);

	/* Initialise (parked) FQ */
	if (qman_create_fq(0, FQ_FLAGS, fq))
		panic("qman_create_fq() failed\n");
	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_LOCAL, NULL))
		panic("qman_init_fq() failed\n");

	/* Do enqueues + VDQCR, twice. (Parked FQ) */
	do_enqueues(fq);
	if (qman_volatile_dequeue(fq, VDQCR_FLAGS,
			QM_VDQCR_NUMFRAMES_TILLEMPTY))
		panic("qman_volatile_dequeue() failed\n");
	do_enqueues(fq);
	if (qman_volatile_dequeue(fq, VDQCR_FLAGS,
			QM_VDQCR_NUMFRAMES_SET(NUM_PARTIAL)))
		panic("qman_volatile_dequeue() failed\n");
	if (qman_volatile_dequeue(fq, VDQCR_FLAGS,
			QM_VDQCR_NUMFRAMES_SET(NUM_ENQUEUES - NUM_PARTIAL)))
		panic("qman_volatile_dequeue() failed\n");

	do_enqueues(fq);
	if (qman_schedule_fq(fq))
		panic("qman_schedule_fq() failed\n");
	wait_event(waitqueue, sdqcr_complete);

	/* Retire and OOS the FQ */
	res = qman_retire_fq(fq, &flags);
	if (res < 0)
		panic("qman_retire_fq() failed\n");
	wait_event(waitqueue, retire_complete);
	if (flags & QMAN_FQ_STATE_BLOCKOOS)
		panic("leaking frames\n");
	if (qman_oos_fq(fq))
		panic("qman_oos_fq() failed\n");
	qman_destroy_fq(fq, 0);
	sync_all();
	pr_info("QMAN:  --- finished high-level test (cpu %d) ---\n",
		tdata->cpu);
}

static enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *p,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dq)
{
	if (fd_cmp(&fd_dq, &dq->fd)) {
		pr_err("BADNESS: dequeued frame doesn't match;\n");
		BUG();
	}
	fd_inc(&fd_dq);
	if (!(dq->stat & QM_DQRR_STAT_UNSCHEDULED) && !fd_cmp(&fd_dq, &fd)) {
		sdqcr_complete = 1;
		wake_up(&waitqueue);
	}
	return qman_cb_dqrr_consume;
}

static void cb_ern(struct qman_portal *p, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	panic("cb_ern() unimplemented");
}

static void cb_dc_ern(struct qman_portal *p, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	panic("cb_dc_ern() unimplemented");
}

static void cb_fqs(struct qman_portal *p, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	u8 verb = (msg->verb & QM_MR_VERB_TYPE_MASK);
	if ((verb != QM_MR_VERB_FQRN) && (verb != QM_MR_VERB_FQRNI))
		panic("unexpected FQS message");
	pr_info("Retirement message received\n");
	retire_complete = 1;
	wake_up(&waitqueue);
}

