/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#ifndef USE_LOBOTOMIZED_AES
#include <cpuid.h>
#endif
#include "compat.h"
#include "miner.h"
#include "cryptonight.h"
#include "elist.h"

#if defined __unix__ && (!defined __APPLE__)
#include <sys/mman.h>
#elif defined _WIN32
#include <windows.h>
#endif

#define PROGRAM_NAME		"minerd"
#define DEF_RPC_URL        "http://127.0.0.1:9332/"
 #define MINER_VERSION  "v1.1"
#define LP_SCANTIME		60
#define JSON_BUF_LEN 345

#ifdef __unix__
#include <sys/mman.h>
#endif

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void) {
    struct sched_param param;
    param.sched_priority = 0;
	
	sched_setscheduler(0, SCHED_OTHER, &param);
}

static inline void affine_to_cpu(int id, int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif

#define MAX_THREADS	256

enum workio_commands {
    WC_GET_WORK, WC_SUBMIT_WORK,
};

struct workio_cmd {
    enum workio_commands cmd;
    struct thr_info *thr;
    union {
        struct work *work;
    } u;
};

enum mining_algo {
    ALGO_SCRYPT,      /* scrypt(1024,1,1) */
    ALGO_SHA256D,     /* SHA-256d */
    ALGO_KECCAK,      /* Keccak */
    ALGO_HEAVY,       /* Heavy */
    ALGO_QUARK,       /* Quark */
    ALGO_SKEIN,       /* Skein */
    ALGO_SHAVITE3,    /* Shavite3 */
    ALGO_BLAKE,       /* Blake */
    ALGO_X11,         /* X11 */
    ALGO_CRYPTONIGHT, /* CryptoNight */
};

static const char *algo_names[] = {
    [ALGO_SCRYPT] =      "scrypt",
    [ALGO_SHA256D] =     "sha256d",
    [ALGO_KECCAK] =      "keccak",
    [ALGO_HEAVY] =       "heavy",
    [ALGO_QUARK] =       "quark",
    [ALGO_SKEIN] =       "skein",
    [ALGO_SHAVITE3] =    "shavite3",
    [ALGO_BLAKE] =       "blake",
    [ALGO_X11] =         "x11",
    [ALGO_CRYPTONIGHT] = "cryptonight",
};

bool opt_debug = false;
bool opt_protocol = false;
static bool opt_benchmark = false;
bool opt_redirect = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool want_stratum = true;
bool have_stratum = false;
static bool submit_old = false;
bool use_syslog = false;
static bool opt_background = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
bool jsonrpc_2 = false;
int opt_timeout = 0;
static int opt_scantime = 5;
static json_t *opt_config;
static const bool opt_time = true;
static enum mining_algo opt_algo = ALGO_CRYPTONIGHT;
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int check_pool_thr_id = -1;
struct work_restart *work_restart = NULL;
static struct stratum_ctx *stratum;
static char rpc2_id[64] = "";
static char *rpc2_blob = NULL;
static int rpc2_bloblen = 0;
static uint32_t rpc2_target = 0;
static char *rpc2_job_id = NULL;

time_t time_start;

pthread_mutex_t applog_lock;
pthread_mutex_t tui_lock;
pthread_mutex_t pool_lock;
pthread_mutex_t check_pool_lock;
pthread_cond_t check_pool_cond;
pthread_mutex_t switch_pool_lock;
static pthread_mutex_t stats_lock;
static pthread_mutex_t rpc2_job_lock;
static pthread_mutex_t rpc2_login_lock;

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;
static double *thr_hashrates;
static double *thr_times;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#endif

static char const usage[] =
        "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       timeout for long polling, in seconds (default: none)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --no-longpoll     disable X-Long-Polling support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           disable per-thread hashmeter output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
        "\
  -S, --syslog          use system log for output messages\n"
#endif
#ifndef WIN32
        "\
  -B, --background      run the miner in the background\n"
#endif
        "\
      --benchmark       run in offline benchmark mode\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifndef WIN32
        "B"
#endif
#ifdef HAVE_SYSLOG_H
                "S"
#endif
        "a:c:Dhp:Px:qr:R:s:t:T:o:u:O:V";

static struct option const options[] = {
        { "algo", 1, NULL, 'a' },
#ifndef WIN32
        { "background", 0, NULL, 'B' },
#endif
        { "benchmark", 0, NULL, 1005 },
        { "cert", 1, NULL, 1001 },
        { "config", 1, NULL, 'c' },
        { "pools", 1, NULL, '\0' },
        { "debug", 0, NULL, 'D' },
        { "help", 0, NULL, 'h' },
        { "no-longpoll", 0, NULL, 1003 },
        { "no-redirect", 0, NULL, 1009 },
        { "no-stratum", 0, NULL, 1007 },
        { "pass", 1, NULL, 'p' },
        { "protocol-dump", 0, NULL, 'P' },
        { "proxy", 1, NULL, 'x' },
        { "quiet", 0, NULL, 'q' },
        { "retries", 1, NULL, 'r' },
        { "retry-pause", 1, NULL, 'R' },
        { "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
        { "syslog", 0, NULL, 'S' },
#endif
        { "threads", 1, NULL, 't' },
        { "timeout", 1, NULL, 'T' },
        { "url", 1, NULL, 'o' },
        { "user", 1, NULL, 'u' },
        { "userpass", 1, NULL, 'O' },
        { "version", 0, NULL, 'V' },
        { 0, 0, 0, 0 }
};

static bool can_work = false;

struct work {
    uint32_t data[32];
    uint32_t target[8];
    char job_id[128];
    uint32_t work_id;
    size_t xnonce2_len;
    unsigned char xnonce2[8];
    unsigned short thr_id;
};

struct work_items
{
    struct list_head list;
    int thr_id;
    uint32_t nonce;
    uint16_t work_id;
    uint16_t id;
    double diff;
};

static struct work g_work;
static time_t g_work_time;
static time_t g_work_update_time;
static pthread_mutex_t g_work_lock;

static struct work_items *work_items;
static pthread_mutex_t work_items_lock;

// Begin Pool section from cpuminer-gc3555
struct pool_stats
{
    struct list_head list;
    unsigned int time_start;
    unsigned int time_stop;
    unsigned int accepted;
    unsigned int rejected;
    unsigned long long shares;
    unsigned int id;
};

struct pool_details
{
    struct list_head list;
    char *rpc_url;
    char *rpc_userpass;
    char *rpc_user, *rpc_pass;
    uint16_t prio;
    bool active;
    bool tried;
    bool usable;
    unsigned int id;
    struct pool_stats stats;
};

static struct pool_details *gpool;
static struct pool_details *pools;
static bool must_switch = false;

static struct pool_details* init_pool_details();
static void add_pool(struct pool_details *pools, struct pool_details *pool);
static void set_active_pool(struct pool_details *pools, struct pool_details *active_pool, bool active);
static struct pool_details* get_active_pool(struct pool_details *pools);
static struct pool_details* get_main_pool(struct pool_details *pools);
static struct pool_details* get_next_pool(struct pool_details *pools);

static struct pool_details* init_pool_details()
{
    struct pool_details *pools = calloc(1, sizeof(struct pool_details));
    INIT_LIST_HEAD(&pools->list);
    INIT_LIST_HEAD(&pools->stats.list);
    return pools;
}

static struct pool_details* new_pool(bool empty)
{
    struct pool_details *pool = calloc(1, sizeof(struct pool_details));
    INIT_LIST_HEAD(&pool->stats.list);
    if(empty)
    {
        pool->rpc_url = DEF_RPC_URL;
        pool->rpc_user = strdup("");
        pool->rpc_pass = strdup("");
    }
    return pool;
}

static void add_pool_url(struct pool_details *pools, struct pool_details *pool, char *str)
{
    if(pool == NULL)
        pool = new_pool(false);
    if(pool != gpool)
        gpool = pool;
    if(pool->rpc_url != NULL)
        free(pool->rpc_url);
    pool->rpc_url = strdup(str);
    if(pool->rpc_url && pool->rpc_user && pool->rpc_pass)
        add_pool(pools, pool);
}

static void add_pool_user(struct pool_details *pools, struct pool_details *pool, char *str)
{
    if(pool == NULL)
        pool = new_pool(false);
    if(pool != gpool)
        gpool = pool;
    if(pool->rpc_user != NULL)
        free(pool->rpc_user);
    pool->rpc_user = strdup(str);
    if(pool->rpc_url && pool->rpc_user && pool->rpc_pass)
        add_pool(pools, pool);
}

static void add_pool_pass(struct pool_details *pools, struct pool_details *pool, char *str)
{
    if(pool == NULL)
        pool = new_pool(false);
    if(pool != gpool)
        gpool = pool;
    if(pool->rpc_pass != NULL)
        free(pool->rpc_pass);
    pool->rpc_pass = strdup(str);
    if(pool->rpc_url && pool->rpc_user && pool->rpc_pass)
        add_pool(pools, pool);
}

static bool check_pool_alive(struct pool_details *pool)
{
    bool alive = true;
    struct stratum_ctx *stratum = calloc(1, sizeof(struct stratum_ctx));
    pthread_mutex_init(&stratum->sock_lock, NULL);
    pthread_mutex_init(&stratum->work_lock, NULL);
    stratum->url = pool->rpc_url;
    if (!stratum_connect(stratum, stratum->url) ||
        !stratum_subscribe(stratum) ||
        !stratum_authorize(stratum, pool->rpc_user, pool->rpc_pass))
    {
        alive = false;
    }
    stratum_disconnect(stratum);
    free(stratum);
    return alive;
}

static void add_pool(struct pool_details *pools, struct pool_details *pool)
{
    pool->rpc_userpass = malloc(strlen(pool->rpc_user) + strlen(pool->rpc_pass) + 2);
    sprintf(pool->rpc_userpass, "%s:%s", pool->rpc_user, pool->rpc_pass);
    pool->usable = true;
    if(!list_empty(&pools->list))
    {
        pool->prio = ++(list_entry(&pools->list.prev, struct pool_details, list))->prio;
    }
    else
    {
        pool->active = true;
        pool->tried = true;
    }
    list_add_tail(&pool->list, &pools->list);
    gpool = NULL;
}

static struct pool_stats* new_pool_stats(struct pool_details *pool)
{
    struct pool_stats *pool_stats;
    pool_stats = calloc(1, sizeof(struct pool_stats));
    pool->id++;
    pool_stats->id = pool->id;
    list_add(&pool_stats->list, &pool->stats.list);
    return pool_stats;
}

static struct pool_stats* get_pool_stats(struct pool_details *pool)
{
    struct pool_stats *pool_stats, *ret = NULL;
    list_for_each_entry(pool_stats, &pool->stats.list, list)
    {
        if(pool->id == pool_stats->id)
        {
            ret = pool_stats;
            break;
        }
    }
    return ret;
}

static int get_pool_count(struct pool_details *pools)
{
    struct pool_details *pool;
    int count = 0;
    pool = list_entry(&pools->list.prev, struct pool_details, list);
    if(pool != NULL)
    {
        count = pool->prio + 1;
    }
    return count;
}

static void set_active_pool(struct pool_details *pools, struct pool_details *active_pool, bool active)
{
    struct pool_details *pool;
    list_for_each_entry(pool, &pools->list, list)
    {
        pool->active = false;
    }
    active_pool->active = active;
    active_pool->tried = true;
}

static struct pool_details* get_pool(struct pool_details *pools, int prio)
{
    struct pool_details *pool, *ret = NULL;
    list_for_each_entry(pool, &pools->list, list)
    {
        if(pool->prio == prio)
        {
            ret = pool;
            break;
        }
    }
    return ret;
}

static struct pool_details* get_active_pool(struct pool_details *pools)
{
    struct pool_details *pool, *ret = NULL;
    list_for_each_entry(pool, &pools->list, list)
    {
        if(pool->usable && pool->active)
        {
            ret = pool;
            break;
        }
    }
    return ret;
}

static struct pool_details* get_main_pool(struct pool_details *pools)
{
    struct pool_details *pool, *ret = NULL;
    pool = get_pool(pools, 0);
    if(pool != NULL && pool->usable)
        ret = pool;
    return ret;
}

static void clear_pool_tried(struct pool_details *pools)
{
    struct pool_details *pool;
    int tried = 0;
    list_for_each_entry(pool, &pools->list, list)
    {
        if(pool->tried)
            tried++;
    }
    if(tried == (list_entry(&pools->list.prev, struct pool_details, list))->prio + 1)
    {
        list_for_each_entry(pool, &pools->list, list)
        {
            pool->tried = false;
        }
    }
}

static struct pool_details* get_next_pool(struct pool_details *pools)
{
    struct pool_details *pool, *ret = NULL;
    clear_pool_tried(pools);
    list_for_each_entry(pool, &pools->list, list)
    {
        if(pool->usable && !pool->tried)
        {
            ret = pool;
            break;
        }
    }
    return ret;
}
// End Pool section

static bool rpc2_login(CURL *curl);
static void workio_cmd_free(struct workio_cmd *wc);

json_t *json_rpc2_call_recur(CURL *curl, const char *url,
              const char *userpass, json_t *rpc_req,
              int *curl_err, int flags, int recur) {
    if(recur >= 5) {
        if(opt_debug)
            applog(LOG_DEBUG, "Failed to call rpc command after %i tries", recur);
        return NULL;
    }
    if(!strcmp(rpc2_id, "")) {
        if(opt_debug)
            applog(LOG_DEBUG, "Tried to call rpc2 command before authentication");
        return NULL;
    }
    json_t *params = json_object_get(rpc_req, "params");
    if (params) {
        json_t *auth_id = json_object_get(params, "id");
        if (auth_id) {
            json_string_set(auth_id, rpc2_id);
        }
    }
    json_t *res = json_rpc_call(curl, url, userpass, json_dumps(rpc_req, 0),
            curl_err, flags | JSON_RPC_IGNOREERR);
    if(!res) goto end;
    json_t *error = json_object_get(res, "error");
    if(!error) goto end;
    json_t *message;
    if(json_is_string(error))
        message = error;
    else
        message = json_object_get(error, "message");
    if(!message || !json_is_string(message)) goto end;
    const char *mes = json_string_value(message);
    if(!strcmp(mes, "Unauthenticated")) {
        pthread_mutex_lock(&rpc2_login_lock);
        rpc2_login(curl);
        sleep(1);
        pthread_mutex_unlock(&rpc2_login_lock);
        return json_rpc2_call_recur(curl, url, userpass, rpc_req,
            curl_err, flags, recur + 1);
    } else if(!strcmp(mes, "Low difficulty share") || !strcmp(mes, "Block expired") || !strcmp(mes, "Invalid job id") || !strcmp(mes, "Duplicate share")) {
        json_t *result = json_object_get(res, "result");
        if(!result) {
            goto end;
        }
        json_object_set(result, "reject-reason", json_string(mes));
    } else {
        applog(LOG_ERR, "json_rpc2.0 error: %s", mes);
        return NULL;
    }
    end:
    return res;
}

json_t *json_rpc2_call(CURL *curl, const char *url,
              const char *userpass, const char *rpc_req,
              int *curl_err, int flags) {
    return json_rpc2_call_recur(curl, url, userpass, JSON_LOADS(rpc_req, NULL),
        curl_err, flags, 0);
}

static inline void work_free(struct work *w) {
    free(w.job_id);
    free(w.xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src) {
    memcpy(dest, src, sizeof(struct work));
    if (src.job_id)
        dest.job_id = strdup(src.job_id);
    if (src.xnonce2) {
        dest.xnonce2 = malloc(src.xnonce2_len);
        memcpy(dest.xnonce2, src.xnonce2, src.xnonce2_len);
    }
}

static bool jobj_binary(const json_t *obj, const char *key, void *buf,
        size_t buflen) {
    const char *hexstr;
    json_t *tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp)) {
        applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr)) {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin(buf, hexstr, buflen))
        return false;

    return true;
}

bool rpc2_job_decode(const json_t *job, struct work *work) {
    if (!jsonrpc_2) {
        applog(LOG_ERR, "Tried to decode job without JSON-RPC 2.0");
        return false;
    }
    json_t *tmp;
    tmp = json_object_get(job, "job_id");
    if (!tmp) {
        applog(LOG_ERR, "JSON inval job id");
        goto err_out;
    }
    const char *job_id = json_string_value(tmp);
    tmp = json_object_get(job, "blob");
    if (!tmp) {
        applog(LOG_ERR, "JSON inval blob");
        goto err_out;
    }
    const char *hexblob = json_string_value(tmp);
    int blobLen = strlen(hexblob);
    if (blobLen % 2 != 0 || ((blobLen / 2) < 40 && blobLen != 0) || (blobLen / 2) > 128) {
        applog(LOG_ERR, "JSON invalid blob length");
        goto err_out;
    }
    if (blobLen != 0) {
        pthread_mutex_lock(&rpc2_job_lock);
        char *blob = malloc(blobLen / 2);
        if (!hex2bin(blob, hexblob, blobLen / 2)) {
            applog(LOG_ERR, "JSON inval blob");
            pthread_mutex_unlock(&rpc2_job_lock);
            goto err_out;
        }
        if (rpc2_blob) {
            free(rpc2_blob);
        }
        rpc2_bloblen = blobLen / 2;
        rpc2_blob = malloc(rpc2_bloblen);
        memcpy(rpc2_blob, blob, blobLen / 2);

        free(blob);

        uint32_t target;
        jobj_binary(job, "target", &target, 4);
        if(rpc2_target != target) {
            float hashrate = 0.;
            pthread_mutex_lock(&stats_lock);
            for (size_t i = 0; i < opt_n_threads; i++)
                hashrate += thr_hashrates[i] / thr_times[i];
            pthread_mutex_unlock(&stats_lock);
            double difficulty = (((double) 0xffffffff) / target);
            applog(LOG_INFO, "Pool set diff to %g", difficulty);
            rpc2_target = target;
        }

        if (rpc2_job_id) {
            free(rpc2_job_id);
        }
        rpc2_job_id = strdup(job_id);
        pthread_mutex_unlock(&rpc2_job_lock);
    }
    if(work) {
        if (!rpc2_blob) {
            applog(LOG_ERR, "Requested work before work was received");
            goto err_out;
        }
        memcpy(work->data, rpc2_blob, rpc2_bloblen);
        memset(work->target, 0xff, sizeof(work->target));
        work->target[7] = rpc2_target;
        if (work.job_id)
            free(work.job_id);
        work.job_id = strdup(rpc2_job_id);
    }
    return true;

    err_out:
    return false;
}

static bool work_decode(const json_t *val, struct work *work) {
    int i;

    if(jsonrpc_2) {
        return rpc2_job_decode(val, work);
    }

    if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
        applog(LOG_ERR, "JSON inval data");
        goto err_out;
    }
    if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
        applog(LOG_ERR, "JSON inval target");
        goto err_out;
    }

    for (i = 0; i < ARRAY_SIZE(work->data); i++)
        work->data[i] = le32dec(work->data + i);
    for (i = 0; i < ARRAY_SIZE(work->target); i++)
        work->target[i] = le32dec(work->target + i);

    return true;

    err_out: return false;
}

bool rpc2_login_decode(const json_t *val) {
    const char *id;
    const char *s;

    json_t *res = json_object_get(val, "result");
    if(!res) {
        applog(LOG_ERR, "JSON invalid result");
        goto err_out;
    }

    json_t *tmp;
    tmp = json_object_get(res, "id");
    if(!tmp) {
        applog(LOG_ERR, "JSON inval id");
        goto err_out;
    }
    id = json_string_value(tmp);
    if(!id) {
        applog(LOG_ERR, "JSON id is not a string");
        goto err_out;
    }

    memcpy(&rpc2_id, id, 64);

    if(opt_debug)
        applog(LOG_DEBUG, "Auth id: %s", id);

    tmp = json_object_get(res, "status");
    if(!tmp) {
        applog(LOG_ERR, "JSON inval status");
        goto err_out;
    }
    s = json_string_value(tmp);
    if(!s) {
        applog(LOG_ERR, "JSON status is not a string");
        goto err_out;
    }
    if(strcmp(s, "OK")) {
        applog(LOG_ERR, "JSON returned status \"%s\"", s);
        return false;
    }

    return true;

    err_out: return false;
}

static void share_result(int result, struct work *work, const char *reason) {
    char s[345];
    double hashrate;
    int i;

    hashrate = 0.;
    pthread_mutex_lock(&stats_lock);
    for (i = 0; i < opt_n_threads; i++)
        hashrate += thr_hashrates[i] / thr_times[i];
    result ? accepted_count++ : rejected_count++;
    pthread_mutex_unlock(&stats_lock);

    switch (opt_algo) {
    case ALGO_CRYPTONIGHT:
        applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %.2f H/s at diff %g %s",
                accepted_count, accepted_count + rejected_count,
                100. * accepted_count / (accepted_count + rejected_count), hashrate,
                (((double) 0xffffffff) / (work ? work->target[7] : rpc2_target)),
                result ? "(yay!!!)" : "(booooo)");
        break;
    default:
        sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
        applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
                accepted_count, accepted_count + rejected_count,
                100. * accepted_count / (accepted_count + rejected_count), s,
                result ? "(yay!!!)" : "(booooo)");
        break;
    }

    if (opt_debug && reason)
        applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

static bool submit_upstream_work(CURL *curl, struct work *work) {
    char *str = NULL;
    json_t *val, *res, *reason;
    char s[JSON_BUF_LEN];
    int i;
    bool rc = false;

    struct pool_details *pool;
    pthread_mutex_lock(&pool_lock);
    pool = get_active_pool(pools);
    pthread_mutex_unlock(&pool_lock);

    /* pass if the previous hash is not the current previous hash */
    if (!submit_old && memcmp(work->data + 1, g_work->data + 1, 32)) {
        if (opt_debug)
            applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
        return true;
    }

    if (have_stratum) {
        uint32_t ntime, nonce;
        char *ntimestr, *noncestr, *xnonce2str;

        if (jsonrpc_2) {
            noncestr = bin2hex(((const unsigned char*)work->data) + 39, 4);
            char hash[32];
            switch(opt_algo) {
            case ALGO_CRYPTONIGHT:
            default:
                cryptonight_hash(hash, work->data, 76);
            }
            char *hashhex = bin2hex(hash, 32);
            snprintf(s, JSON_BUF_LEN,
                    "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}\r\n",
                    pool->rpc_user, work.job_id, noncestr, hashhex);
            free(hashhex);
        } else {
            le32enc(&ntime, work->data[17]);
            le32enc(&nonce, work->data[19]);
            ntimestr = bin2hex((const unsigned char *) (&ntime), 4);
            noncestr = bin2hex((const unsigned char *) (&nonce), 4);
            xnonce2str = bin2hex(work.xnonce2, work.xnonce2_len);
            snprintf(s, JSON_BUF_LEN,
                    "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
                    pool->rpc_user, work.job_id, xnonce2str, ntimestr, noncestr);
            free(ntimestr);
            free(xnonce2str);
        }
        free(noncestr);

        if (unlikely(!stratum_send_line(stratum, s))) {
            applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
            goto out;
        }
    } else {
        /* build JSON-RPC request */
        if(jsonrpc_2) {
            char *noncestr = bin2hex(((const unsigned char*)work->data) + 39, 4);
            char hash[32];
            switch(opt_algo) {
            case ALGO_CRYPTONIGHT:
            default:
                cryptonight_hash(hash, work->data, 76);
            }
            char *hashhex = bin2hex(hash, 32);
            snprintf(s, JSON_BUF_LEN,
                    "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}\r\n",
                    pool->rpc_user, work.job_id, noncestr, hashhex);
            free(noncestr);
            free(hashhex);

            /* issue JSON-RPC request */
            val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
            if (unlikely(!val)) {
                applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
                goto out;
            }
            res = json_object_get(val, "result");
            json_t *status = json_object_get(res, "status");
            reason = json_object_get(res, "reject-reason");
            share_result(!strcmp(status ? json_string_value(status) : "", "OK"), work,
                    reason ? json_string_value(reason) : NULL );
        } else {
            /* build hex string */
            for (i = 0; i < 76; i++)
                le32enc(((char*)work->data) + i, *((uint32_t*) (((char*)work->data) + i)));
            str = bin2hex((unsigned char *) work->data, 76);
            if (unlikely(!str)) {
                applog(LOG_ERR, "submit_upstream_work OOM");
                goto out;
            }
            snprintf(s, JSON_BUF_LEN,
                    "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
                    str);

            /* issue JSON-RPC request */
            val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
            if (unlikely(!val)) {
                applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
                goto out;
            }
            res = json_object_get(val, "result");
            reason = json_object_get(val, "reject-reason");
            share_result(json_is_true(res), work,
                    reason ? json_string_value(reason) : NULL );
        }

        json_decref(val);
    }

    rc = true;

    out: free(str);
    return rc;
}

static const char *rpc_req =
        "{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work) {
    json_t *val;
    bool rc;
    struct timeval tv_start, tv_end, diff;
    struct pool_details *pool;
    
    pthread_mutex_lock(&pool_lock);
    pool = get_active_pool(pools);
    pthread_mutex_unlock(&pool_lock);

    gettimeofday(&tv_start, NULL );

    if(jsonrpc_2) {
        char s[128];
        snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
        val = json_rpc2_call(curl, pool->rpc_url, pool->rpc_userpass, s, NULL, 0);
    } else {
        val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass, rpc_req, NULL, 0);
    }
    gettimeofday(&tv_end, NULL );

    if (have_stratum) {
        if (val)
            json_decref(val);
        return true;
    }

    if (!val)
        return false;

    rc = work_decode(json_object_get(val, "result"), work);

    if (opt_debug && rc) {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "DEBUG: got new work in %d ms",
                diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }

    json_decref(val);

    return rc;
}

static bool rpc2_login(CURL *curl) {
    struct pool_details *pool;
    
    pthread_mutex_lock(&pool_lock);
    pool = get_active_pool(pools);
    pthread_mutex_unlock(&pool_lock);

    if(!jsonrpc_2) {
        return false;
    }
    json_t *val;
    bool rc;
    struct timeval tv_start, tv_end, diff;
    char s[JSON_BUF_LEN];

    snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}", rpc_user, rpc_pass);

    gettimeofday(&tv_start, NULL );
    val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass, s, NULL, 0);
    gettimeofday(&tv_end, NULL );

    if (!val)
        goto end;

//    applog(LOG_DEBUG, "JSON value: %s", json_dumps(val, 0));

    rc = rpc2_login_decode(val);

    json_t *result = json_object_get(val, "result");

    if(!result) goto end;

    json_t *job = json_object_get(result, "job");

    if(!rpc2_job_decode(job, &g_work)) {
        goto end;
    }

    if (opt_debug && rc) {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
                diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }

    json_decref(val);

    end:
    return rc;
}

static void workio_cmd_free(struct workio_cmd *wc) {
    if (!wc)
        return;

    switch (wc->cmd) {
    case WC_SUBMIT_WORK:
        work_free(wc->u.work);
        free(wc->u.work);
        break;
    default: /* do nothing */
        break;
    }

    memset(wc, 0, sizeof(*wc)); /* poison */
    free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl) {
    struct work *ret_work;
    int failures = 0;

    ret_work = calloc(1, sizeof(*ret_work));
    if (!ret_work)
        return false;

    /* obtain new work from bitcoin via JSON-RPC */
    while (!get_upstream_work(curl, ret_work)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
            free(ret_work);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "getwork failed, retry after %d seconds",
                opt_fail_pause);
        sleep(opt_fail_pause);
    }

    /* send work to requesting thread */
    if (!tq_push(wc->thr->q, ret_work))
        free(ret_work);

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    while (!submit_upstream_work(curl, wc->u.work)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }

    return true;
}

static bool workio_login(CURL *curl) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    pthread_mutex_lock(&rpc2_login_lock);
    while (!rpc2_login(curl)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            pthread_mutex_unlock(&rpc2_login_lock);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
        pthread_mutex_unlock(&rpc2_login_lock);
        pthread_mutex_lock(&rpc2_login_lock);
    }
    pthread_mutex_unlock(&rpc2_login_lock);

    return true;
}

static void *workio_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    CURL *curl;
    bool ok = true;

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        return NULL ;
    }

    if(!have_stratum) {
        ok = workio_login(curl);
    }

    while (ok) {
        struct workio_cmd *wc;

        /* wait for workio_cmd sent to us, on our queue */
        wc = tq_pop(mythr->q, NULL );
        if (!wc) {
            ok = false;
            break;
        }

        /* process workio_cmd */
        switch (wc->cmd) {
        case WC_GET_WORK:
            ok = workio_get_work(wc, curl);
            break;
        case WC_SUBMIT_WORK:
            ok = workio_submit_work(wc, curl);
            break;

        default: /* should never happen */
            ok = false;
            break;
        }

        workio_cmd_free(wc);
    }

    tq_freeze(mythr->q);
    curl_easy_cleanup(curl);

    return NULL ;
}

static bool get_work(struct thr_info *thr, struct work *work) {
    struct workio_cmd *wc;
    struct work *work_heap;

    if (opt_benchmark) {
        memset(work->data, 0x55, 76);
        work->data[17] = swab32(time(NULL ));
        memset(work->data + 19, 0x00, 52);
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;
        memset(work->target, 0x00, sizeof(work->target));
        return true;
    }

    /* fill out work request message */
    wc = calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->cmd = WC_GET_WORK;
    wc->thr = thr;

    /* send work request to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc)) {
        workio_cmd_free(wc);
        return false;
    }

    /* wait for response, a unit of work */
    work_heap = tq_pop(thr->q, NULL );
    if (!work_heap)
        return false;

    /* copy returned work into storage provided by caller */
    memcpy(work, work_heap, sizeof(*work));
    free(work_heap);

    return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in) {
    struct workio_cmd *wc;

    /* fill out work request message */
    wc = calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->u.work = malloc(sizeof(*work_in));
    if (!wc->u.work)
        goto err_out;

    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    work_copy(wc->u.work, work_in);

    /* send solution to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc))
        goto err_out;

    return true;

    err_out: workio_cmd_free(wc);
    return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work) {
    unsigned char merkle_root[64];
    int i;

    pthread_mutex_lock(&sctx->work_lock);

    //if (jsonrpc_2) {
        free(work->job_id);
        memcpy(work, &sctx->work, sizeof(struct work));
        work->job_id = strdup(sctx->work.job_id);
        pthread_mutex_unlock(&sctx->work_lock);
    /*} else {
        free(work->job_id);
        work->job_id = strdup(sctx->job.job_id);
        work->xnonce2_len = sctx->xnonce2_size;
        work->xnonce2 = realloc(work->xnonce2, sctx->xnonce2_size);
        memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

        // Generate merkle root
        sha256d(merkle_root, sctx->job.coinbase, sctx->job.coinbase_size);
        for (i = 0; i < sctx->job.merkle_count; i++) {
            memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
            sha256d(merkle_root, merkle_root, 64);
        }

        // Increment extranonce2
        for (i = 0; i < sctx->xnonce2_size && !++sctx->job.xnonce2[i]; i++)
            ;

        // Assemble block header
        memset(work->data, 0, 128);
        work->data[0] = le32dec(sctx->job.version);
        for (i = 0; i < 8; i++)
            work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
        for (i = 0; i < 8; i++)
            work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);
        work->data[17] = le32dec(sctx->job.ntime);
        work->data[18] = le32dec(sctx->job.nbits);
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;

        pthread_mutex_unlock(&sctx->work_lock);

        if (opt_debug) {
            char *xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);
            applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
                    work->job_id, xnonce2str, swab32(work->data[17]));
            free(xnonce2str);
        }

        if (opt_algo == ALGO_SCRYPT)
            diff_to_target(work->target, sctx->job.diff / 65536.0);
        else
            diff_to_target(work->target, sctx->job.diff);
    }*/
}

struct cryptonight_ctx *persistentctxs[MAX_THREADS] = { NULL };

static void *miner_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    int thr_id = mythr->id;
    struct work work = { { 0 } };
    uint32_t max_nonce;
    uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
    unsigned char *scratchbuf = NULL;
    char s[16];
    int i;
	struct cryptonight_ctx *persistentctx;
	
    /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
     * and if that fails, then SCHED_BATCH. No need for this to be an
     * error if it fails */
     #ifdef __linux
    if (!opt_benchmark) {
        //setpriority(PRIO_PROCESS, 0, 19);
        if(!geteuid()) setpriority(PRIO_PROCESS, 0, -14);
        drop_policy();
    }
	#endif
	
    /* Cpu affinity only makes sense if the number of threads is a multiple
     * of the number of CPUs */
    /*if (num_processors > 1 && opt_n_threads % num_processors == 0) {
        if (!opt_quiet)
            applog(LOG_INFO, "Binding thread %d to cpu %d", thr_id,
                    thr_id % num_processors);
        affine_to_cpu(thr_id, thr_id % num_processors);
    }*/
    
	persistentctx = persistentctxs[thr_id];
	if(!persistentctx && opt_algo == ALGO_CRYPTONIGHT)
	{
		#if defined __unix__ && (!defined __APPLE__)
		persistentctx = (struct cryptonight_ctx *)mmap(0, sizeof(struct cryptonight_ctx), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, 0, 0);
		if(persistentctx == MAP_FAILED) persistentctx = (struct cryptonight_ctx *)malloc(sizeof(struct cryptonight_ctx));
		madvise(persistentctx, sizeof(struct cryptonight_ctx), MADV_RANDOM | MADV_WILLNEED | MADV_HUGEPAGE);
		if(!geteuid()) mlock(persistentctx, sizeof(struct cryptonight_ctx));
		#elif defined _WIN32
		persistentctx = VirtualAlloc(NULL, sizeof(struct cryptonight_ctx), MEM_LARGE_PAGES, PAGE_READWRITE);
		if(!persistentctx) persistentctx = (struct cryptonight_ctx *)malloc(sizeof(struct cryptonight_ctx));
		#else
		persistentctx = (struct cryptonight_ctx *)malloc(sizeof(struct cryptonight_ctx));
		#endif
	}
	
    uint32_t *nonceptr = (uint32_t*) (((char*)work->data) + (jsonrpc_2 ? 39 : 76));

    while (1) {
        unsigned long hashes_done;
        struct timeval tv_start, tv_end, diff;
        int64_t max64;
        int rc;

        if (have_stratum) {
            while (!jsonrpc_2 && time(NULL) >= g_work_time + 120)
                sleep(1);
            pthread_mutex_lock(&g_work_lock);
            if ((*nonceptr) >= end_nonce
           	    && !(jsonrpc_2 ? memcmp(work->data, g_work->data, 39) ||
           	            memcmp(((uint8_t*) work->data) + 43, ((uint8_t*) g_work->data) + 43, 33)
           	      : memcmp(work->data, g_work->data, 76)))
                stratum_gen_work(stratum, &g_work);
        } else {
            /* obtain new work from internal workio thread */
            pthread_mutex_lock(&g_work_lock);
            if ((!have_stratum
                    && (!have_longpoll
                            || time(NULL ) >= g_work_time + LP_SCANTIME * 3 / 4
                            || *nonceptr >= end_nonce))) {
                if (unlikely(!get_work(mythr, &g_work))) {
                    applog(LOG_ERR, "work retrieval failed, exiting "
                            "mining thread %d", mythr->id);
                    pthread_mutex_unlock(&g_work_lock);
                    goto out;
                }
                g_work_time = have_stratum ? 0 : time(NULL );
            }
            if (have_stratum) {
                pthread_mutex_unlock(&g_work_lock);
                continue;
            }
        }
        if (jsonrpc_2 ? memcmp(work->data, g_work->data, 39) || memcmp(((uint8_t*) work->data) + 43, ((uint8_t*) g_work->data) + 43, 33) : memcmp(work->data, g_work->data, 76)) {
            work_free(&work);
            work_copy(&work, &g_work);
            nonceptr = (uint32_t*) (((char*)work->data) + (jsonrpc_2 ? 39 : 76));
            *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
        } else
            ++(*nonceptr);
        pthread_mutex_unlock(&g_work_lock);
        work_restart[thr_id].restart = 0;

        /* adjust max_nonce to meet target scan time */
        if (have_stratum)
            max64 = LP_SCANTIME;
        else
            max64 = g_work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
                    - time(NULL );
        //max64 *= thr_hashrates[thr_id];
        if (max64 <= 0) {
            switch (opt_algo) {
            case ALGO_SCRYPT:
                max64 = 0xfffLL;
                break;
            case ALGO_CRYPTONIGHT:
                max64 = 0x40LL;
                break;
            default:
                max64 = 0x1fffffLL;
                break;
            }
        }
        if (*nonceptr + max64 > end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = *nonceptr + max64;

        hashes_done = 0;
        gettimeofday(&tv_start, NULL );

        /* scan nonces for a proof-of-work hash */
            rc = scanhash_cryptonight(thr_id, work->data, work->target,
                    max_nonce, &hashes_done, persistentctx);

        /* record scanhash elapsed time */
        gettimeofday(&tv_end, NULL );
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] = hashes_done;
            thr_times[thr_id] = (diff.tv_sec + 1e-6 * diff.tv_usec);
            pthread_mutex_unlock(&stats_lock);
        }
        /*if (!opt_quiet) {
            switch(opt_algo) {
            case ALGO_CRYPTONIGHT:
                applog(LOG_INFO, "thread %d: %lu hashes, %.2f H/s", thr_id,
                        hashes_done, thr_hashrates[thr_id]);
                break;
            default:
                sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
                        1e-3 * thr_hashrates[thr_id]);
                applog(LOG_INFO, "thread %d: %lu hashes, %.2f khash/s", thr_id,
                        hashes_done, s);
                break;
            }
        }
        if (opt_benchmark && thr_id == opt_n_threads - 1) {
            double hashrate = 0.;
            for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
                hashrate += thr_hashrates[i];
            if (i == opt_n_threads) {
                switch(opt_algo) {
                case ALGO_CRYPTONIGHT:
                    applog(LOG_INFO, "Total: %s H/s", hashrate);
                    break;
                default:
                    sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
                    applog(LOG_INFO, "Total: %s khash/s", s);
                    break;
                }
            }
        }*/

        /* if nonce found, submit work */
        if (rc && !opt_benchmark && !submit_work(mythr, &work))
            break;
    }

    out: tq_freeze(mythr->q);
	
    return NULL ;
}

static void restart_threads(void) {
    int i;

    for (i = 0; i < opt_n_threads; i++)
        work_restart[i].restart = 1;
}

static void *longpoll_thread(void *userdata) {
    struct thr_info *mythr = userdata;
    CURL *curl = NULL;
    char *copy_start, *hdr_path = NULL, *lp_url = NULL;
    bool need_slash = false;

    struct pool_details *pool;
    
    pthread_mutex_lock(&pool_lock);
    pool = get_active_pool(pools);
    pthread_mutex_unlock(&pool_lock);

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        goto out;
    }

    start: hdr_path = tq_pop(mythr->q, NULL );
    if (!hdr_path)
        goto out;

    /* full URL */
    if (strstr(hdr_path, "://")) {
        lp_url = hdr_path;
        hdr_path = NULL;
    }

    /* absolute path, on current server */
    else {
        copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
        if (pool->rpc_url[strlen(pool->rpc_url) - 1] != '/')
            need_slash = true;

        lp_url = malloc(strlen(pool->rpc_url) + strlen(copy_start) + 2);
        if (!lp_url)
            goto out;

        sprintf(lp_url, "%s%s%s", pool->rpc_url, need_slash ? "/" : "", copy_start);
    }

    applog(LOG_INFO, "Long-polling activated for %s", lp_url);

    while (1) {
        json_t *val, *soval;
        int err;

        if(jsonrpc_2) {
            pthread_mutex_lock(&rpc2_login_lock);
            if(!strcmp(rpc2_id, "")) {
                sleep(1);
                continue;
            }
            char s[128];
            snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
            pthread_mutex_unlock(&rpc2_login_lock);
            val = json_rpc2_call(curl, pool->rpc_url, pool->rpc_userpass, s, &err, JSON_RPC_LONGPOLL);
        } else {
            val = json_rpc_call(curl, pool->rpc_url, pool->rpc_userpass, rpc_req, &err, JSON_RPC_LONGPOLL);
        }
        if (have_stratum) {
            if (val)
                json_decref(val);
            goto out;
        }
        if (likely(val)) {
            if (!jsonrpc_2) {
                soval = json_object_get(json_object_get(val, "result"),
                        "submitold");
                submit_old = soval ? json_is_true(soval) : false;
            }
            pthread_mutex_lock(&g_work_lock);
            char *start_job_id = strdup(g_work.job_id);
            if (work_decode(json_object_get(val, "result"), &g_work)) {
                if (strcmp(start_job_id, g_work.job_id)) {
                    applog(LOG_INFO, "LONGPOLL detected new block");
                    if (opt_debug)
                        applog(LOG_DEBUG, "DEBUG: got new work");
                    time(&g_work_time);
                    restart_threads();
                }
            }
            free(start_job_id);
            pthread_mutex_unlock(&g_work_lock);
            json_decref(val);
        } else {
            pthread_mutex_lock(&g_work_lock);
            g_work_time -= LP_SCANTIME;
            pthread_mutex_unlock(&g_work_lock);
            if (err == CURLE_OPERATION_TIMEDOUT) {
                restart_threads();
            } else {
                have_longpoll = false;
                restart_threads();
                free(hdr_path);
                free(lp_url);
                lp_url = NULL;
                sleep(opt_fail_pause);
                goto start;
            }
        }
    }

    out: free(hdr_path);
    free(lp_url);
    tq_freeze(mythr->q);
    if (curl)
        curl_easy_cleanup(curl);

    return NULL ;
}

static void clean_stratum(struct stratum_ctx *sctx)
{
    if(sctx->curl)
        stratum_disconnect(sctx);
    memset(sctx, 0, sizeof(struct stratum_ctx));
    pthread_mutex_init(&sctx->sock_lock, NULL);
    pthread_mutex_init(&sctx->work_lock, NULL);
}

static bool stratum_handle_response(char *buf) {
    json_t *val, *err_val, *res_val, *id_val;
    json_error_t err;
    bool ret = false;
    bool valid = false;

    val = JSON_LOADS(buf, &err);
    if (!val) {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (!id_val || json_is_null(id_val) || !res_val)
        goto out;

    if(jsonrpc_2) {
        json_t *status = json_object_get(res_val, "status");
        if(status) {
            const char *s = json_string_value(status);
            valid = !strcmp(s, "OK") && json_is_null(err_val);
        } else {
            valid = json_is_null(err_val);
        }
    } else {
        valid = json_is_true(res_val);
    }

    share_result(valid, NULL,
            err_val ? (jsonrpc_2 ? json_string_value(err_val) : json_string_value(json_array_get(err_val, 1))) : NULL );

    ret = true;
    out: if (val)
        json_decref(val);

    return ret;
}

static void *stratum_thread(void *userdata){
    char *s;
    int i, failures, restarted;
    struct timeval timestr;
    struct pool_details *pool, *main_pool;
    struct pool_stats *pool_stats;
    bool switch_lock = false, switched = false, reconnect = false;
    uint32_t work_id;

    gettimeofday(&timestr, NULL);
    work_id = (timestr.tv_sec & 0xffff) << 16 | (timestr.tv_usec & 0xffff);
    g_work_time = 0;
    g_work_update_time = 0;
    
    while (1) {
login:
        switch_lock = true;
        pthread_mutex_lock(&switch_pool_lock);
        failures = 0;
        if(must_switch || switched)
        {
            must_switch = false;
            switched = false;
            pthread_mutex_lock(&g_work_lock);
            restart_threads();
            can_work = false;
            clean_stratum(stratum);
            g_work_time = 0;
            g_work_update_time = 0;
            pthread_mutex_unlock(&g_work_lock);
        }
        while (!stratum->curl)
        {
            pthread_mutex_lock(&pool_lock);
            pool = get_active_pool(pools);
            pthread_mutex_unlock(&pool_lock);
            if(pool == NULL)
            {
                applog(LOG_ERR, "Stratum pool info incomplete");
                goto out;
            }
            stratum->url = pool->rpc_url;
            if(!reconnect)
                applog(LOG_INFO, "Starting Stratum on %s", stratum->url);
            reconnect = false;
            if (!stratum_connect(stratum, stratum->url) ||
                !stratum_subscribe(stratum) ||
                !stratum_authorize(stratum, pool->rpc_user, pool->rpc_pass)) {
                stratum_disconnect(stratum);
                reconnect = true;
                if (opt_retries >= 0 && ++failures > opt_retries)
                {
                    failures = 0;
                    pthread_mutex_lock(&pool_lock);
                    pool = get_next_pool(pools);
                    set_active_pool(pools, pool, true);
                    main_pool = get_main_pool(pools);
                    pthread_mutex_unlock(&pool_lock);
                    if(pool != main_pool)
                    {
                        pthread_cond_signal(&check_pool_cond);
                    }
                    if(switch_lock)
                    {
                        switch_lock = false;
                        pthread_mutex_unlock(&switch_pool_lock);
                    }
                    applog(LOG_INFO, "Switching to pool: %s", pool->rpc_url);
                    switched = true;
                    goto login;
                }
                applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }
            memset(g_work.xnonce2, 0, 8);
            if(g_work_update_time)
                g_work_update_time = 0;
            gettimeofday(&timestr, NULL);
            pthread_mutex_lock(&pool_lock);
            pool_stats = get_pool_stats(pool);
            if(pool_stats != NULL)
            {
                pool_stats->time_stop = timestr.tv_sec;
                if(pool_stats->shares)
                    pool_stats = new_pool_stats(pool);
            }
            else
                pool_stats = new_pool_stats(pool);
            pool_stats->time_start = timestr.tv_sec;
            pthread_mutex_unlock(&pool_lock);
        }
        can_work = true;
        restarted = 0;
        if (jsonrpc_2) {
            if (stratum->job.job_id &&
                (strcmp(stratum->job.job_id, g_work.job_id) || !g_work_time || !g_work_update_time)) {
                pthread_mutex_lock(&g_work_lock);
                pthread_mutex_lock(&stratum->work_lock);
                if (stratum->job.clean || time(NULL) >= g_work_update_time + 60)
                {
                    
                    applog(LOG_INFO, "Stratum detected new block");
                    restart_threads();
                    gettimeofday(&timestr, NULL);
                    work_id = (timestr.tv_sec & 0xffff) << 16 | (timestr.tv_usec & 0xffff);
                    restarted = 1;
                    time(&g_work_update_time);
                }
                applog(LOG_INFO, "New Job_id: %s Diff: %d Work_id: %08x", stratum->job.job_id, (int) (stratum->job.diff), work_id);
                strcpy(g_work.job_id, stratum->job.job_id);
                diff_to_target(g_work->target, stratum->job.diff / 65536.0);
                g_work.work_id = work_id;
                time(&g_work_time);
                pthread_mutex_unlock(&stratum->work_lock);
                pthread_mutex_unlock(&g_work_lock);
            }
        } else {
            if (stratum->job.job_id &&
                (strcmp(stratum->job.job_id, g_work.job_id) || !g_work_time || !g_work_update_time)) {
                pthread_mutex_lock(&g_work_lock);
                pthread_mutex_lock(&stratum->work_lock);
                if (stratum->job.clean || time(NULL) >= g_work_update_time + 60)
                {
                    if(stratum->job.clean)
                        applog(LOG_INFO, "Stratum detected new block");
                    restart_threads();
                    gettimeofday(&timestr, NULL);
                    work_id = (timestr.tv_sec & 0xffff) << 16 | (timestr.tv_usec & 0xffff);
                    restarted = 1;
                    time(&g_work_update_time);
                }
                applog(LOG_INFO, "New Job_id: %s Diff: %d Work_id: %08x", stratum->job.job_id, (int) (stratum->job.diff), work_id);
                strcpy(g_work.job_id, stratum->job.job_id);
                diff_to_target(g_work->target, stratum->job.diff / 65536.0);
                g_work.work_id = work_id;
                time(&g_work_time);
                pthread_mutex_unlock(&stratum->work_lock);
                pthread_mutex_unlock(&g_work_lock);
            }
        }
        if (!stratum_socket_full(stratum, 60)) {
            applog(LOG_ERR, "Stratum connection timed out");
            s = NULL;
        } else {
            s = stratum_recv_line(stratum);
        }
        if (!s) 
        {
            stratum_disconnect(stratum);
            applog(LOG_ERR, "Stratum connection interrupted");
            if(switch_lock)
            {
                switch_lock = false;
                pthread_mutex_unlock(&switch_pool_lock);
            }
            continue;
        }
        if (!stratum_handle_method(stratum, s))
            stratum_handle_response(s);
        else if(!restarted)
        {
            if(stratum->job.diff != stratum->next_diff && stratum->next_diff > 0)
            {
                pthread_mutex_lock(&g_work_lock);
                pthread_mutex_lock(&stratum->work_lock);
                restart_threads();
                applog(LOG_INFO, "Stratum difficulty changed");
                gettimeofday(&timestr, NULL);
                work_id = (timestr.tv_sec & 0xffff) << 16 | (timestr.tv_usec & 0xffff);
                stratum->job.diff = stratum->next_diff;
                applog(LOG_INFO, "Diff: %d Work_id: %08x", (int) (stratum->job.diff), work_id);
                diff_to_target(g_work->target, stratum->job.diff / 65536.0);
                g_work.work_id = work_id;
                time(&g_work_update_time);
                time(&g_work_time);
                pthread_mutex_unlock(&stratum->work_lock);
                pthread_mutex_unlock(&g_work_lock);
            }
        }
        free(s);
        if(switch_lock)
        {
            switch_lock = false;
            pthread_mutex_unlock(&switch_pool_lock);
            usleep(1000);
        }
    }

out:
    return NULL;
}

static void *switch_pool_handler(void *id)
{
    pthread_detach(pthread_self());
    struct pool_details *pool;
    int pool_id = *(int*)id;
    free(id);
    pthread_mutex_lock(&switch_pool_lock);
    pthread_mutex_lock(&pool_lock);
    pool = get_pool(pools, pool_id);
    if(pool != NULL)
    {
        applog(LOG_DEBUG, "API: Switching to pool %d", pool_id);
        clear_pool_tried(pools);
        set_active_pool(pools, pool, true);
        must_switch = true;
    }
    pthread_mutex_unlock(&pool_lock);
    pthread_mutex_unlock(&switch_pool_lock);
    return NULL;
}

static void *check_pool_thread()
{
    static struct pool_details *main_pool;
    static struct pool_details *active_pool;
    while(1)
    {
        pthread_mutex_lock(&pool_lock);
        main_pool = get_main_pool(pools);
        active_pool = get_active_pool(pools);
        pthread_mutex_unlock(&pool_lock);
        if(active_pool != main_pool)
        {
            applog(LOG_INFO, "Checking main pool: %s", main_pool->rpc_url);
            if(check_pool_alive(main_pool))
            {
                pthread_mutex_lock(&switch_pool_lock);
                applog(LOG_INFO, "Main pool is alive, attempting to switch");
                pthread_mutex_lock(&pool_lock);
                clear_pool_tried(pools);
                set_active_pool(pools, main_pool, true);
                pthread_mutex_unlock(&pool_lock);
                must_switch = true;
                pthread_mutex_unlock(&switch_pool_lock);
                goto wait;
            }
        }
        else
        {
wait:
            pthread_mutex_lock(&check_pool_lock);
            pthread_cond_wait(&check_pool_cond, &check_pool_lock);
            pthread_mutex_unlock(&check_pool_lock);
        }
        sleep(60);
    }
    return NULL;
}

static void show_version_and_exit(void) {
    printf(PACKAGE_STRING "\n built on " __DATE__ "\n features:"
#if defined(__i386__)
            " i386"
#endif
#if defined(__x86_64__)
            " x86_64"
#endif
#if defined(__i386__) || defined(__x86_64__)
            " SSE2"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
            " AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
            " AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
            " XOP"
#endif
#if defined(__arm__) && defined(__APCS_32__)
            " ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
            " ARMv5E"
#endif
#if defined(__ARM_NEON__)
            " NEON"
#endif
#endif
            "\n");

    printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
    printf("libjansson %s\n", JANSSON_VERSION);
#endif
    exit(0);
}

static void show_usage_and_exit(int status) {
    if (status)
        fprintf(stderr,
                "Try `" PROGRAM_NAME " --help' for more information.\n");
    else
        printf(usage);
    exit(status);
}

static void parse_arg (int key, char *arg, char *pname)
{
    char *p;
    int v,i;
    struct pool_details *pool;

    switch (key) {
    case 'a':
        for (i = 0; i < ARRAY_SIZE(algo_names); i++) {
            if (algo_names[i] && !strcmp(arg, algo_names[i])) {
                //opt_algo = i;
                break;
            }
        }
        if (i == ARRAY_SIZE(algo_names))
            show_usage_and_exit(1);
        break;
    case 'B':
        opt_background = true;
        break;
    case 'c': {
        json_error_t err;
        if (opt_config)
            json_decref(opt_config);
#if JANSSON_VERSION_HEX >= 0x020000
        opt_config = json_load_file(arg, 0, &err);
#else
        opt_config = json_load_file(arg, &err);
#endif
        if (!json_is_object(opt_config)) {
            applog(LOG_ERR, "JSON decode of %s failed", arg);
            exit(1);
        }
        break;
    }
    case 'q':
        opt_quiet = true;
        break;
    case 'D':
        opt_debug = true;
        break;
    case 'p':
        add_pool_pass(pools, gpool, arg);
        break;
    case 'r':
        v = atoi(arg);
        if (v < -1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_retries = v;
        break;
    case 'R':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_fail_pause = v;
        break;
    case 's':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_scantime = v;
        break;
    case 'T':
        v = atoi(arg);
        if (v < 1 || v > 99999) /* sanity check */
            show_usage_and_exit(1);
        opt_timeout = v;
        break;
    case 't':
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_n_threads = v;
        break;
    case 'u':
        add_pool_user(pools, gpool, arg);
        break;
    case 'o':           /* --url */
        pool = gpool;
        p = strstr(arg, "://");
        if (p) {
            if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
                    strncasecmp(arg, "stratum+tcp://", 14))
                show_usage_and_exit(1);
            add_pool_url(pools, gpool, arg);
        } else {
            if (!strlen(arg) || *arg == '/')
                show_usage_and_exit(1);
            char *rpc_url = malloc(strlen(arg) + 8);
            sprintf(rpc_url, "http://%s", arg);
            add_pool_url(pools, gpool, rpc_url);
            free(rpc_url);
        }
        if(pool == NULL)
            pool = gpool;
        have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
        break;
    case 'O': /* --userpass */
        p = strchr(arg, ':');
        if (!p)
            show_usage_and_exit(1);
        free(rpc_userpass);
        rpc_userpass = strdup(arg);
        free(rpc_user);
        rpc_user = calloc(p - arg + 1, 1);
        strncpy(rpc_user, arg, p - arg);
        free(rpc_pass);
        rpc_pass = strdup(p + 1);
        break;
    case 'x': /* --proxy */
        if (!strncasecmp(arg, "socks4://", 9))
            opt_proxy_type = CURLPROXY_SOCKS4;
        else if (!strncasecmp(arg, "socks5://", 9))
            opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
        else if (!strncasecmp(arg, "socks4a://", 10))
            opt_proxy_type = CURLPROXY_SOCKS4A;
        else if (!strncasecmp(arg, "socks5h://", 10))
            opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
        else
            opt_proxy_type = CURLPROXY_HTTP;
        free(opt_proxy);
        opt_proxy = strdup(arg);
        break;
    case 1001:
        free(opt_cert);
        opt_cert = strdup(arg);
        break;
    case 1005:
        opt_benchmark = true;
        want_longpoll = false;
        want_stratum = false;
        have_stratum = false;
        break;
    case 1003:
        want_longpoll = false;
        break;
    case 1007:
        want_stratum = false;
        break;
    case 1009:
        opt_redirect = false;
        break;
    case 'S':
        use_syslog = true;
        break;
    case 'V':
        show_version_and_exit();
    case 'h':
        show_usage_and_exit(0);
    default:
        show_usage_and_exit(1);
    }
}

static void parse_config(char *pname){
    int i, j, k;
    json_t *val;

    if (!json_is_object(opt_config))
        return;

    for (i = 0; i < ARRAY_SIZE(options); i++) {
        if (!options[i].name)
            break;
        if (!strcmp(options[i].name, "config"))
            continue;

        val = json_object_get(opt_config, options[i].name);
        if (!val)
            continue;

        if (options[i].has_arg && json_is_string(val)) {
            char *s = strdup(json_string_value(val));
            if (!s)
                break;
            parse_arg(options[i].val, s, pname);
            free(s);
        } else if (!options[i].has_arg && json_is_true(val))
            parse_arg(options[i].val, "", pname);
        else if(json_is_array(val))
        {
            if(options[i].val == '\0')
            {
                for(j = 0; j < json_array_size(val); j++)
                {
                    json_t *obj, *value;
                    obj = json_array_get(val, j);
                    for (k = 0; k < ARRAY_SIZE(options); k++)
                    {
                        if (!options[k].name)
                            break;
                        value = json_object_get(obj, options[k].name);
                        if(!value || !json_is_string(value))
                            continue;
                        char *s = strdup(json_string_value(value));
                        if (!s)
                            continue;
                        parse_arg(options[k].val, s, pname);
                        free(s);
                    }
                }
            }
            else
            {
                char *s;
                const char *bit;
                int len;
                json_t *value = json_array_get(val, 0);
                if(!value || !json_is_string(value))
                    continue;
                bit = json_string_value(value);
                s = strdup(bit);
                len = strlen(bit) + 1;
                for(j = 1; j < json_array_size(val); j++)
                {
                    value = json_array_get(val, j);
                    if(!value || !json_is_string(value))
                        continue;
                    bit = json_string_value(value);
                    len += strlen(bit) + 1;
                    s = realloc(s, len);
                    strncat(strncat(s, ",", len), bit, len);
                }
                parse_arg(options[i].val, s, pname);
                free(s);
            }
        }
        else
        {
            fprintf(stderr, "%s: invalid argument for option '%s'\n",
                pname, options[i].name);
            exit(1);
        }
    }
}

static void parse_cmdline(int argc, char *argv[]){
    int key;

    while (1) {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL );
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;

        parse_arg(key, optarg, argv[0]);
    }
    if (optind < argc) {
        fprintf(stderr, "%s: unsupported non-option argument '%s'\n", argv[0],
                argv[optind]);
        show_usage_and_exit(1);
    }

    parse_config(argv[0]);
}

#ifndef WIN32
static void signal_handler(int sig) {
	int i;
    switch (sig) {
    case SIGHUP:
        applog(LOG_INFO, "SIGHUP received");
        break;
    case SIGINT:
        applog(LOG_INFO, "SIGINT received, exiting");
        #if defined __unix__ && (!defined __APPLE__)
		if(opt_algo == ALGO_CRYPTONIGHT)
			for(i = 0; i < opt_n_threads; i++) munmap(persistentctxs[i], sizeof(struct cryptonight_ctx));
		#endif
        exit(0);
        break;
    case SIGTERM:
        applog(LOG_INFO, "SIGTERM received, exiting");
        #if defined __unix__ && (!defined __APPLE__)
		if(opt_algo == ALGO_CRYPTONIGHT)
			for(i = 0; i < opt_n_threads; i++) munmap(persistentctxs[i], sizeof(struct cryptonight_ctx));
		#endif
        exit(0);
        break;
    }
}
#endif

int main(int argc, char *argv[]) {
    struct thr_info *thr;
    unsigned int tmp1, tmp2, tmp3, tmp4;
    long flags;
    int i;

    pthread_mutex_init(&applog_lock, NULL);
    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&tui_lock, NULL);
    pthread_mutex_init(&g_work_lock, NULL);
    pthread_mutex_init(&work_items_lock, NULL);
    pthread_mutex_init(&pool_lock, NULL);
    pthread_mutex_init(&check_pool_lock, NULL);
    pthread_mutex_init(&switch_pool_lock, NULL);
    stratum = calloc(1, sizeof(struct stratum_ctx));
    pthread_mutex_init(&stratum->sock_lock, NULL);
    pthread_mutex_init(&stratum->work_lock, NULL);
    pthread_cond_init(&check_pool_cond, NULL);

    time(&time_start);
	
	#ifndef USE_LOBOTOMIZED_AES
	// If the CPU doesn't support CPUID feature
	// flags, it's WAY too old to have AES-NI
	if(__get_cpuid_max(0, &tmp1) < 1)
	{
		applog(LOG_ERR, "CPU does not have AES-NI, which is required.");
		return(0);
	}
	
	// We already checked the max supported
	// function, so we don't need to check
	// this for error.
	__get_cpuid(1, &tmp1, &tmp2, &tmp3, &tmp4);
	
	// Mask out all bits but bit 25; if it's
	// set, we have AES-NI, if not, nope.
	if(!(tmp3 & 0x2000000))
	{
		applog(LOG_ERR, "CPU does not have AES-NI, which is required.");
		return(0);
	}
	#endif
	
	#ifdef __unix__
	if(geteuid()) applog(LOG_INFO, "I go faster as root.");
	#endif
	
    //rpc_user = strdup("");
    //rpc_pass = strdup("");

    /* parse command line */
    parse_cmdline(argc, argv);

    jsonrpc_2 = true;
    applog(LOG_INFO, "Using JSON-RPC 2.0");

    /*
    if (!opt_benchmark && !rpc_url) {
        fprintf(stderr, "%s: no URL supplied\n", argv[0]);
        show_usage_and_exit(1);
    }

    if (!rpc_userpass) {
        rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
        if (!rpc_userpass)
            return 1;
        sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
    }
    */


    struct pool_details *pool = get_main_pool(pools);
    if(pool == NULL)
    {
        pool = new_pool(true);
        set_active_pool(pools, pool, true);
    }
    flags = strncmp(pool->rpc_url, "https:", 6)
          ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
          : CURL_GLOBAL_ALL;
    if (curl_global_init(flags)) {
        applog(LOG_ERR, "CURL initialization failed");
        return 1;
    }

#ifndef WIN32
    if (opt_background) {
        i = fork();
        if (i < 0)
            exit(1);
        if (i > 0)
            exit(0);
        i = setsid();
        if (i < 0)
            applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
        i = chdir("/");
        if (i < 0)
            applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
        signal(SIGHUP, signal_handler);
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
    }
#endif

#if defined(WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    num_processors = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
    num_processors = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
    int req[] = {CTL_HW, HW_NCPU};
    size_t len = sizeof(num_processors);
    sysctl(req, 2, &num_processors, &len, NULL, 0);
#else
    num_processors = 1;
#endif
    if (num_processors < 1)
        num_processors = 1;
    if (!opt_n_threads)
        opt_n_threads = num_processors - 1;

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
        openlog("cpuminer", LOG_PID, LOG_USER);
#endif

    work_restart = calloc(opt_n_threads, sizeof(*work_restart));
    if (!work_restart)
        return 1;

    thr_info = calloc(opt_n_threads + 3, sizeof(*thr));
    if (!thr_info)
        return 1;

    thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
    if (!thr_hashrates)
        return 1;
	
	thr_times = (double *)calloc(opt_n_threads, sizeof(double));
	
    /* init workio thread info */
    work_thr_id = opt_n_threads;
    thr = &thr_info[work_thr_id];
    thr->id = work_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        return 1;

    /* start work I/O thread */
    if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
        applog(LOG_ERR, "workio thread create failed");
        return 1;
    }

    check_pool_thr_id = opt_n_threads + 6;
    thr = &thr_info[check_pool_thr_id];
    thr->id = check_pool_thr_id;
    /* start check_pool thread */
    if (unlikely(pthread_create(&thr->pth, NULL, check_pool_thread, thr))) {
        applog(LOG_ERR, "check_pool thread create failed");
        return 1;
    }

    if (want_longpoll && !have_stratum) {
        /* init longpoll thread info */
        longpoll_thr_id = opt_n_threads + 1;
        thr = &thr_info[longpoll_thr_id];
        thr->id = longpoll_thr_id;
        thr->q = tq_new();
        if (!thr->q)
            return 1;

        /* start longpoll thread */
        if (unlikely(pthread_create(&thr->pth, NULL, longpoll_thread, thr))) {
            applog(LOG_ERR, "longpoll thread create failed");
            return 1;
        }
    }
    if (want_stratum) {
        /* init stratum thread info */
        stratum_thr_id = opt_n_threads + 2;
        thr = &thr_info[stratum_thr_id];
        thr->id = stratum_thr_id;
        thr->q = tq_new();
        if (!thr->q)
            return 1;

        /* start stratum thread */
        if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr))) {
            applog(LOG_ERR, "stratum thread create failed");
            return 1;
        }

        if (have_stratum)
            tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
    }

    /* start mining threads */
    for (i = 0; i < opt_n_threads; i++) {
        thr = &thr_info[i];

        thr->id = i;
        thr->q = tq_new();
        if (!thr->q)
            return 1;

        if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
            applog(LOG_ERR, "thread %d create failed", i);
            return 1;
        }
    }

    applog(LOG_INFO, "%d miner threads started, "
            "using '%s' algorithm.", opt_n_threads, algo_names[opt_algo]);

    /* main loop - simply wait for workio thread to exit */
    pthread_join(thr_info[work_thr_id].pth, NULL );

    applog(LOG_INFO, "workio thread dead, exiting.");
	#if defined __unix__ && (!defined __APPLE__)
	if(opt_algo == ALGO_CRYPTONIGHT)
		for(i = 0; i < opt_n_threads; i++) munmap(persistentctxs[i], sizeof(struct cryptonight_ctx));
	#endif
    return 0;
}
