/*
 *     Filename: pc_eval.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiang Wang
 *               Chang Chen
 *               Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History:  1. Unified packet classification algorithm / evaluation
 *                   framework design (Xiang Wang & Chang Chen)
 *
 *                2. Add build & search time evaluation in main (Chang Chen)
 *
 *                3. Add range2prefix, prefix2range function
 *                   (Xiang Wang & Chang Chen)
 *
 *                4. Add split_range_rule function (Xiang Wang)
 *
 *                5. Support multi algorithms (Xiaohe Hu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include "pc_eval.h"
#include "hs.h"
#include "tss.h"

#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

static void print_help(void);
static void parse_args(int argc, char *argv[]);
static void load_cb_rules(struct rule_set *rs, const char *rf);     // classbench rule format
static void load_prfx_rules(struct rule_set *rs, const char *rf);   // prefix rule format

static struct {
    char *rule_file;
    char *u_rule_file;
    char *trace_file;
    int algrthm_id;
} cfg = {
    NULL,
    NULL,
    NULL,
    0
};


/* maybe we can use function factory later? */
static struct {
    void (*load_rules)(struct rule_set *, const char *);
    int (*build)(const struct rule_set *, void *);
    int (*insrt_update)(const struct rule_set *, void *);
    int (*search)(const struct trace *, const void *);
    void (*cleanup)(void *);
} algrthms[ALGO_NUM] = {
    {
        load_cb_rules,
        hs_build,
        hs_insrt_update,
        hs_search,
        hs_cleanup
    },
    {
        load_prfx_rules,
        tss_build,
        tss_build,
        tss_search,
        tss_cleanup
    }
};

static struct timeval starttime, stoptime;

int main(int argc, char *argv[])
{
    uint64_t timediff;
    struct rule_set rs = {NULL, NULL, 0};
    struct rule_set u_rs = {NULL, NULL, 0};
    struct trace t;
    void *rt = NULL;

    if (argc < 2) {
        print_help();
        exit(-1);
    }

    parse_args(argc, argv);

    /*
     * Building
     */
    if (cfg.rule_file == NULL) {
        fprintf(stderr, "No rules for processing\n");
        exit(-1);
    }

    algrthms[cfg.algrthm_id].load_rules(&rs, cfg.rule_file);

    printf("Building\n");

    gettimeofday(&starttime, NULL);
    if (algrthms[cfg.algrthm_id].build(&rs, &rt) != 0) {
        fprintf(stderr, "Building failed\n");
        unload_rules(&rs);
        exit(-1);
    }
    gettimeofday(&stoptime, NULL);
    timediff = make_timediff(&starttime, &stoptime);

    printf("Building pass\n");
    printf("Time for building: %ld(us)\n", timediff);

    unload_rules(&rs);

    /*
     * Updating
     */
    if (cfg.u_rule_file != NULL) {
        printf("Updating\n");

        algrthms[cfg.algrthm_id].load_rules(&u_rs, cfg.u_rule_file);

        gettimeofday(&starttime, NULL);
        if (algrthms[cfg.algrthm_id].insrt_update(&u_rs, &rt) != 0) {
            fprintf(stderr, "Updating failed\n");
            unload_rules(&u_rs);
            exit(-1);
        }
        gettimeofday(&stoptime, NULL);
        timediff = make_timediff(&starttime, &stoptime);

        printf("Updating pass\n");
        printf("Time for updating: %ld(us)\n", timediff);

        unload_rules(&u_rs);
    }

    /*
     * Searching
     */
    if (cfg.trace_file == NULL) {
        algrthms[cfg.algrthm_id].cleanup(&rt);
        return 0;
    }

    load_trace(&t, cfg.trace_file);

    printf("Searching\n");

    gettimeofday(&starttime, NULL);
    if (algrthms[cfg.algrthm_id].search(&t, &rt) != 0) {
        fprintf(stderr, "Searching failed\n");
        unload_trace(&t);
        algrthms[cfg.algrthm_id].cleanup(&rt);
        exit(-1);
    }
    gettimeofday(&stoptime, NULL);
    timediff = make_timediff(&starttime, &stoptime);

    printf("Searching pass\n");
    printf("Time for searching: %ld(us)\n", timediff);
    printf("Searching speed: %lld(pps)\n", (t.num * 1000000ULL) / timediff);

    unload_trace(&t);
    algrthms[cfg.algrthm_id].cleanup(&rt);

    return 0;
}

static void print_help(void)
{
    static const char *help =

        "Valid options:\n"
        "  -h, --help         display this help and exit\n"
        "  -r, --rule FILE    specify a rule file for building\n"
        "  -t, --trace FILE   specify a trace file for searching\n"
        "  -u, --update FILE  specify a update rule file for searching\n"
        "  -a, --algorithm ID specify an algorithm, 0:HyperSplit, 1:TSS\n"
        "\n";

    printf("%s", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hr:t:u:a:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"rule", required_argument, NULL, 'r'},
        {"trace", required_argument, NULL, 't'},
        {"update", required_argument, NULL, 'u'},
        {"algorithm", required_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            print_help();
            exit(0);

        case 'a':
            cfg.algrthm_id = atoi(optarg);
            assert(cfg.algrthm_id >= 0 && cfg.algrthm_id < ALGO_NUM);
            break;

        case 'r':
        case 't':
        case 'u':
            if (access(optarg, F_OK) == -1) {
                perror(optarg);
                exit(-1);
            } else {
                if (option == 'r') {
                    cfg.rule_file = optarg;
                } else if (option == 't') {
                    cfg.trace_file = optarg;
                } else if (option == 'u') {
                    cfg.u_rule_file = optarg;
                }
                break;
            }

        default:
            print_help();
            exit(-1);
        }
    }

    return;
}

uint64_t make_timediff(struct timeval *start, struct timeval *stop)
{
    return (1000000ULL * stop->tv_sec + stop->tv_usec) -
        (1000000ULL * start->tv_sec + start->tv_usec);
}

static void load_cb_rules(struct rule_set *rs, const char *rf)
{
    FILE *rule_fp;
    uint32_t src_ip, src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip, dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    uint32_t src_port_begin, src_port_end, dst_port_begin, dst_port_end;
    uint32_t proto, proto_mask;
    uint32_t rule_id;
    unsigned int i = 0;

    printf("Loading rules from %s\n", rf);

    if ((rule_fp = fopen(rf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", rf);
        exit(-1);
    }

    rs->r_rules = calloc(RULE_MAX, sizeof(*rs->r_rules));
    if (rs->r_rules == NULL) {
        perror("Cannot allocate memory for rules");
        exit(-1);
    }
    rs->num = 0;

    while (!feof(rule_fp)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            exit(-1);
        }

        if (fscanf(rule_fp, CB_RULE_FMT,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &src_port_begin, &src_port_end, &dst_port_begin, &dst_port_end,
            &proto, &proto_mask, &rule_id) != 17) {
            fprintf(stderr, "Illegal rule format\n");
            exit(-1);
        }

        /* src ip */
        src_ip = ((src_ip_0 & 0xff) << 24) | ((src_ip_1 & 0xff) << 16) |
            ((src_ip_2 & 0xff) << 8) | (src_ip_3 & 0xff);
        src_ip_mask = src_ip_mask > 32 ? 32 : src_ip_mask;
        src_ip_mask = (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rs->r_rules[i].dim[DIM_SIP][0].u32 = src_ip & src_ip_mask;
        rs->r_rules[i].dim[DIM_SIP][1].u32 = src_ip | (~src_ip_mask);

        /* dst ip */
        dst_ip = ((dst_ip_0 & 0xff) << 24) | ((dst_ip_1 & 0xff) << 16) |
            ((dst_ip_2 & 0xff) << 8) | (dst_ip_3 & 0xff);
        dst_ip_mask = dst_ip_mask > 32 ? 32 : dst_ip_mask;
        dst_ip_mask = (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rs->r_rules[i].dim[DIM_DIP][0].u32 = dst_ip & dst_ip_mask;
        rs->r_rules[i].dim[DIM_DIP][1].u32 = dst_ip | (~dst_ip_mask);

        /* src port */
        rs->r_rules[i].dim[DIM_SPORT][0].u16 = src_port_begin & 0xffff;
        rs->r_rules[i].dim[DIM_SPORT][1].u16 = src_port_end & 0xffff;
        if (rs->r_rules[i].dim[DIM_SPORT][0].u16 >
                rs->r_rules[i].dim[DIM_SPORT][1].u16) {
            swap(rs->r_rules[i].dim[DIM_SPORT][0].u16,
                    rs->r_rules[i].dim[DIM_SPORT][1].u16);
        }

        /* dst port */
        rs->r_rules[i].dim[DIM_DPORT][0].u16 = dst_port_begin & 0xffff;
        rs->r_rules[i].dim[DIM_DPORT][1].u16 = dst_port_end & 0xffff;
        if (rs->r_rules[i].dim[DIM_DPORT][0].u16 >
                rs->r_rules[i].dim[DIM_DPORT][1].u16) {
            swap(rs->r_rules[i].dim[DIM_DPORT][0].u16,
                    rs->r_rules[i].dim[DIM_DPORT][1].u16);
        }

        /* proto */
        if (proto_mask == 0xff) {
            rs->r_rules[i].dim[DIM_PROTO][0].u8 = proto & 0xff;
            rs->r_rules[i].dim[DIM_PROTO][1].u8 = proto & 0xff;
        } else if (proto_mask == 0) {
            rs->r_rules[i].dim[DIM_PROTO][0].u8 = 0;
            rs->r_rules[i].dim[DIM_PROTO][1].u8 = 0xff;
        } else {
            fprintf(stderr, "Protocol mask error: %02x\n", proto_mask);
            exit(-1);
        }

        rs->r_rules[i].pri = rule_id - 1;

        rs->num++;
        i++;
    }

    fclose(rule_fp);

    printf("%d rules loaded\n", rs->num);

    return;
}

static void load_prfx_rules(struct rule_set *rs, const char *rf)
{
    FILE *rule_fp;
    uint32_t src_ip, src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip, dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    uint32_t src_port, src_port_mask, dst_port, dst_port_mask;
    uint32_t proto, proto_mask;
    uint32_t rule_id;
    unsigned int i = 0;

    printf("Loading rules from %s\n", rf);

    if ((rule_fp = fopen(rf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", rf);
        exit(-1);
    }

    rs->p_rules = calloc(RULE_MAX, sizeof(*rs->p_rules));
    if (rs->p_rules == NULL) {
        perror("Cannot allocate memory for rules");
        exit(-1);
    }
    rs->num = 0;

    while (!feof(rule_fp)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            exit(-1);
        }

        if (fscanf(rule_fp, PRFX_RULE_FMT,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &src_port, &src_port_mask, &dst_port, &dst_port_mask,
            &proto, &proto_mask, &rule_id) != 17) {
            fprintf(stderr, "Illegal rule format\n");
            exit(-1);
        }

        /* src ip */
        src_ip = ((src_ip_0 & 0xff) << 24) | ((src_ip_1 & 0xff) << 16) |
            ((src_ip_2 & 0xff) << 8) | (src_ip_3 & 0xff);
        src_ip_mask = src_ip_mask > 32 ? 32 : src_ip_mask;
        rs->p_rules[i].dim[DIM_SIP].u32 = src_ip & \
            (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rs->p_rules[i].len[DIM_SIP] = src_ip_mask;

        /* dst ip */
        dst_ip = ((dst_ip_0 & 0xff) << 24) | ((dst_ip_1 & 0xff) << 16) |
            ((dst_ip_2 & 0xff) << 8) | (dst_ip_3 & 0xff);
        dst_ip_mask = dst_ip_mask > 32 ? 32 : dst_ip_mask;
        rs->p_rules[i].dim[DIM_DIP].u32 = dst_ip & \
            (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rs->p_rules[i].len[DIM_DIP] = dst_ip_mask;

        /* src port */
        rs->p_rules[i].dim[DIM_SPORT].u16 = src_port & 0xffff;
        rs->p_rules[i].len[DIM_SPORT] = src_port_mask;

        /* dst port */
        rs->p_rules[i].dim[DIM_DPORT].u16 = dst_port & 0xffff;
        rs->p_rules[i].len[DIM_DPORT] = dst_port_mask;

        /* proto */
        if (proto_mask == 0xff) {
            rs->p_rules[i].dim[DIM_PROTO].u8 = proto & 0xff;
            rs->p_rules[i].len[DIM_PROTO] = 8;
        } else if (proto_mask == 0) {
            rs->p_rules[i].dim[DIM_PROTO].u8 = 0;
            rs->p_rules[i].len[DIM_PROTO] = 0;
        } else {
            fprintf(stderr, "Protocol mask error: %02x\n", proto_mask);
            exit(-1);
        }

        rs->p_rules[i].pri = rule_id - 1;

        rs->num++;
        i++;
    }

    fclose(rule_fp);

    printf("%d rules loaded\n", rs->num);

    return;
}

void unload_rules(struct rule_set *rs)
{
    SAFE_FREE(rs->r_rules);
    SAFE_FREE(rs->p_rules);
    return;
}

void load_trace(struct trace *t, const char *tf)
{
    FILE *trace_fp;
    unsigned int i = 0;

    printf("Loading trace from %s\n", tf);

    if ((trace_fp = fopen(tf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", tf);
        exit(-1);
    }

    t->pkts = calloc(PKT_MAX, sizeof(struct packet));
    if (t->pkts == NULL) {
        perror("Cannot allocate memory for packets");
        exit(-1);
    }
    t->num = 0;

    while (!feof(trace_fp)) {
        if (i >= PKT_MAX) {
            fprintf(stderr, "Too many packets\n");
            exit(-1);
        }

        if (fscanf(trace_fp, PKT_FMT,
            &t->pkts[i].val[DIM_SIP].u32, &t->pkts[i].val[DIM_DIP].u32,
            &t->pkts[i].val[DIM_SPORT].u32, &t->pkts[i].val[DIM_DPORT].u32,
            &t->pkts[i].val[DIM_PROTO].u32, &t->pkts[i].match) != 6) {
            fprintf(stderr, "Illegal packet format\n");
            exit(-1);
        }

        t->pkts[i].val[DIM_SPORT].u16 = t->pkts[i].val[DIM_SPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_DPORT].u16 = t->pkts[i].val[DIM_DPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_PROTO].u8 = t->pkts[i].val[DIM_PROTO].u32 & 0xff;
        t->pkts[i].match--; //rule priority start @ 0

        t->num++;
        i++;
    }

    fclose(trace_fp);

    printf("%d packets loaded\n", t->num);

    return;
}

void unload_trace(struct trace *t)
{
    free(t->pkts);
    return;
}
