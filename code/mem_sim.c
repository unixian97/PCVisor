/*
 *     Filename: mem_sim.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History:  1. main file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include "pc_eval.h"

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

int main(int argc, char *argv[])
{
    uint64_t timediff;
    struct timeval starttime, stoptime;
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
