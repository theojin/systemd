/*
 * This file contains standalone test-runner.
 * This file is NOT part of systemd project.
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 * Author: Kazimierz Krosman <k.krosman@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <ctype.h>
#include <time.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdbool.h>

#define TC_NAME "systemd-tests"
#define MAX_TC_NUM 1024
#define MAX_BUFFER (64*1024)
#define MAX_COMMENT 1024

enum {
        INIT_TEST,
        NEW_STDOUT,
        NEW_STDERR,
        RESULT_CODE,
        RESULT_SIGNAL,
        RESULT_ERROR,
        RESULT_TIMEOUT
};

struct test_result {
        bool is_positive;
        char comment[MAX_COMMENT];
        char result[MAX_COMMENT];
        char name[MAX_COMMENT];
};

struct test_case {
        const char* name;
        const char* description;
};

struct binary {
        const char* path;
        const char* name;
        struct test_case* test_cases;
        int timeout;

        char** (*prepare_args) (const struct binary* b, const char* test_name);
        void (*parse) (const struct binary* b, const char* test_name, char* buffer, int state_change, int state_option);
        int (*init)(void);
        int (*clean)(void);
};

char* get_test_id(char* dest, const struct binary* b, const char* test_name);
void add_test_result(const char* test_id, const char* result, const char* comment, int res);

enum {
        PIPE_READ,
        PIPE_WRITE,
};

void parse_test_state(const struct binary* b, const char* test_name, char* buffer, int state_change, int state_option);
void parse_one_test_one_binary(const struct binary* b, const char* test_name, char* buffer, int state_change, int state_option);
char** prepare_args_for_binary(const struct binary* b, const char* test_name);

static struct test_case test_case_desc_01[] = {
        {"", "Test messages (signals and method calls) passing between server and clients"},
        {NULL, NULL}
};

static struct test_case test_case_desc_02[] = {
        {"", "Test bus reference counting"},
        {NULL, NULL}
};

static struct test_case test_case_desc_03[] = {
        {"", "Test handling of processes credentials"},
        {NULL, NULL}
};

static struct test_case test_case_desc_04[] = {
        {"", "Test sd_bus_error component and errors handling"},
        {NULL, NULL}
};

static struct test_case test_case_desc_05[] = {
        {"", "Test GVariant serializer/deserializer"},
        {NULL, NULL}
};

static struct test_case test_case_desc_06[] = {
        {"", "Test object vtable implementation for exposing objects on the bus"},
        {NULL, NULL}
};

static struct test_case test_case_desc_07[] = {
        {"", "Test low-level sd-bus API"},
        {NULL, NULL}
};

static struct test_case test_case_desc_08[] = {
        {"", "Benchmark tool to determine the right threshold for copying vs. memfd"},
        {NULL, NULL}
};

static struct test_case test_case_desc_09[] = {
        {"", "Comprehensive test for the bloom filter logic"},
        {NULL, NULL}
};

static struct test_case test_case_desc_10[] = {
        {"", "Yet another test for low-level sd-bus API"},
        {NULL, NULL}
};

static struct test_case test_case_desc_11[] = {
        {"", "Test parsing and spliting up 'match' strings"},
        {NULL, NULL}
};

static struct test_case test_case_desc_12[] = {
        {"", "Yet another test for object vtable implementation"},
        {NULL, NULL}
};

static struct test_case test_case_desc_13[] = {
        {"", "Test APIs for negotiating what is attached to messages"},
        {NULL, NULL}
};

static struct test_case test_case_desc_14[] = {
        {"", "Test message signatures"},
        {NULL, NULL}
};

static struct test_case test_case_desc_15[] = {
        {"", "Test memfd support"},
        {NULL, NULL}
};

/* This table is used to start binaries */
struct binary tests[] = {
        /*path, name, TC_table, timeout in us, prepare_args_handler, parse_function_handler, init_handler, clean_handler*/
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-chat",             "test-bus-chat",             test_case_desc_01, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-cleanup",          "test-bus-cleanup",          test_case_desc_02, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-creds",            "test-bus-creds",            test_case_desc_03, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-error",            "test-bus-error",            test_case_desc_04, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-gvariant",         "test-bus-gvariant",         test_case_desc_05, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-introspect",       "test-bus-introspect",       test_case_desc_06, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-kernel",           "test-bus-kernel",           test_case_desc_07, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-kernel-benchmark", "test-bus-kernel-benchmark", test_case_desc_08, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-kernel-bloom",     "test-bus-kernel-bloom",     test_case_desc_09, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-marshal",          "test-bus-marshal",          test_case_desc_10, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-match",            "test-bus-match",            test_case_desc_11, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-objects",          "test-bus-objects",          test_case_desc_12, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-server",           "test-bus-server",           test_case_desc_13, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-signature",        "test-bus-signature",        test_case_desc_14, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
        {"/usr/lib/dbus-tests/test-suites/systemd-tests/test-bus-zero-copy",        "test-bus-zero-copy",        test_case_desc_15, 5000*1000, prepare_args_for_binary, parse_one_test_one_binary, NULL, NULL},
};

static char* args[3];
char** prepare_args_for_binary(const struct binary* b, const char* test_name)
{
        args[0] = (char*)b->name;
        args[1] = NULL;
        return args;
}

void parse_one_test_one_binary(const struct binary* b, const char* test_name, char* buffer, int state_change, int state_option)
{
        char test_id[MAX_COMMENT];

        switch(state_change) {
        case INIT_TEST:
                break;
        case NEW_STDOUT:
                buffer[state_option] = 0;
                get_test_id(test_id, b, test_name);
                fprintf(stderr, "[stdout][%s]%s\n",test_id, buffer);
                break;
        case NEW_STDERR:
                buffer[state_option] = 0;
                get_test_id(test_id, b, test_name);
                fprintf(stderr, "[stderr][%s]%s\n",test_id, buffer);
                break;
        case RESULT_CODE:
                get_test_id(test_id, b, test_name);
                if (state_option == 0)
                        add_test_result(test_id, "OK", "", 1);
                else if (state_option == 77)
                        add_test_result(test_id, "SKIP", "Please check stderr for details", 0);
                else
                        add_test_result(test_id, "ERROR", "", 0);
                break;
        case RESULT_SIGNAL:
                get_test_id(test_id, b, test_name);
                add_test_result(test_id, "ERROR", "Finished by SIGNAL", 0);
                break;
        case RESULT_TIMEOUT:
                get_test_id(test_id, b, test_name);
                add_test_result(test_id, "ERROR", "Test TIMEOUT", 0);
                break;
        }
}

static struct option long_options[] = {
        {"list",        no_argument,       0, 'l'},
        {"run",         required_argument, 0, 'r'},
        {"description", required_argument, 0, 'd'},
        {0,             0,                 0,  0 }
};

static int stdin_pipe[2];
static int stdout_pipe[2];
static int stderr_pipe[2];
static int gravedigger_pipe[2];
static struct test_result test_results[MAX_TC_NUM];
static int test_results_i;
static char buffer[MAX_BUFFER];
static const char* requested_tc[MAX_TC_NUM];

char* get_test_id(char* dest, const struct binary* b, const char* test_name)
{
        int len = strlen(b->name);
        memcpy(dest, b->name, len);
        memcpy(dest + len, test_name, strlen(test_name)+1);
        return dest;
}

static void print_description(const char* name, const char* description)
{
        printf("%s;%s\n",name, description);
}

static void print_list(const char* test_name)
{
        unsigned int i;
        char full_name[MAX_COMMENT];
        for (i = 0;i < sizeof(tests)/sizeof(struct binary); i++) {
                int j = 0;
                int l = strlen(tests[i].name);
                memcpy(full_name, tests[i].name, l+1);
                if (test_name && strncmp(test_name, full_name, l) != 0)
                        continue;

                while (tests[i].test_cases[j].name) {
                        memcpy(full_name + l, tests[i].test_cases[j].name, strlen(tests[i].test_cases[j].name) + 1);
                        if (!test_name || strcmp(full_name, test_name) == 0)
                                print_description(full_name,tests[i].test_cases[j].description);
                        j++;
                }
        }
}


static void stop_binary(const struct binary* b, pid_t pid, const char* test_name, int w_res)
{
        int status = 0;
        int res = 0;
        if (w_res == 0)
                res = waitpid(pid, &status, WNOHANG);
        else
                res = waitpid(pid, &status, 0);

        if (res == 0) {
                //timeouted
                kill(pid, SIGKILL);
                res = waitpid(pid, &status, WNOHANG);
                b->parse(b, test_name, buffer, RESULT_TIMEOUT, res);
        } else if (res < 0) {
                //errno check
                kill(pid, SIGKILL);
                res = waitpid(pid, &status, WNOHANG);
                b->parse(b, test_name, buffer, RESULT_ERROR, res);
        } else if (res > 0) {
                if (WIFEXITED(status)) {
                        b->parse(b, test_name, buffer, RESULT_CODE, WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                        b->parse(b, test_name, buffer, RESULT_SIGNAL, WTERMSIG(status));
                } else if (WIFSTOPPED(status)) {
                        b->parse(b, test_name, buffer, RESULT_SIGNAL, WSTOPSIG(status));
        } else if (WIFCONTINUED(status)) {
                        kill(pid, SIGKILL);
                        b->parse(b, test_name, buffer, RESULT_SIGNAL, -1);
                }
        }
}

static void parse_output_with_timeout(const struct binary* b, pid_t pid, const char* test_name)
{
        struct timeval tv;
        fd_set rfds;
        int nfds;
        int res;
        int w_res = 0;
        tv.tv_sec = b->timeout/(1000*1000);
        tv.tv_usec = (b->timeout-tv.tv_sec*1000*1000);
        while (1) {
                FD_ZERO(&rfds);
                if (stdout_pipe[PIPE_READ] > -1) {
                        assert(stdout_pipe[PIPE_READ] > -1);
                        assert(stdout_pipe[PIPE_READ] < 1024);
                        FD_SET(stdout_pipe[PIPE_READ], &rfds);
                }
                if (stderr_pipe[PIPE_READ] > -1) {
                        assert(stderr_pipe[PIPE_READ] > -1);
                        assert(stderr_pipe[PIPE_READ] < 1024);
                        FD_SET(stderr_pipe[PIPE_READ], &rfds);
                }
                FD_SET(gravedigger_pipe[PIPE_READ], &rfds);

                nfds = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
                if (nfds == -1) {
                        if (errno != EINTR) {
                                w_res = 0;
                                break;
                        }
                } else if (nfds > 0) {
                        if (stdout_pipe[PIPE_READ] > -1 && FD_ISSET(stdout_pipe[PIPE_READ], &rfds)) {
                                res = read(stdout_pipe[PIPE_READ], buffer, MAX_BUFFER-1);
                                if (res == 0 || (res < 0 && errno != EINTR)) {
                                        close (stdout_pipe[PIPE_READ]);
                                        stdout_pipe[PIPE_READ] = -1;
                                        continue;
                                } else if (res >=0) {
                                        b->parse(b, test_name, buffer, NEW_STDOUT, res);
                                }
                        }

                        if (stderr_pipe[PIPE_READ] > -1 && FD_ISSET(stderr_pipe[PIPE_READ], &rfds)) {
                                res = read(stderr_pipe[PIPE_READ], buffer, MAX_BUFFER-1);
                                if (res == 0 || (res < 0 && errno != EINTR)) {
                                        close (stderr_pipe[PIPE_READ]);
                                        stderr_pipe[PIPE_READ] = -1;
                                        continue;
                                }
                                b->parse(b, test_name, buffer, NEW_STDERR, res);
                        }

                        if (FD_ISSET(gravedigger_pipe[PIPE_READ], &rfds)) {
                                w_res = 1;
                                break; //it has ended
                        }
                } else {
                        //timeout
                        w_res = 0;
                        break;
                }
        }
        stop_binary(b, pid, test_name, w_res);
}

static int create_child(const char* path, char* const arguments[])
{
        int child;
        int nResult;
        if (pipe(gravedigger_pipe) < 0) {
                perror("allocating pipe for gravedigger failed");
                goto error1;
        }

        if (pipe(stdin_pipe) < 0) {
                perror("allocating pipe for child input redirect failed");
                goto error1;
        }

        if (pipe(stdout_pipe) < 0) {
                perror("allocating pipe for child output redirect failed");
                goto error2;
        }

        if (pipe(stderr_pipe) < 0) {
                perror("allocating pipe for child output redirect failed");
                goto error3;
        }

        child = fork();
        if (!child) {
                // redirect stdin
                if (dup2(stdin_pipe[PIPE_READ], STDIN_FILENO) == -1) {
                        perror("redirecting stdin failed");
                        return -1;
                }

                if (dup2(stdout_pipe[PIPE_WRITE], STDOUT_FILENO) == -1) {
                        perror("redirecting stdout failed");
                        return -1;
                }

                if (dup2(stderr_pipe[PIPE_WRITE], STDERR_FILENO) == -1) {
                        perror("redirecting stderr failed");
                        return -1;
                }

                close(stdin_pipe[PIPE_READ]);
                close(stdin_pipe[PIPE_WRITE]);
                close(stdout_pipe[PIPE_READ]);
                close(stdout_pipe[PIPE_WRITE]);
                close(stderr_pipe[PIPE_READ]);
                close(stderr_pipe[PIPE_WRITE]);
                close(gravedigger_pipe[PIPE_READ]);

                // run child process image
                nResult = execv(path, arguments);

                // if we get here at all, an error occurred, but we are in the child
                // process, so just exit
                perror("exec of the child process  failed");
                exit(nResult);
        } else if (child > 0) {
                // close unused file descriptors, these are for child only
                close(stdin_pipe[PIPE_READ]);
                close(stdout_pipe[PIPE_WRITE]);
                close(stderr_pipe[PIPE_WRITE]);
                close(gravedigger_pipe[PIPE_WRITE]);
        } else {
                // failed to create child
                goto error4;
        }

        return child;

error4:
        close(stderr_pipe[PIPE_READ]);
        close(stderr_pipe[PIPE_WRITE]);
error3:
        close(stdout_pipe[PIPE_READ]);
        close(stdout_pipe[PIPE_WRITE]);
error2:
        close(stdin_pipe[PIPE_READ]);
        close(stdin_pipe[PIPE_WRITE]);
error1:
        return -1;
}

static void run_test(const struct binary* b, const char* test_name)
{
        int res = -1;
        char** arg;
        char test_id[MAX_COMMENT];

        assert(b);
        assert(b->name);
        assert(b->path);
        assert(test_name);

        arg = b->prepare_args(b, test_name);

        if (b->init)
                if (!b->init()) {
                        add_test_result(get_test_id(test_id, b, test_name), "0", "Cannot init test", 0);
                        return;
                }

        res = create_child(b->path, arg);
        if (res > 0)
                parse_output_with_timeout(b, res, test_name);
        else
                add_test_result(get_test_id(test_id, b, test_name), "0", "Cannot start test", 0);

        if (b->clean)
                b->clean();
}

static void parse_run_test(const char* tc) {
        unsigned int i = 0;
        for (i = 0;i < sizeof(tests)/sizeof(struct binary); i++) {
                int len = strlen(tests[i].name);
                if (strncmp(tc, tests[i].name, len) == 0) {
                        if (tc[len] == '*' || tc[len] == '\0')
                                run_test(&tests[i], "");
            else
                                run_test(&tests[i], tc + len);
                }
        }
}

static int parse_option(int argc, char* argv[])
{
        int ch = 0;
        int c = 0;
        while ((ch = getopt_long(argc, argv, "lr:d:", long_options, NULL)) != -1) {
                switch (ch) {
                case 'l':
                        print_list(NULL);
                        return 1;
                case 'r':
                        if (c >= MAX_TC_NUM - 1) //NULL at the end
                                return 0;

                        if (optarg)
                                requested_tc[c++] = optarg;

                        break;
                case 'd':
                        print_list(optarg);
            return 1;
                }
        }
        return 0;
}

void add_test_result(const char* test_id, const char* result, const char* comment, int res)
{
        test_results[test_results_i].is_positive = res;
        strcpy(test_results[test_results_i].result, result);
        strcpy(test_results[test_results_i].comment, comment);
        strcpy(test_results[test_results_i++].name, test_id);
}

static void prepare_results(void)
{
}

static void print_results(const char* tcs_name)
{
        int i = 0;
        for (i = 0; i < test_results_i; i++)
        {
                printf("%s;%s;%s;%s\n", tcs_name, test_results[i].name, test_results[i].result, test_results[i].comment);
        }
}

int main(int argc, char* argv[])
{
        unsigned int i;
        signal(SIGPIPE, SIG_IGN);
        if (parse_option(argc, argv))
                return 0;

        prepare_results();

        if (!requested_tc[0]) {
                for (i = 0;i < sizeof(tests)/sizeof(struct binary); i++)
                    run_test(&tests[i], "");
        } else {
                i = 0;
                while(requested_tc[i]) {
                    parse_run_test(requested_tc[i]);
                        i++;
                }
        }

        print_results(TC_NAME);
        return 0;
}
