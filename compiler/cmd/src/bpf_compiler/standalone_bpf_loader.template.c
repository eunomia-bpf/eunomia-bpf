#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char* package_json_buf = "<REPLACE-HERE>";

struct eunomia_bpf;
struct eunomia_polling_handle;

enum export_format_type {
    EXPORT_PLAIN_TEXT,
    EXPORT_JSON,
    EXPORT_RAW_EVENT,
};
struct eunomia_bpf* open_eunomia_skel_from_json_package_with_args(
    const char* json_data,
    char** args,
    int argc,
    char* btf_archive_path);
void get_error_message(char* str_out, size_t buf_size);
int load_and_attach_eunomia_skel(struct eunomia_bpf* prog);
struct eunomia_polling_handle* handle_create(struct eunomia_bpf* prog);
void handle_set_pause_state(struct eunomia_polling_handle* handle,
                            uint8_t pause);
void handle_terminate(struct eunomia_polling_handle* handle);
void handle_destroy(struct eunomia_polling_handle* handle);
void destroy_eunomia_skel(struct eunomia_bpf* prog);
int wait_and_poll_events_to_handler(struct eunomia_bpf* prog,
                                    enum export_format_type type,
                                    void (*handler)(void*,
                                                    const char*,
                                                    size_t size),
                                    void* ctx);


void print_error() {
    static char buf[2048];
    get_error_message(buf, sizeof(buf));
    fputs(buf, stderr);
}

void callback(void* ctx, const char* data, size_t size) {
    static char buf[2048];
    memcpy(buf, data, size);
    buf[size] = 0;
    puts(buf);
}

static struct eunomia_bpf* skel;
static int polling = 0;

static struct eunomia_polling_handle* handle;

void handle_sigterm(int sig) {
    puts("Received SIGINT, exiting..");
    handle_terminate(handle);
    handle_destroy(handle);
    destroy_eunomia_skel(skel);
    exit(0);
}

int main(int argc, char** argv) {
    // Register the signal handler
    {
        struct sigaction action;
        action.sa_handler = handle_sigterm;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;

        if (sigaction(SIGINT, &action, NULL) < 0) {
            fputs("Failed to register signal handler", stderr);
        }
    }

    skel = open_eunomia_skel_from_json_package_with_args(package_json_buf, argv,
                                                         argc, NULL);
    int err;
    if (!skel) {
        print_error();
        return 1;
    }
    err = load_and_attach_eunomia_skel(skel);
    if (err != 0) {
        print_error();
        return 1;
    }
    handle = handle_create(skel);
    if (!handle) {
        print_error();
        return 1;
    }
    polling = 1;
    err = wait_and_poll_events_to_handler(skel, EXPORT_PLAIN_TEXT, callback,
                                          NULL);
    if (err != 0) {
        print_error();
        return 1;
    }
    destroy_eunomia_skel(skel);
    return 0;
}
