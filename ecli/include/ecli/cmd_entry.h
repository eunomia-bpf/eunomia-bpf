#ifndef ECLI_CMD_ENTRY_H
#define ECLI_CMD_ENTRY_H

// The running cmd of ecli
int
cmd_run_main(int argc, char *argv[]);
// pull package from a remote server or url
int
cmd_pull_main(int argc, char *argv[]);
// images cmd of ecli
int
cmd_images_main(int argc, char *argv[]);

#endif
