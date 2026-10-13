/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    char path[PROC_PIDPATHINFO_MAXSIZE], config[PATH_MAX];
    if (proc_pidpath(getpid(), path, sizeof(path)) <= 0) return 1;
    char *slash = strrchr(path, '/');
    if (!slash) return 1;
    *slash = '\0';
    if (snprintf(config, sizeof(config), "%s/../Resources/runtime.txt", path) >= (int)sizeof(config)) return 1;
    FILE *file = fopen(config, "r");
    if (!file) return 1;
    char runtime[PATH_MAX], python[PATH_MAX], script[PATH_MAX];
    if (!fgets(runtime, sizeof(runtime), file)) { fclose(file); return 1; }
    fclose(file);
    runtime[strcspn(runtime, "\r\n")] = '\0';
    if (snprintf(python, sizeof(python), "%s/bin/python", runtime) >= (int)sizeof(python) ||
        snprintf(script, sizeof(script), "%s/bin/isopropyl", runtime) >= (int)sizeof(script)) return 1;
    char **args = calloc((size_t)argc + 3, sizeof(char *));
    if (!args) return 1;
    args[0] = python; args[1] = "-I"; args[2] = script;
    for (int i = 1; i < argc; i++) args[i + 2] = argv[i];
    pid_t child;
    int error = posix_spawn(&child, python, NULL, NULL, args, environ);
    free(args);
    if (error) { fprintf(stderr, "ISOpropyl launch: %s\n", strerror(error)); return 1; }
    // Keep the LaunchServices app process alive for TCC attribution.
    int status;
    while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) return 1; }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
