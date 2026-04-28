/*
 * sshpass-win.c - SSH password automation for Windows
 * Feature-compatible with Unix sshpass.
 * Uses SSH_ASKPASS to pass passwords to Windows OpenSSH.
 *
 * Compile: gcc -O2 -o sshpass.exe sshpass-win.c
 *
 * Exit codes (matching original sshpass):
 *   0 - success
 *   1 - invalid arguments
 *   3 - general runtime error
 *   4 - password source error
 *   6 - password refused
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <io.h>
#include <fcntl.h>

#define MAX_PASSWORD_LEN 16384

static int g_verbose = 0;

static void vprint(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("sshpass: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---------- Resolve SSH to Windows native binary ---------- */
static const char *resolve_ssh(const char *cmd) {
    if (strcmp(cmd, "ssh") != 0 && strcmp(cmd, "ssh.exe") != 0)
        return cmd;
    static char win_ssh[MAX_PATH];
    const char *checks[] = {
        "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "C:\\Windows\\System32\\ssh.exe",
        NULL
    };
    for (int i = 0; checks[i]; i++) {
        DWORD a = GetFileAttributesA(checks[i]);
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            strcpy(win_ssh, checks[i]);
            return win_ssh;
        }
    }
    return cmd;
}

/* ---------- Spawn process and wait ---------- */
static int run_proc(const char *app, char *cmdline) {
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(app, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "sshpass: Failed to start process (error %lu)\n", GetLastError());
        return -1;
    }
    vprint("started PID %lu", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    vprint("process exited with code %lu", ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)ec;
}

/* ---------- Write raw data to a temp file ---------- */
static int write_raw_file(const char *path, const char *data, int len) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD written;
    BOOL ok = WriteFile(h, data, (DWORD)len, &written, NULL);
    CloseHandle(h);
    return ok && (int)written == len;
}

/* ---------- Print usage ---------- */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-f|-d|-p|-e] [-hV] command parameters\n"
        "   -f filename   Take password to use from file\n"
        "   -d number     Use number as file descriptor for password\n"
        "   -p password   Provide password as argument (security UNsafe)\n"
        "   -e            Password is passed via env var SSHPASS\n"
        "   -P prompt     Prompt string to look for (ignored, for compat)\n"
        "   -v            Be verbose\n"
        "   -h            Show this help\n"
        "\n"
        "With no arguments -p, -f, -d, or -e the password will be taken\n"
        "from the standard input.\n",
        prog);
}

/* ---------- Main ---------- */
int main(int argc, char *argv[]) {
    char password[MAX_PASSWORD_LEN];
    int  password_len = 0;
    int  password_set = 0;
    int  cmd_start = 1;

    /* Parse options (same order and names as original sshpass) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "sshpass: -p requires an argument\n");
                return 1;
            }
            const char *src = argv[i + 1];
            password_len = (int)strlen(src);
            if (password_len >= MAX_PASSWORD_LEN) {
                fprintf(stderr, "sshpass: password too long\n");
                return 1;
            }
            memcpy(password, src, password_len + 1);
            password_set = 1;
            cmd_start = i + 2; i++;
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "sshpass: -f requires an argument\n");
                return 1;
            }
            FILE *fp = fopen(argv[i + 1], "rb");
            if (!fp) {
                fprintf(stderr, "sshpass: Failed to open %s\n", argv[i + 1]);
                return 4;
            }
            password_len = (int)fread(password, 1, MAX_PASSWORD_LEN - 1, fp);
            fclose(fp);
            if (password_len <= 0) {
                fprintf(stderr, "sshpass: Empty password file\n");
                return 4;
            }
            while (password_len > 0 && (password[password_len-1] == '\n' ||
                                        password[password_len-1] == '\r'))
                password_len--;
            password[password_len] = '\0';
            password_set = 1;
            cmd_start = i + 2; i++;
        } else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "sshpass: -d requires an argument\n");
                return 1;
            }
            int fd = atoi(argv[i + 1]);
            if (fd < 0) {
                fprintf(stderr, "sshpass: Invalid file descriptor\n");
                return 4;
            }
            int n = (int)_read(fd, password, MAX_PASSWORD_LEN - 1);
            if (n <= 0) {
                fprintf(stderr, "sshpass: Failed to read from fd %d\n", fd);
                return 4;
            }
            password_len = n;
            while (password_len > 0 && (password[password_len-1] == '\n' ||
                                        password[password_len-1] == '\r'))
                password_len--;
            password[password_len] = '\0';
            password_set = 1;
            cmd_start = i + 2; i++;
        } else if (strcmp(argv[i], "-e") == 0) {
            const char *env = getenv("SSHPASS");
            if (!env) {
                fprintf(stderr, "sshpass: SSHPASS environment variable not set\n");
                return 1;
            }
            password_len = (int)strlen(env);
            if (password_len >= MAX_PASSWORD_LEN) {
                fprintf(stderr, "sshpass: password too long\n");
                return 1;
            }
            memcpy(password, env, password_len + 1);
            password_set = 1;
            cmd_start = i + 1;
        } else if (strcmp(argv[i], "-P") == 0) {
            /* Prompt string to match — ignored for SSH_ASKPASS approach */
            if (i + 1 < argc) i++;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1]) {
            fprintf(stderr, "sshpass: Unknown option: %s\n", argv[i]);
            return 1;
        } else {
            break;  /* first non-option arg = start of SSH command */
        }
    }

    if (!password_set && cmd_start >= argc) {
        usage(argv[0]);
        return 1;
    }

    /* If password not set yet, read from stdin */
    if (!password_set) {
        int total = 0;
        while (total < MAX_PASSWORD_LEN - 1) {
            int c = getchar();
            if (c == EOF || c == '\n') break;
            password[total++] = (char)c;
        }
        password[total] = '\0';
        password_len = total;
        password_set = 1;
    }

    /* ---------- SSH_ASKPASS setup ---------- */
    char tmpdir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpdir);

    /* 1. Write raw password to a temp file */
    char pwd_file[MAX_PATH];
    if (!GetTempFileNameA(tmpdir, "spp", 0, pwd_file)) {
        fprintf(stderr, "sshpass: Could not create temp file\n");
        return 3;
    }
    if (!write_raw_file(pwd_file, password, password_len)) {
        fprintf(stderr, "sshpass: Could not write password temp file\n");
        DeleteFileA(pwd_file);
        return 3;
    }
    vprint("password file: %s", pwd_file);

    /* 2. Create a batch helper that prints the password file */
    char bat_file[MAX_PATH];
    if (!GetTempFileNameA(tmpdir, "spb", 0, bat_file)) {
        DeleteFileA(pwd_file);
        fprintf(stderr, "sshpass: Could not create temp file\n");
        return 3;
    }
    /* Rename .tmp to .bat so cmd.exe will accept it */
    int bfn = (int)strlen(bat_file);
    if (bfn > 4) strcpy(bat_file + bfn - 4, ".bat");

    FILE *f = fopen(bat_file, "w");
    if (!f) {
        DeleteFileA(pwd_file);
        DeleteFileA(bat_file);
        fprintf(stderr, "sshpass: Could not create askpass script\n");
        return 3;
    }
    fprintf(f, "@type \"%s\"\r\n", pwd_file);
    fclose(f);
    vprint("askpass script: %s", bat_file);

    /* 3. Set environment variables for SSH */
    SetEnvironmentVariableA("SSH_ASKPASS", bat_file);
    SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", "force");
    if (g_verbose) {
        char buf[4096];
        GetEnvironmentVariableA("SSH_ASKPASS", buf, sizeof(buf));
        vprint("SSH_ASKPASS=%s", buf);
        GetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", buf, sizeof(buf));
        vprint("SSH_ASKPASS_REQUIRE=%s", buf);
    }

    /* 4. Resolve SSH binary */
    const char *ssh_path = resolve_ssh(argv[cmd_start]);
    vprint("ssh binary: %s", ssh_path);

    /* 5. Build command line */
    int len = 0;
    for (int i = cmd_start; i < argc; i++) {
        const char *a = (i == cmd_start) ? ssh_path : argv[i];
        len += (int)strlen(a) + 4;
    }
    char *cmdline = (char*)malloc(len + 1);
    if (!cmdline) { DeleteFileA(pwd_file); DeleteFileA(bat_file); return 3; }
    cmdline[0] = '\0';
    for (int i = cmd_start; i < argc; i++) {
        const char *a = (i == cmd_start) ? ssh_path : argv[i];
        if (i > cmd_start) strcat(cmdline, " ");
        if (strchr(a, ' ')) { strcat(cmdline, "\""); strcat(cmdline, a); strcat(cmdline, "\""); }
        else strcat(cmdline, a);
    }
    vprint("command line: %s", cmdline);

    /* 6. Run SSH */
    int rc = run_proc(ssh_path, cmdline);
    if (rc < 0) rc = 3;
    if (rc == 255) rc = 6;  /* map SSH auth failure to sshpass code 6 */

    /* 7. Cleanup temp files (ignore errors) */
    free(cmdline);
    DeleteFileA(bat_file);
    DeleteFileA(pwd_file);

    return rc;
}
