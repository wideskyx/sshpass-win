/*
 * sshpass-win.c - SSH password automation for Windows
 * Feature-compatible with Unix sshpass.
 * Uses SSH_ASKPASS to pass passwords to Windows OpenSSH.
 * Supports winpty-based interactive mode (-i) for AI tool integration.
 *
 * Compile: gcc -O2 -o sshpass.exe sshpass-win.c /usr/lib/winpty.lib
 *
 * Exit codes (matching original sshpass):
 *   0 - success
 *   1 - invalid arguments
 *   2 - conflicting arguments
 *   3 - general runtime error
 *   4 - password source error
 *   5 - reserved
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

/* ========== WinPTY dynamic loading ========== */
typedef void *winpty_config_t;
typedef void *winpty_spawn_config_t;
typedef void *winpty_error_ptr_t;
typedef void *winpty_t;

typedef winpty_config_t *(*winpty_config_new_t)(DWORD, winpty_error_ptr_t *);
typedef void (*winpty_config_free_t)(winpty_config_t *);
typedef void (*winpty_config_set_initial_size_t)(winpty_config_t *, int, int);
typedef void (*winpty_config_set_agent_timeout_t)(winpty_config_t *, DWORD);
typedef winpty_t *(*winpty_open_t)(winpty_config_t *, winpty_error_ptr_t *);
typedef LPCWSTR (*winpty_conin_name_t)(winpty_t *);
typedef LPCWSTR (*winpty_conout_name_t)(winpty_t *);
typedef winpty_spawn_config_t *(*winpty_spawn_config_new_t)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, winpty_error_ptr_t *);
typedef void (*winpty_spawn_config_free_t)(winpty_spawn_config_t *);
typedef BOOL (*winpty_spawn_t)(winpty_t *, winpty_spawn_config_t *, HANDLE *, HANDLE *, DWORD *, winpty_error_ptr_t *);
typedef void (*winpty_free_t)(winpty_t *);
typedef HRESULT (*winpty_error_code_t)(winpty_error_ptr_t);
typedef LPCWSTR (*winpty_error_msg_t)(winpty_error_ptr_t);
typedef void (*winpty_error_free_t)(winpty_error_ptr_t);

static struct {
    HMODULE dll;
    winpty_config_new_t config_new;
    winpty_config_free_t config_free;
    winpty_config_set_initial_size_t config_set_initial_size;
    winpty_config_set_agent_timeout_t config_set_agent_timeout;
    winpty_open_t open;
    winpty_conin_name_t conin_name;
    winpty_conout_name_t conout_name;
    winpty_spawn_config_new_t spawn_config_new;
    winpty_spawn_config_free_t spawn_config_free;
    winpty_spawn_t spawn;
    winpty_free_t free;
    winpty_error_code_t error_code;
    winpty_error_msg_t error_msg;
    winpty_error_free_t error_free;
} wp;

#define WP_LOAD(name) do { \
    wp.name = (winpty_##name##_t)GetProcAddress(wp.dll, "winpty_" #name); \
    if (!wp.name) { vprint("winpty: " #name " not found"); return 0; } \
} while(0)

static int load_winpty(void) {
    const wchar_t *paths[] = {
        L"winpty.dll",
        L"/usr/bin/winpty.dll",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        wp.dll = LoadLibraryW(paths[i]);
        if (wp.dll) break;
    }
    if (!wp.dll) { vprint("winpty.dll not found"); return 0; }
    vprint("winpty.dll loaded");
    WP_LOAD(config_new);
    WP_LOAD(config_free);
    WP_LOAD(config_set_initial_size);
    WP_LOAD(config_set_agent_timeout);
    WP_LOAD(open);
    WP_LOAD(conin_name);
    WP_LOAD(conout_name);
    WP_LOAD(spawn_config_new);
    WP_LOAD(spawn_config_free);
    WP_LOAD(spawn);
    WP_LOAD(free);
    WP_LOAD(error_code);
    WP_LOAD(error_msg);
    WP_LOAD(error_free);
    return 1;
}

static void winpty_diag(const char *prefix, winpty_error_ptr_t err) {
    if (!err) return;
    LPCWSTR msg = wp.error_msg(err);
    vprint("%s: 0x%lx: %S", prefix, (unsigned long)wp.error_code(err), msg);
    wp.error_free(err);
}

/* ========== Resolve SSH to Windows native binary ========== */
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

/* ========== Spawn process (non-interactive, existing behaviour) ========== */
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

/* ========== Interactive mode: winpty + I/O forwarding ========== */

/* I/O forwarding thread: reads from hRead, writes to hWrite */
typedef struct {
    HANDLE hRead;
    HANDLE hWrite;
    volatile LONG *pDone;
} ForwardData;

static DWORD WINAPI forward_thread(LPVOID param) {
    ForwardData *fd = (ForwardData*)param;
    char buf[65536];
    DWORD nread;
    while (!*fd->pDone) {
        if (!ReadFile(fd->hRead, buf, sizeof(buf), &nread, NULL) || nread == 0)
            break;
        /* Write all bytes */
        DWORD total = 0, written;
        while (total < nread) {
            if (!WriteFile(fd->hWrite, buf + total, nread - total, &written, NULL))
                break;
            total += written;
        }
    }
    return 0;
}

static int run_interactive(const char *ssh_path, char *cmdline,
                           const char *pwd_file, const char *bat_file) {
    /* Load winpty */
    if (!load_winpty()) {
        fprintf(stderr, "sshpass: winpty.dll not found (required for -i mode)\n");
        return 3;
    }

    /* Set SSH_ASKPASS so the SSH process can read the password */
    SetEnvironmentVariableA("SSH_ASKPASS", bat_file);
    SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", "force");

    /* Create winpty config */
    winpty_error_ptr_t err = NULL;
    winpty_config_t *cfg = wp.config_new(0, &err);
    if (!cfg) { winpty_diag("config_new", err); return 3; }
    wp.config_set_initial_size(cfg, 160, 50);
    wp.config_set_agent_timeout(cfg, 20000);

    /* Open winpty */
    winpty_t *wp_handle = wp.open(cfg, &err);
    wp.config_free(cfg);
    if (!wp_handle) { winpty_diag("open", err); return 3; }
    vprint("winpty opened");

    /* Open conin (write to PTY = send input) */
    HANDLE hConIn = CreateFileW(wp.conin_name(wp_handle), GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    if (hConIn == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "sshpass: Failed to open PTY input\n");
        wp.free(wp_handle); return 3;
    }
    /* Open conout (read from PTY = receive output) */
    HANDLE hConOut = CreateFileW(wp.conout_name(wp_handle), GENERIC_READ,
                                 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hConOut == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "sshpass: Failed to open PTY output\n");
        CloseHandle(hConIn); wp.free(wp_handle); return 3;
    }
    vprint("PTY pipes opened (in=%p, out=%p)", hConIn, hConOut);

    /* Convert cmdline to wide for winpty */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, cmdline, -1, NULL, 0);
    wchar_t *wcmd = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, cmdline, -1, wcmd, wlen);

    /* Spawn SSH in winpty */
    winpty_spawn_config_t *scfg = wp.spawn_config_new(0, NULL, wcmd, NULL, NULL, &err);
    free(wcmd);
    if (!scfg) { winpty_diag("spawn_config_new", err); goto cleanup; }

    HANDLE hProcess;
    BOOL spawned = wp.spawn(wp_handle, scfg, &hProcess, NULL, NULL, &err);
    wp.spawn_config_free(scfg);
    if (!spawned) {
        winpty_diag("spawn", err);
        fprintf(stderr, "sshpass: Failed to spawn SSH in winpty\n");
        goto cleanup;
    }
    vprint("SSH spawned in winpty, PID=%lu", GetProcessId(hProcess));

    /* Start I/O forwarding threads */
    volatile LONG done = 0;
    ForwardData fd_out = { hConOut, GetStdHandle(STD_OUTPUT_HANDLE), &done };
    ForwardData fd_in  = { GetStdHandle(STD_INPUT_HANDLE), hConIn, &done };

    HANDLE hOutThread = CreateThread(NULL, 0, forward_thread, &fd_out, 0, NULL);
    HANDLE hInThread  = CreateThread(NULL, 0, forward_thread, &fd_in,  0, NULL);

    /* Wait for SSH to exit */
    WaitForSingleObject(hProcess, INFINITE);

    /* Signal threads to stop, cancel I/O to unblock */
    InterlockedExchange(&done, 1);
    CancelIo(hConOut);
    CancelIo(GetStdHandle(STD_INPUT_HANDLE));

    WaitForSingleObject(hOutThread, 3000);
    WaitForSingleObject(hInThread,  3000);
    CloseHandle(hOutThread);
    CloseHandle(hInThread);

    /* Capture exit code */
    DWORD ec = 0;
    GetExitCodeProcess(hProcess, &ec);
    vprint("process exited with code %lu", ec);

    CloseHandle(hProcess);
cleanup:
    CloseHandle(hConOut);
    CloseHandle(hConIn);
    wp.free(wp_handle);
    return (int)ec;
}

/* ========== Write raw data to a temp file ========== */
static int write_raw_file(const char *path, const char *data, int len) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD written;
    BOOL ok = WriteFile(h, data, (DWORD)len, &written, NULL);
    CloseHandle(h);
    return ok && (int)written == len;
}

/* ========== Print usage ========== */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-f|-d|-p|-e] [-ihV] command parameters\n"
        "   -f filename   Take password to use from file\n"
        "   -d number     Use number as file descriptor for password\n"
        "   -p password   Provide password as argument (security UNsafe)\n"
        "   -e            Password is passed via env var SSHPASS\n"
        "   -P prompt     Prompt string to look for (ignored, for compat)\n"
        "   -v            Be verbose\n"
        "   -i            Interactive mode (winpty PTY, bidirectional I/O)\n"
        "   -h            Show this help\n"
        "\n"
        "With no explicit password source (-p/-f/-d/-e), password is read\n"
        "from standard input.\n"
        "\n"
        "Exit codes: 0=OK  1=bad args  3=runtime  4=password source  6=auth fail\n",
        prog);
}

/* ========== Main ========== */
int main(int argc, char *argv[]) {
    char password[MAX_PASSWORD_LEN];
    int  password_len = 0;
    int  password_set = 0;
    int  cmd_start = 1;
    int  interactive = 0;

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
            /* Prompt string to match — ignored for SSH_ASKPASS */
            if (i + 1 < argc) i++;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-i") == 0) {
            interactive = 1;
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

    /* If no password source and no command, show usage */
    if (!password_set && cmd_start >= argc) {
        usage(argv[0]);
        return 1;
    }

    /* If password not set yet, read from stdin (trailing newline stripped) */
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

    /* ========== SSH_ASKPASS setup (shared by both modes) ========== */
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

    /* 3. Resolve SSH binary */
    const char *ssh_path = resolve_ssh(argv[cmd_start]);
    vprint("ssh binary: %s", ssh_path);

    /* 4. Build command line */
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

    /* 5. Run SSH */
    int rc;
    if (interactive) {
        rc = run_interactive(ssh_path, cmdline, pwd_file, bat_file);
    } else {
        /* Set SSH_ASKPASS for the non-interactive path */
        SetEnvironmentVariableA("SSH_ASKPASS", bat_file);
        SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", "force");
        if (g_verbose) {
            char buf[4096];
            GetEnvironmentVariableA("SSH_ASKPASS", buf, sizeof(buf));
            vprint("SSH_ASKPASS=%s", buf);
        }

        rc = run_proc(ssh_path, cmdline);
    }
    if (rc < 0) rc = 3;
    if (rc == 255) rc = 6;  /* map SSH auth failure to sshpass code 6 */

    /* 6. Cleanup temp files */
    free(cmdline);
    DeleteFileA(bat_file);
    DeleteFileA(pwd_file);

    return rc;
}
