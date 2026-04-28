/*
 * sshpass-win.c — SSH password automation for Windows
 * Feature-compatible with Unix sshpass.
 * Session-based interactive SSH for AI tool integration.
 *
 * Compile: gcc -O2 -o sshpass.exe sshpass-win.c /usr/lib/winpty.lib
 * Compile (no winpty, no -i mode): gcc -O2 -o sshpass.exe sshpass-win.c
 *
 * Exit codes (matching original sshpass):
 *   0 - success  1 - bad args  2 - conflict  3 - runtime  4 - password  6 - auth fail
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <io.h>
#include <fcntl.h>

#define MAX_PASSWORD_LEN 16384
#define MAX_SESS_NAME 64

static int g_verbose = 0;
static void vprint(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt); fputs("sshpass: ", stderr); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap);
}

/* =========================== WinPTY (only used by legacy -i mode) =========================== */
typedef void *winpty_config_t, *winpty_spawn_config_t, *winpty_error_ptr_t, *winpty_t;
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
    winpty_config_new_t config_new; winpty_config_free_t config_free;
    winpty_config_set_initial_size_t config_set_initial_size;
    winpty_config_set_agent_timeout_t config_set_agent_timeout;
    winpty_open_t open; winpty_conin_name_t conin_name; winpty_conout_name_t conout_name;
    winpty_spawn_config_new_t spawn_config_new; winpty_spawn_config_free_t spawn_config_free;
    winpty_spawn_t spawn; winpty_free_t free;
    winpty_error_code_t error_code; winpty_error_msg_t error_msg; winpty_error_free_t error_free;
} wp;

#define WP_LOAD(n) do { wp.n = (winpty_##n##_t)GetProcAddress(wp.dll, "winpty_"#n); if (!wp.n) return 0; } while(0)
static int load_winpty(void) {
    const wchar_t *p[] = {L"winpty.dll", L"/usr/bin/winpty.dll", NULL};
    for (int i=0; p[i]; i++) { wp.dll = LoadLibraryW(p[i]); if (wp.dll) break; }
    if (!wp.dll) return 0;
    WP_LOAD(config_new); WP_LOAD(config_free); WP_LOAD(config_set_initial_size);
    WP_LOAD(config_set_agent_timeout); WP_LOAD(open); WP_LOAD(conin_name);
    WP_LOAD(conout_name); WP_LOAD(spawn_config_new); WP_LOAD(spawn_config_free);
    WP_LOAD(spawn); WP_LOAD(free); WP_LOAD(error_code); WP_LOAD(error_msg); WP_LOAD(error_free);
    return 1;
}
static void wp_err(const char *pre, winpty_error_ptr_t e) {
    if (!e) return; LPCWSTR m = wp.error_msg(e); vprint("%s: 0x%lx: %S", pre, (unsigned long)wp.error_code(e), m); wp.error_free(e);
}

/* =========================== Utilities =========================== */
static const char *resolve_ssh(const char *cmd) {
    if (strcmp(cmd,"ssh") && strcmp(cmd,"ssh.exe")) return cmd;
    static char buf[MAX_PATH];
    const char *c[]={"C:\\Windows\\System32\\OpenSSH\\ssh.exe","C:\\Windows\\System32\\ssh.exe",NULL};
    for (int i=0;c[i];i++) { DWORD a=GetFileAttributesA(c[i]); if (a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)) { strcpy(buf,c[i]); return buf; }}
    return cmd;
}
static int write_file(const char *path, const char *data, int len) {
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (h==INVALID_HANDLE_VALUE) return 0;
    DWORD w; BOOL ok=WriteFile(h,data,(DWORD)len,&w,NULL); CloseHandle(h);
    return ok && (int)w==len;
}
static void mkdirs(const char *path) {
    char tmp[MAX_PATH]; strncpy(tmp,path,MAX_PATH-1);
    for (char *p=tmp+3; *p; p++) if (*p=='\\') { *p='\0'; CreateDirectoryA(tmp,NULL); *p='\\'; }
    CreateDirectoryA(tmp,NULL);
}

/* =========================== Session Info =========================== */
typedef struct {
    char name[MAX_SESS_NAME], sess_dir[MAX_PATH];
    char askpass_bat[MAX_PATH], askpass_pwd[MAX_PATH];
    char ssh_cmdline[4096], ssh_path[MAX_PATH], pipe_name[MAX_PATH];
    int winpty_cols, winpty_rows, idle_timeout_ms;
    DWORD daemon_pid;
} SessionInfo;

static void get_sdir(char *buf, int sz) {
    if (GetEnvironmentVariableA("SSHPASS_SESSION_DIR", buf, sz) > 0) return;
    char h[MAX_PATH]; GetEnvironmentVariableA("USERPROFILE", h, sizeof(h));
    _snprintf(buf, sz, "%s\\.sshpass-sessions", h);
}
static void s_path(const char *name, char *buf, int sz, const char *sub) {
    char d[MAX_PATH]; get_sdir(d,sizeof(d));
    if (sub) _snprintf(buf,sz,"%s\\%s\\%s",d,name,sub); else _snprintf(buf,sz,"%s\\%s",d,name);
}
static int sess_save(const SessionInfo *info) {
    char path[MAX_PATH]; _snprintf(path,sizeof(path),"%s\\session.dat",info->sess_dir);
    FILE *f=fopen(path,"w"); if (!f) return 0;
    fprintf(f,"name=%s\nsess_dir=%s\naskpass_bat=%s\naskpass_pwd=%s\n",info->name,info->sess_dir,info->askpass_bat,info->askpass_pwd);
    fprintf(f,"ssh_cmdline=%s\nssh_path=%s\npipe_name=%s\n",info->ssh_cmdline,info->ssh_path,info->pipe_name);
    fprintf(f,"winpty_cols=%d\nwinpty_rows=%d\nidle_timeout_ms=%d\ndaemon_pid=%lu\n",info->winpty_cols,info->winpty_rows,info->idle_timeout_ms,info->daemon_pid);
    fclose(f); return 1;
}
static int sess_load(const char *name, SessionInfo *info) {
    memset(info,0,sizeof(*info)); strncpy(info->name,name,MAX_SESS_NAME-1);
    info->winpty_cols=160; info->winpty_rows=50; info->idle_timeout_ms=1500;
    char path[MAX_PATH]; s_path(name,path,sizeof(path),"session.dat");
    strncpy(info->sess_dir,path,MAX_PATH-1); char *p=strrchr(info->sess_dir,'\\'); if(p)*p='\0';
    FILE *f=fopen(path,"r"); if (!f) return 0;
    char l[4096];
    while (fgets(l,sizeof(l),f)) {
        char *eq=strchr(l,'='); if (!eq) continue;
        *eq++='\0'; char *v=eq; int vl=(int)strlen(v); while (vl>0&&(v[vl-1]=='\n'||v[vl-1]=='\r')) v[--vl]='\0';
        if (strcmp("sess_dir",l)==0) strncpy(info->sess_dir,v,MAX_PATH-1);
        else if (strcmp("askpass_bat",l)==0) strncpy(info->askpass_bat,v,MAX_PATH-1);
        else if (strcmp("askpass_pwd",l)==0) strncpy(info->askpass_pwd,v,MAX_PATH-1);
        else if (strcmp("ssh_cmdline",l)==0) strncpy(info->ssh_cmdline,v,sizeof(info->ssh_cmdline)-1);
        else if (strcmp("ssh_path",l)==0) strncpy(info->ssh_path,v,MAX_PATH-1);
        else if (strcmp("pipe_name",l)==0) strncpy(info->pipe_name,v,MAX_PATH-1);
        else if (strcmp("winpty_cols",l)==0) info->winpty_cols=atoi(v);
        else if (strcmp("winpty_rows",l)==0) info->winpty_rows=atoi(v);
        else if (strcmp("idle_timeout_ms",l)==0) info->idle_timeout_ms=atoi(v);
        else if (strcmp("daemon_pid",l)==0) info->daemon_pid=(DWORD)atol(v);
    }
    fclose(f); return 1;
}
static void sess_del(const char *name) {
    SessionInfo tmp;
    if (sess_load(name,&tmp)) { char p[MAX_PATH]; _snprintf(p,sizeof(p),"%s\\session.dat",tmp.sess_dir); DeleteFileA(p); RemoveDirectoryA(tmp.sess_dir); }
}

/* =========================== Session Daemon (pipe-based, no winpty) =========================== */
/* Uses SSH_ASKPASS for auth (no local TTY, SSH uses the askpass program).
 * We add -tt to force a remote PTY for interactive command responses. */

static int read_to_idle(HANDLE h, char *buf, int sz, DWORD ms) {
    int t=0; DWORD start=GetTickCount();
    while (t<sz-1) { DWORD n=0;
        if (!PeekNamedPipe(h,NULL,0,NULL,&n,NULL)) break;
        if (n>0) { DWORD nr; if(!ReadFile(h,buf+t,(sz-1-t<(int)n)?sz-1-t:n,&nr,NULL)||nr==0)break; t+=nr; start=GetTickCount(); }
        else { if(GetTickCount()-start>=ms)break; Sleep(50); }
    } buf[t]='\0'; return t;
}

static int session_daemon(const char *name) {
    SessionInfo inf;
    if (!sess_load(name,&inf)) { fprintf(stderr,"sshpass: session '%s' not found\n",name); return 1; }
    vprint("daemon starting", name);

    /* Build cmd with -tt inserted after ssh binary (force remote PTY) */
    char cmd[8192]; const char *s=inf.ssh_cmdline;
    while(*s==' ')s++; /* skip leading spaces */
    /* Copy binary path */
    const char *end=s; while(*end&&*end!=' ')end++;
    int has_space = 0; for(const char *ch=s; ch<end; ch++) if(*ch==' ') { has_space=1; break; }
    int bcmd=0; cmd[bcmd]=0;
    if(has_space) cmd[bcmd]='"';
    {int i=0;while(s+i<end){cmd[bcmd++] = s[i++];}}
    if(has_space) cmd[bcmd++]='"';
    cmd[bcmd]='\0';
    /* Add -tt */
    int ttlen = (int)strlen(cmd);
    strcat(cmd," -tt");
    bcmd = (int)strlen(cmd);
    /* Copy remaining args */
    while(*end == ' ') end++; /* skip leading space */
    cmd[bcmd++] = ' '; /* add a space before the remaining args */
    while(*end)cmd[bcmd++]=*end++;
    cmd[bcmd]='\0';
    vprint("ssh cmd: %s", cmd);
    vprint("askpass: %s", inf.askpass_bat);

    /* Create pipes */
    HANDLE hInR, hInW, hOutR, hOutW;
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    if(!CreatePipe(&hInR,&hInW,&sa,0)||!CreatePipe(&hOutR,&hOutW,&sa,0)) return 3;
    SetHandleInformation(hInW,HANDLE_FLAG_INHERIT,0); SetHandleInformation(hOutR,HANDLE_FLAG_INHERIT,0);

    /* Set environment variables for SSH (inherited by child process) */
    SetEnvironmentVariableA("SSH_ASKPASS", inf.askpass_bat);
    SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", "force");

    /* Spawn SSH (inherit full environment) */
    STARTUPINFOA si={0}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdInput=hInR; si.hStdOutput=hOutW; si.hStdError=hOutW;
    PROCESS_INFORMATION pi={0};
    /* CREATE_NO_WINDOW: SSH uses SSH_ASKPASS so it doesn't need a console at all.
     * This avoids flashing a terminal window. */
    if(!CreateProcessA(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) {
        fprintf(stderr,"sshpass: CreateProcess failed (%lu)\n",GetLastError());
        CloseHandle(hInR);CloseHandle(hInW);CloseHandle(hOutR);CloseHandle(hOutW); return 3;
    }
    CloseHandle(hInR); CloseHandle(hOutW);
    vprint("SSH PID=%lu", pi.dwProcessId);

    /* Read initial SSH output (password handled automatically via SSH_ASKPASS) */
    char buf[16384]; int init_len = read_to_idle(hOutR,buf,sizeof(buf),4000);
    vprint("initial read: %d bytes", init_len);

    /* Create named pipe */
    char pn[MAX_PATH]; _snprintf(pn,sizeof(pn),"\\\\.\\pipe\\sshpass-%s-cmd",name);
    strncpy(inf.pipe_name,pn,MAX_PATH-1); sess_save(&inf);

    HANDLE hPipe=CreateNamedPipeA(pn,PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,PIPE_UNLIMITED_INSTANCES,131072,131072,0,NULL);
    if (hPipe==INVALID_HANDLE_VALUE) { fprintf(stderr,"sshpass: pipe failed (%lu)\n",GetLastError()); return 3; }

    fprintf(stderr,"Session '%s' ready\n", name);

    /* Command loop */
    char c[16384], r[131072];
    int done=0;
    while (!done) {
        BOOL cn=ConnectNamedPipe(hPipe,NULL);
        if(!cn&&GetLastError()!=ERROR_PIPE_CONNECTED){if(GetLastError()==ERROR_NO_DATA)continue;break;}
        DWORD nr=0;
        if(!ReadFile(hPipe,c,sizeof(c)-1,&nr,NULL)||nr==0){DisconnectNamedPipe(hPipe);continue;}
        c[nr]='\0';
        if(strcmp(c,"__exit__")==0){done=1;DisconnectNamedPipe(hPipe);break;}
        if(strcmp(c,"__ping__")==0){DWORD w;WriteFile(hPipe,"__pong__",8,&w,NULL);DisconnectNamedPipe(hPipe);continue;}

        WriteFile(hInW,c,(DWORD)strlen(c),&nr,NULL);
        if(c[strlen(c)-1]!='\n') WriteFile(hInW,"\n",1,&nr,NULL);

        int rl=read_to_idle(hOutR,r,sizeof(r),(DWORD)inf.idle_timeout_ms);
        if(rl>0){DWORD w;WriteFile(hPipe,r,(DWORD)rl,&w,NULL);}
        else { DWORD ec; if(!GetExitCodeProcess(pi.hProcess,&ec)||ec!=STILL_ACTIVE){done=1;DisconnectNamedPipe(hPipe);break;} }

        FlushFileBuffers(hPipe); DisconnectNamedPipe(hPipe);
    }
    CloseHandle(hPipe);
    WriteFile(hInW,"exit\n",5,&(DWORD){0},NULL);
    WaitForSingleObject(pi.hProcess,3000); TerminateProcess(pi.hProcess,0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hInW); CloseHandle(hOutR);
    vprint("session done");
    return 0;
}

/* =========================== Session Start =========================== */
static int session_start(const char *name, const char *pwd, int pwd_len, int cmd_start, int argc, char *argv[]) {
    if (!name[0]||strlen(name)>=MAX_SESS_NAME) { fprintf(stderr,"sshpass: invalid session name\n"); return 1; }
    for (const char *c=name;*c;c++) if (!isalnum(*c)&&*c!='-'&&*c!='_') { fprintf(stderr,"sshpass: session name: a-z, 0-9, -, _\n"); return 1; }
    SessionInfo old; if (sess_load(name,&old)) { fprintf(stderr,"sshpass: session '%s' exists\n",name); return 2; }

    const char *ssh_path=resolve_ssh(argv[cmd_start]);
    char *cmdline=(char*)malloc(4096); if(!cmdline)return 3; cmdline[0]='\0';
    for (int i=cmd_start;i<argc;i++) {
        const char *a=(i==cmd_start)?ssh_path:argv[i];
        if(i>cmd_start)strcat(cmdline," "); if(strchr(a,' ')){strcat(cmdline,"\"");strcat(cmdline,a);strcat(cmdline,"\"");}else strcat(cmdline,a);
    }

    char sdir[MAX_PATH]; s_path(name,sdir,sizeof(sdir),NULL); mkdirs(sdir);
    char tmpdir[MAX_PATH]; GetTempPathA(MAX_PATH,tmpdir);
    char pf[MAX_PATH],bf[MAX_PATH];
    if(!GetTempFileNameA(tmpdir,"spp",0,pf)){free(cmdline);return 3;}
    if(!write_file(pf,pwd,pwd_len)){DeleteFileA(pf);free(cmdline);return 3;}
    if(!GetTempFileNameA(tmpdir,"spb",0,bf)){DeleteFileA(pf);free(cmdline);return 3;}
    int bl=(int)strlen(bf);if(bl>4)strcpy(bf+bl-4,".bat");
    FILE*f=fopen(bf,"w");if(!f){DeleteFileA(pf);DeleteFileA(bf);free(cmdline);return 3;}
    fprintf(f,"@type \"%s\"\r\n",pf);fclose(f);

    SessionInfo info; memset(&info,0,sizeof(info));
    strncpy(info.name,name,MAX_SESS_NAME-1); strncpy(info.sess_dir,sdir,MAX_PATH-1);
    strncpy(info.askpass_bat,bf,MAX_PATH-1); strncpy(info.askpass_pwd,pf,MAX_PATH-1);
    strncpy(info.ssh_cmdline,cmdline,sizeof(info.ssh_cmdline)-1); strncpy(info.ssh_path,ssh_path,MAX_PATH-1);
    info.winpty_cols=160; info.winpty_rows=50; info.idle_timeout_ms=1500; info.daemon_pid=GetCurrentProcessId();
    if(!sess_save(&info)){fprintf(stderr,"sshpass: save failed\n");DeleteFileA(pf);DeleteFileA(bf);free(cmdline);return 3;}
    free(cmdline);

    int rc=session_daemon(name);
    sess_del(name); DeleteFileA(pf); DeleteFileA(bf);
    return rc;
}

/* =========================== Session Send =========================== */
static int session_send(const char *name, const char *cmd, int timeout_ms) {
    (void)timeout_ms;
    SessionInfo inf; if(!sess_load(name,&inf)){fprintf(stderr,"sshpass: session '%s' not found\n",name);return 1;}
    char pn[MAX_PATH]; _snprintf(pn,sizeof(pn),"\\\\.\\pipe\\sshpass-%s-cmd",name);
    HANDLE hPipe=CreateFileA(pn,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(hPipe==INVALID_HANDLE_VALUE){fprintf(stderr,"sshpass: cannot connect to '%s' (%lu)\n",name,GetLastError());return 3;}
    DWORD cl=(DWORD)strlen(cmd),w;
    WriteFile(hPipe,cmd,cl,&w,NULL);
    char buf[131072]; DWORD nr; HANDLE hOut=GetStdHandle(STD_OUTPUT_HANDLE);
    while(ReadFile(hPipe,buf,sizeof(buf),&nr,NULL)&&nr>0){DWORD wo;WriteFile(hOut,buf,nr,&wo,NULL);}
    CloseHandle(hPipe);
    return 0;
}

/* =========================== Session Close =========================== */
static int session_close(const char *name) {
    SessionInfo inf;
    if (!sess_load(name,&inf)) { fprintf(stderr,"sshpass: session '%s' not found\n",name); return 1; }
    char pn[MAX_PATH]; _snprintf(pn,sizeof(pn),"\\\\.\\pipe\\sshpass-%s-cmd",name);
    HANDLE hPipe=CreateFileA(pn,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if (hPipe!=INVALID_HANDLE_VALUE) { DWORD w; WriteFile(hPipe,"__exit__",8,&w,NULL); CloseHandle(hPipe); }
    else sess_del(name);
    fprintf(stderr,"Session '%s' closing\n",name);
    return 0;
}

/* =========================== Session List =========================== */
static int session_list(void) {
    char d[MAX_PATH]; get_sdir(d,sizeof(d));
    WIN32_FIND_DATAA fd; char s[MAX_PATH]; _snprintf(s,sizeof(s),"%s\\*",d);
    HANDLE h=FindFirstFileA(s,&fd);
    if(h==INVALID_HANDLE_VALUE){printf("No active sessions.\n");return 0;}
    printf("%-20s %s\n","NAME","STATUS");
    do {
        if(!(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||!strcmp(fd.cFileName,".")||!strcmp(fd.cFileName,".."))continue;
        SessionInfo inf;
        if(sess_load(fd.cFileName,&inf)) printf("%-20s alive\n",inf.name);
        else printf("%-20s orphaned\n",fd.cFileName);
    } while(FindNextFileA(h,&fd));
    FindClose(h);
    return 0;
}

/* =========================== Legacy: run SSH via SSH_ASKPASS =========================== */
static int run_proc(const char *app, char *cmdline) {
    STARTUPINFOA si={0}; si.cb=sizeof(si);
    PROCESS_INFORMATION pi={0};
    if (!CreateProcessA(app,cmdline,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi)) {
        fprintf(stderr,"sshpass: Failed to start process (%lu)\n",GetLastError()); return -1;
    }
    vprint("PID=%lu",pi.dwProcessId);
    WaitForSingleObject(pi.hProcess,INFINITE);
    DWORD ec=0; GetExitCodeProcess(pi.hProcess,&ec);
    vprint("exit code %lu",ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)ec;
}

/* =========================== Legacy: interactive winpty (-i) =========================== */
typedef struct { HANDLE r,w; volatile LONG *d; } FD;
static DWORD WINAPI fwd_io(LPVOID p) {
    FD *f=(FD*)p; char b[65536]; DWORD n;
    while (!*f->d) { if (!ReadFile(f->r,b,sizeof(b),&n,NULL)||n==0) break; DWORD t=0,w; while(t<n){if(!WriteFile(f->w,b+t,n-t,&w,NULL))break;t+=w;}}
    return 0;
}
static int run_interactive(const char *ssh, char *cmd, const char *bat) {
    if (!load_winpty()) { fprintf(stderr,"sshpass: winpty.dll not found\n"); return 3; }
    char eb[4096]; int el=0;
    {const char*ev[]={"SSH_ASKPASS",bat,"SSH_ASKPASS_REQUIRE","force",NULL}; for(int i=0;ev[i];i+=2){int n=_snprintf(eb+el,sizeof(eb)-el,"%s=%s",ev[i],ev[i+1]);if(n>0){el+=n;eb[el++]='\0';}} eb[el++]='\0';}
    wchar_t *we=NULL; int wl=MultiByteToWideChar(CP_UTF8,0,eb,el,NULL,0);
    if(wl>0){we=(wchar_t*)malloc(wl*sizeof(wchar_t));MultiByteToWideChar(CP_UTF8,0,eb,el,we,wl);}

    winpty_error_ptr_t e=NULL;
    winpty_config_t *c=wp.config_new(0,&e); if(!c){free(we);return 3;}
    wp.config_set_initial_size(c,160,50); wp.config_set_agent_timeout(c,20000);
    winpty_t *w=wp.open(c,&e); wp.config_free(c); if(!w){free(we);return 3;}
    HANDLE hi=CreateFileW(wp.conin_name(w),GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    HANDLE ho=CreateFileW(wp.conout_name(w),GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(hi==INVALID_HANDLE_VALUE||ho==INVALID_HANDLE_VALUE){if(hi!=INVALID_HANDLE_VALUE)CloseHandle(hi);if(ho!=INVALID_HANDLE_VALUE)CloseHandle(ho);wp.free(w);free(we);return 3;}
    int wlen=MultiByteToWideChar(CP_UTF8,0,cmd,-1,NULL,0);
    wchar_t *wc=(wchar_t*)malloc(wlen*sizeof(wchar_t)); MultiByteToWideChar(CP_UTF8,0,cmd,-1,wc,wlen);
    winpty_spawn_config_t *sc=wp.spawn_config_new(0,NULL,wc,NULL,we,&e); free(wc); if(!sc){CloseHandle(hi);CloseHandle(ho);wp.free(w);free(we);return 3;}
    HANDLE hp; BOOL ok=wp.spawn(w,sc,&hp,NULL,NULL,&e); wp.spawn_config_free(sc); free(we); if(!ok){CloseHandle(hi);CloseHandle(ho);wp.free(w);return 3;}
    volatile LONG done=0;
    FD fo={ho,GetStdHandle(STD_OUTPUT_HANDLE),&done}, fi={GetStdHandle(STD_INPUT_HANDLE),hi,&done};
    HANDLE ht[2]; ht[0]=CreateThread(NULL,0,fwd_io,&fo,0,NULL); ht[1]=CreateThread(NULL,0,fwd_io,&fi,0,NULL);
    WaitForSingleObject(hp,INFINITE); InterlockedExchange(&done,1); CancelIo(ho); CancelIo(GetStdHandle(STD_INPUT_HANDLE));
    WaitForSingleObject(ht[0],3000); WaitForSingleObject(ht[1],3000); CloseHandle(ht[0]); CloseHandle(ht[1]);
    DWORD ec=0; GetExitCodeProcess(hp,&ec); CloseHandle(hp); CloseHandle(hi); CloseHandle(ho); wp.free(w);
    return (int)ec;
}

/* =========================== Usage =========================== */
static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [-f|-d|-p|-e] [-ihV] command\n"
        "       %s --session-start <name> [-p <pass>] ssh <args...>\n"
        "       %s --session-send <name> [command...]\n"
        "       %s --session-close <name>\n"
        "       %s --session-list\n\n"
        "Password: -f file  -d fd  -p pass  -e (env SSHPASS)\n"
        "Other: -P (ignored)  -v verbose  -i interactive  -h help\n\n"
        "Sessions:\n"
        "  --session-start  Start persistent SSH session (foreground, use &)\n"
        "  --session-send   Send command, print output, exit\n"
        "  --session-close  Close session\n"
        "  --session-list   List sessions\n\n"
        "Exit codes: 0=OK  1=bad args  2=conflict  3=runtime  4=password  6=auth fail\n",
        p,p,p,p,p);
}

/* =========================== Main =========================== */
int main(int argc, char *argv[]) {
    if (argc<2) { usage(argv[0]); return 1; }

    /* Normalize: move --session-* to argv[1-2] */
    for (int i=1; i<argc; i++) {
        int is = argv[i][0]=='-' && argv[i][1]=='-' && (
            strcmp(argv[i],"--session-start")==0 || strcmp(argv[i],"--session-daemon")==0 ||
            strcmp(argv[i],"--session-send")==0 || strcmp(argv[i],"--session-close")==0 ||
            strcmp(argv[i],"--session-list")==0);
        if (!is) continue;
        if (i!=1) { char *t=argv[1]; argv[1]=argv[i]; argv[i]=t;
            int nn=strcmp(argv[1],"--session-start")==0||strcmp(argv[1],"--session-daemon")==0
                   ||strcmp(argv[1],"--session-send")==0||strcmp(argv[1],"--session-close")==0;
            if (nn && i+1<argc) { char *t2=argv[2]; argv[2]=argv[i+1]; argv[i+1]=t2; }
        }
        break;
    }

    /* ---- Session commands ---- */
    if (strcmp(argv[1],"--session-start")==0) {
        if (argc<4) { fprintf(stderr,"Usage: sshpass --session-start <name> -p <pass> ssh ...\n"); return 1; }
        const char *sn=argv[2]; char pw[MAX_PASSWORD_LEN]; int pw_len=0,pw_set=0;
        for (int i=3; i<argc; i++) {
            if(strcmp(argv[i],"-p")==0&&i+1<argc){const char*s=argv[i+1];pw_len=(int)strlen(s);if(pw_len>=MAX_PASSWORD_LEN){fprintf(stderr,"pw too long\n");return 1;}memcpy(pw,s,pw_len+1);pw_set=1;memmove(&argv[i],&argv[i+2],(argc-i-1)*sizeof(char*));argc-=2;i=2;}
            else if(strcmp(argv[i],"-e")==0){const char*e=getenv("SSHPASS");if(!e){fprintf(stderr,"SSHPASS not set\n");return 1;}pw_len=(int)strlen(e);if(pw_len>=MAX_PASSWORD_LEN){fprintf(stderr,"pw too long\n");return 1;}memcpy(pw,e,pw_len+1);pw_set=1;memmove(&argv[i],&argv[i+1],(argc-i)*sizeof(char*));argc--;i=2;}
            else if(strcmp(argv[i],"-v")==0){g_verbose=1;memmove(&argv[i],&argv[i+1],(argc-i)*sizeof(char*));argc--;i=2;}
            else break;
        }
        if(!pw_set){fprintf(stderr,"sshpass: --session-start needs -p or -e\n");return 1;}
        if(3>=argc){fprintf(stderr,"sshpass: --session-start needs SSH command\n");return 1;}
        return session_start(sn,pw,pw_len,3,argc,argv);
    }
    if(strcmp(argv[1],"--session-send")==0) {
        if(argc<3){fprintf(stderr,"Usage: sshpass --session-send <name> [command]\n");return 1;}
        const char *sn=argv[2];
        if(argc>=4){int l=0;for(int i=3;i<argc;i++)l+=(int)strlen(argv[i])+1;char*c=(char*)malloc(l+1);c[0]='\0';for(int i=3;i<argc;i++){if(i>3)strcat(c," ");strcat(c,argv[i]);}int r=session_send(sn,c,1500);free(c);return r;}
        else {char c[65536];int t=0;while(t<(int)sizeof(c)-1){int ch=getchar();if(ch==EOF)break;c[t++]=(char)ch;}c[t]='\0';while(t>0&&(c[t-1]=='\n'||c[t-1]=='\r'))c[--t]='\0';return session_send(sn,c,1500);}
    }
    if(strcmp(argv[1],"--session-close")==0){if(argc<3){fprintf(stderr,"Usage: sshpass --session-close <name>\n");return 1;}return session_close(argv[2]);}
    if(strcmp(argv[1],"--session-list")==0){return session_list();}
    if(strcmp(argv[1],"--session-daemon")==0){if(argc<3){fprintf(stderr,"Usage: sshpass --session-daemon <name>\n");return 1;}return session_daemon(argv[2]);}

    /* ---- Legacy mode ---- */
    char password[MAX_PASSWORD_LEN]; int pw_len=0, pw_set=0, cmd_start=1, interactive=0;
    for (int i=1; i<argc; i++) {
        if(strcmp(argv[i],"-p")==0){if(i+1>=argc){fprintf(stderr,"-p needs arg\n");return 1;}const char*s=argv[i+1];pw_len=(int)strlen(s);if(pw_len>=MAX_PASSWORD_LEN){fprintf(stderr,"pw too long\n");return 1;}memcpy(password,s,pw_len+1);pw_set=1;cmd_start=i+2;i++;}
        else if(strcmp(argv[i],"-f")==0){if(i+1>=argc){fprintf(stderr,"-f needs arg\n");return 1;}FILE*fp=fopen(argv[i+1],"rb");if(!fp){fprintf(stderr,"Cannot open %s\n",argv[i+1]);return 4;}pw_len=(int)fread(password,1,MAX_PASSWORD_LEN-1,fp);fclose(fp);while(pw_len>0&&(password[pw_len-1]=='\n'||password[pw_len-1]=='\r'))pw_len--;password[pw_len]='\0';pw_set=1;cmd_start=i+2;i++;}
        else if(strcmp(argv[i],"-d")==0){if(i+1>=argc){fprintf(stderr,"-d needs arg\n");return 1;}int fd=atoi(argv[i+1]);int n=(int)_read(fd,password,MAX_PASSWORD_LEN-1);if(n<=0){fprintf(stderr,"read fd %d failed\n",fd);return 4;}pw_len=n;while(pw_len>0&&(password[pw_len-1]=='\n'||password[pw_len-1]=='\r'))pw_len--;password[pw_len]='\0';pw_set=1;cmd_start=i+2;i++;}
        else if(strcmp(argv[i],"-e")==0){const char*e=getenv("SSHPASS");if(!e){fprintf(stderr,"SSHPASS not set\n");return 1;}pw_len=(int)strlen(e);if(pw_len>=MAX_PASSWORD_LEN){fprintf(stderr,"pw too long\n");return 1;}memcpy(password,e,pw_len+1);pw_set=1;cmd_start=i+1;}
        else if(strcmp(argv[i],"-P")==0){if(i+1<argc)i++;}
        else if(strcmp(argv[i],"-v")==0){g_verbose=1;}
        else if(strcmp(argv[i],"-i")==0){interactive=1;}
        else if(strcmp(argv[i],"-h")==0||strcmp(argv[i],"--help")==0){usage(argv[0]);return 0;}
        else if(argv[i][0]=='-'&&argv[i][1]){fprintf(stderr,"sshpass: Unknown option: %s\n",argv[i]);return 1;}
        else break;
    }
    if (!pw_set && cmd_start>=argc) { usage(argv[0]); return 1; }
    if (!pw_set) { int t=0; while(t<MAX_PASSWORD_LEN-1){int c=getchar();if(c==EOF||c=='\n')break;password[t++]=(char)c;} password[t]='\0'; pw_len=t; pw_set=1; }

    char tmpdir[MAX_PATH]; GetTempPathA(MAX_PATH,tmpdir);
    char pf[MAX_PATH],bf[MAX_PATH];
    if(!GetTempFileNameA(tmpdir,"spp",0,pf))return 3;
    if(!write_file(pf,password,pw_len)){DeleteFileA(pf);return 3;}
    if(!GetTempFileNameA(tmpdir,"spb",0,bf)){DeleteFileA(pf);return 3;}
    int bl=(int)strlen(bf);if(bl>4)strcpy(bf+bl-4,".bat");
    FILE*f=fopen(bf,"w");if(!f){DeleteFileA(pf);DeleteFileA(bf);return 3;}
    fprintf(f,"@type \"%s\"\r\n",pf);fclose(f);

    const char *ssh=resolve_ssh(argv[cmd_start]);
    char *cmdline=(char*)malloc(4096);if(!cmdline){DeleteFileA(pf);DeleteFileA(bf);return 3;} cmdline[0]='\0';
    for(int i=cmd_start;i<argc;i++){const char*a=(i==cmd_start)?ssh:argv[i];if(i>cmd_start)strcat(cmdline," ");if(strchr(a,' ')){strcat(cmdline,"\"");strcat(cmdline,a);strcat(cmdline,"\"");}else strcat(cmdline,a);}

    int rc;
    if(interactive){SetEnvironmentVariableA("SSH_ASKPASS",bf);SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE","force");rc=run_interactive(ssh,cmdline,bf);}
    else{SetEnvironmentVariableA("SSH_ASKPASS",bf);SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE","force");rc=run_proc(ssh,cmdline);}
    if(rc<0)rc=3;if(rc==255)rc=6;
    free(cmdline); DeleteFileA(bf); DeleteFileA(pf);
    return rc;
}
