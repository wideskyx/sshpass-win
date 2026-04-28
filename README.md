# sshpass-win

Windows 版 sshpass — SSH 密码认证工具，支持非交互式和交互式模式。

功能完全兼容 Unix [sshpass](https://sourceforge.net/projects/sshpass/)，让 Windows 用户也能在脚本和自动化中安全地使用 SSH 密码认证。

## 特性

- 与原版 sshpass 命令行完全兼容（`-p`, `-f`, `-d`, `-e`, `-P`, `-v` 等）
- 非交互模式：利用 Windows 原生 OpenSSH 的 SSH_ASKPASS 机制，无需虚拟终端
- 交互模式（`-i`）：基于 winpty 提供完整 PTY，支持 AI 工具驱动交互式会话
- 自动检测并使用 `C:\Windows\System32\OpenSSH\ssh.exe`
- 支持从 stdin 读取密码
- 退出码与原版 sshpass 兼容（0/1/3/4/6）
- 单文件可执行程序

## 安装

从 [Releases](../../releases) 页面下载 `sshpass.exe`，放到 `PATH` 目录中即可。

或从源码编译（交互模式需要 winpty.dll）：

```bash
gcc -O2 -o sshpass.exe sshpass-win.c /usr/lib/winpty.lib
```

**要求**：Windows 10+，已安装 OpenSSH 客户端（Windows 10 1803+ 已内置）。
交互模式需要 [winpty](https://github.com/rprichard/winpty)。

## 使用方法

```bash
# 密码作为命令行参数
sshpass -p <password> ssh user@host command

# 从文件读取密码（首行）
sshpass -f /path/to/password.txt ssh user@host command

# 从环境变量读取
export SSHPASS=<password>
sshpass -e ssh user@host command

# 从 stdin 读取密码（不带 -p/-f/-d/-e）
echo <password> | sshpass ssh user@host command

# 从文件描述符读取
sshpass -d 3 ssh user@host command 3<password.txt

# 交互模式（winpty PTY，适用于 AI 工具调用）
echo "whoami
hostname
exit" | sshpass -i -p <password> ssh -t user@host

# 详细输出
sshpass -v -p <password> ssh user@host command
```

## 交互模式（-i）

`-i` 模式通过 winpty 创建本地 PTY，让 SSH 在完整终端环境中运行：

- **AI 工具集成**：通过管道发送命令、读取输出，支持长会话
- **完整 PTY 行为**：支持 `sudo`、`top` 等需要 TTY 的程序
- **双向 I/O 转发**：stdin 映射到 PTY 输入，PTY 输出映射到 stdout

典型用例（AI 工具连续交互）：

```bash
# 建立会话，执行多个命令
{
  echo "cd /var/log"
  echo "tail -5 syslog"
  echo "exit"
} | sshpass -i -p <password> ssh -t user@host
```

## 与原版 sshpass 的差异

| 功能 | 原版 | sshpass-win |
|------|:----:|:-----------:|
| `-p <password>` | ✅ | ✅ |
| `-f <file>` | ✅ | ✅ |
| `-d <fd>` | ✅ | ⚠️ |
| `-e` | ✅ | ✅ |
| stdin 输入 | ✅ | ✅ |
| `-P <prompt>` | ✅ | ✅（忽略） |
| `-v` | ✅ | ✅ |
| 退出码兼容 | ✅ | ✅ |
| 交互模式（`-i`） | ❌ | ✅ winpty PTY |
| 非 SSH 工具 | ✅ | ❌ 仅支持 SSH |

- `-d` 从原生 Windows 进程（cmd/PowerShell）启动时正常工作；从 MSYS2/Git Bash 启动时受限于 fd 表隔离，可能不可用。
- `-P` 参数接受但不会检查提示内容，因为密码通过 SSH_ASKPASS 传递，不需要匹配屏幕输出。

## 工作原理

1. 将密码写入临时文件
2. 创建批处理脚本输出该文件内容
3. 设置 `SSH_ASKPASS` 和 `SSH_ASKPASS_REQUIRE=force` 环境变量
4. **非交互模式**：启动 SSH，SSH 自动调用脚本获取密码 → 执行命令 → 退出
5. **交互模式**（`-i`）：在 winpty PTY 中启动 SSH，自动完成密码验证，然后双向转发 I/O
6. 执行完成后清理临时文件

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。
