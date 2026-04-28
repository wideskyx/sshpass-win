# sshpass-win

Windows 版 sshpass — 非交互式 SSH 密码认证工具。

功能完全兼容 Unix [sshpass](https://sourceforge.net/projects/sshpass/)，让 Windows 用户也能在脚本和自动化中安全地使用 SSH 密码认证。

## 特性

- 与原版 sshpass 命令行兼容（`-p`, `-f`, `-d`, `-e`）
- 利用 Windows 原生 OpenSSH 的 SSH_ASKPASS 机制，无需虚拟终端
- 自动检测并使用 `C:\Windows\System32\OpenSSH\ssh.exe`
- 支持从 stdin 读取密码
- 单文件可执行程序，零依赖

## 安装

从 [Releases](../../releases) 页面下载 `sshpass.exe`，放到 `PATH` 中即可。

或从源码编译：

```bash
gcc -O2 -o sshpass.exe sshpass-win.c
```

**要求**：Windows 10+，已安装 OpenSSH 客户端（Windows 10 1803+ 已内置）。

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

# 详细输出
sshpass -v -p <password> ssh user@host command
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
| 非 SSH 工具 | ✅ | ❌ 仅支持 SSH |

- `-d` 从原生 Windows 进程（cmd/PowerShell）启动时正常工作；从 MSYS2/Git Bash 启动时受限于 fd 表隔离，可能不可用。
- `-P` 参数接受但不会检查提示内容，因为密码通过 SSH_ASKPASS 传递，不需要匹配屏幕输出。

## 工作原理

1. 将密码写入临时文件
2. 创建批处理脚本输出该文件内容
3. 设置 `SSH_ASKPASS` 和 `SSH_ASKPASS_REQUIRE=force` 环境变量
4. 启动 Windows 原生 OpenSSH，SSH 自动调用脚本获取密码
5. 执行完成后清理临时文件

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。
