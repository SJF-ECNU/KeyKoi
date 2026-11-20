#!/usr/bin/env python3
"""用真实 psql 的交互式会话验证 CancelRequest 转发。

libpq 只在交互式 psql 处于查询等待状态时把 Ctrl-C 变成 CancelRequest，
因此这里分配一个 pty、启动 psql、输入一条长查询，再向 pty 写 \\x03。

用法：
    cancel_pty.py --query "select pg_sleep(30);" --interrupt-after 1.5 -- psql ...

退出码：0 = 观察到取消（canceling statement），1 = 未观察到，2 = 环境错误。
输出：把 psql 的原始输出写到 stdout，便于脚本记录证据。
"""

import argparse
import os
import pty
import re
import select
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default="select pg_sleep(30);")
    parser.add_argument("--interrupt-after", type=float, default=1.5)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("cmd", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("no command given", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env.setdefault("TERM", "dumb")
    env.setdefault("PAGER", "cat")
    env.setdefault("PSQL_PAGER", "cat")

    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            os.execvpe(cmd[0], cmd, env)
        finally:
            os._exit(127)

    output = bytearray()
    state = "prompt"
    query_sent_at = 0.0
    interrupt_sent_at = 0.0
    deadline = time.time() + args.timeout
    cancelled = False
    prompt_seen = False

    try:
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            text = output.decode("utf-8", "replace")

            if state == "prompt" and re.search(r"=>\s*$", text):
                prompt_seen = True
                os.write(fd, (args.query + "\n").encode())
                query_sent_at = time.time()
                state = "running"
            elif state == "running" and query_sent_at and time.time() - query_sent_at >= args.interrupt_after:
                os.write(fd, b"\x03")
                interrupt_sent_at = time.time()
                state = "cancelled"
            elif state == "cancelled":
                if "canceling statement due to user request" in text:
                    cancelled = True
                    break
                if interrupt_sent_at and time.time() - interrupt_sent_at > 8:
                    break
            if state == "prompt" and not prompt_seen and "error" in text.lower():
                break
    finally:
        try:
            os.write(fd, b"\\q\n")
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass

    sys.stdout.write(output.decode("utf-8", "replace"))
    if not prompt_seen:
        print("cancel_pty: psql prompt was never reached", file=sys.stderr)
        return 2
    if not cancelled:
        print("cancel_pty: cancellation was not observed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
