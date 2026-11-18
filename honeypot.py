#!/usr/bin/env python3
"""
honeypot.py - a tiny SSH honeypot.

It pretends to be an SSH server, records every login attempt (username,
password, client software, IP) and every command typed in a FAKE shell.
Nothing the attacker types is ever executed. Everything is only logged to SQLite.

Run:   python honeypot.py --port 2222
"""
import argparse, logging, os, socket, sqlite3, threading, time
import paramiko
import alerts, mitre

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

DB_PATH = "honeypot.db"
HOST_KEY_FILE = "host.key"
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
WEAK_USERS = {"root", "admin", "ubuntu", "pi", "user", "test"}
WEAK_PASSWORDS = {"123456", "password", "admin", "root", "toor", "1234", "12345", "raspberry", "test"}

db_lock = threading.Lock()


# ---------------------------------------------------------------- database
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT,
            username TEXT, password TEXT, accepted INTEGER, client TEXT);
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT,
            username TEXT, command TEXT);
    """)
    con.commit()
    con.close()


def db_exec(sql, args=()):
    with db_lock:
        con = sqlite3.connect(DB_PATH)
        try:
            con.execute(sql, args)
            con.commit()
        finally:
            con.close()


def log_attempt(ip, user, pw, accepted, client):
    db_exec("INSERT INTO attempts(ts,ip,username,password,accepted,client) VALUES(?,?,?,?,?,?)",
            (time.time(), ip, user, pw, int(accepted), client))
    print(f"[login ] {ip:<15} {user!r}:{pw!r} {'ACCEPTED' if accepted else 'denied'}")


def log_command(ip, user, cmd):
    db_exec("INSERT INTO commands(ts,ip,username,command) VALUES(?,?,?,?)",
            (time.time(), ip, user, cmd[:500]))
    tags = ",".join(t[0] for t in mitre.classify(cmd))
    print(f"[cmd   ] {ip:<15} {user}: {cmd[:120]!r}  {('[' + tags + ']') if tags else ''}")
    if mitre.is_download(cmd):
        alerts.notify(f"Honeypot: {ip} ({user}) tried to download something: {cmd[:200]}")


# -------------------------------------------------------------- fake shell
FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
)


def fake_output(cmd, user):
    """Return (text, should_quit). Pure text, nothing is ever executed."""
    parts = cmd.split()
    name = parts[0]
    if name in ("exit", "logout", "quit"):
        return "", True
    if name == "whoami":
        return user, False
    if name == "id":
        uid = 0 if user == "root" else 1000
        return f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})", False
    if name == "pwd":
        return ("/root" if user == "root" else f"/home/{user}"), False
    if name == "ls":
        return "backup.tar.gz  notes.txt", False
    if name == "uname":
        return "Linux srv01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux", False
    if cmd.startswith("cat /etc/passwd"):
        return FAKE_PASSWD, False
    if name == "cat" and len(parts) > 1:
        fname = parts[1].split("/")[-1]
        if fname == "notes.txt":
            return "TODO: rotate backup keys\nTODO: update nginx", False
        if fname == "backup.tar.gz":
            return "cat: backup.tar.gz: binary file", False
        return f"cat: {parts[1]}: No such file or directory", False
    if cmd.startswith("cat /etc/shadow"):
        return "cat: /etc/shadow: Permission denied", False
    if name == "ps":
        return "  PID TTY          TIME CMD\n 1021 pts/0    00:00:00 bash\n 1044 pts/0    00:00:00 ps", False
    if name in ("wget", "curl"):
        return "Connecting... failed: Connection timed out.", False
    return f"bash: {name}: command not found", False


def crlf(text):
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


def run_shell(chan, ip, user):
    chan.settimeout(90)
    chan.send(crlf("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"))
    prompt = f"{user}@srv01:~$ "
    chan.send(prompt)
    buf, started, count = "", time.time(), 0
    while time.time() - started < 180 and count < 50:
        try:
            data = chan.recv(1024)
        except socket.timeout:
            break
        if not data:
            break
        for ch in data.decode("utf-8", errors="ignore"):
            if ch in "\r\n":
                chan.send("\r\n")
                cmd, buf = buf.strip(), ""
                if cmd:
                    count += 1
                    log_command(ip, user, cmd)
                    out, quit_ = fake_output(cmd, user)
                    if out:
                        chan.send(crlf(out) + "\r\n")
                    if quit_:
                        return
                chan.send(prompt)
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":
                buf = ""
                chan.send("^C\r\n" + prompt)
            elif ch == "\x04":
                return
            elif ch.isprintable():
                buf += ch
                chan.send(ch)


# -------------------------------------------------------------- ssh server
class FakeServer(paramiko.ServerInterface):
    def __init__(self, ip, accept_mode):
        self.ip, self.accept_mode = ip, accept_mode
        self.transport = None
        self.user = "root"
        self.exec_cmd = None
        self.event = threading.Event()

    def _allowed(self, user, pw):
        if self.accept_mode == "all":
            return True
        if self.accept_mode == "none":
            return False
        return user in WEAK_USERS and pw in WEAK_PASSWORDS

    def check_auth_password(self, username, password):
        ok = self._allowed(username, password)
        client = getattr(self.transport, "remote_version", "") if self.transport else ""
        log_attempt(self.ip, username, password, ok, client)
        if ok:
            self.user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_cmd = command.decode("utf-8", errors="ignore")
        self.event.set()
        return True


def handle(client, addr, host_key, accept_mode, slots):
    ip = addr[0]
    t = paramiko.Transport(client)
    t.local_version = BANNER
    t.add_server_key(host_key)
    server = FakeServer(ip, accept_mode)
    server.transport = t
    try:
        t.start_server(server=server)
        chan = t.accept(20)
        if chan is None:
            return
        server.event.wait(10)
        if server.exec_cmd:
            log_command(ip, server.user, server.exec_cmd)
            out, _ = fake_output(server.exec_cmd.strip() or "true", server.user)
            chan.send(crlf(out) + "\r\n")
            chan.send_exit_status(0)
        else:
            run_shell(chan, ip, server.user)
        chan.close()
    except Exception:
        pass
    finally:
        t.close()
        slots.release()


def load_host_key():
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    return key


def main():
    global DB_PATH
    p = argparse.ArgumentParser(description="Tiny SSH honeypot (logs only, never executes anything)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--db", default=DB_PATH)
    p.add_argument("--accept", choices=["weak", "all", "none"], default="weak",
                   help="which logins to let into the fake shell (default: weak)")
    p.add_argument("--max-conn", type=int, default=50)
    a = p.parse_args()
    DB_PATH = a.db

    init_db()
    host_key = load_host_key()
    slots = threading.Semaphore(a.max_conn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((a.host, a.port))
    sock.listen(100)
    print(f"[*] honeypot listening on {a.host}:{a.port}  (accept={a.accept})  Ctrl+C to stop")
    try:
        while True:
            client, addr = sock.accept()
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=handle, args=(client, addr, host_key, a.accept, slots),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()
