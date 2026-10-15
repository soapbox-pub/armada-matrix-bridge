#!/usr/bin/env python3
"""A tiny Matrix client for poking the dev stack.

    dev/mx.py login USER PASS            # stores the token in /tmp/mxtoken-USER
    dev/mx.py [-u USER] rooms            # joined rooms with names
    dev/mx.py [-u USER] join ROOM
    dev/mx.py [-u USER] send ROOM TEXT [--reply EVENT] [--thread ROOT] [--html HTML]
    dev/mx.py [-u USER] react ROOM EVENT KEY
    dev/mx.py [-u USER] edit ROOM EVENT TEXT
    dev/mx.py [-u USER] redact ROOM EVENT
    dev/mx.py [-u USER] upload ROOM FILE
    dev/mx.py [-u USER] history ROOM [N]
"""
import json, sys, urllib.request, urllib.parse, uuid, mimetypes, os

HS = os.environ.get("HS", "http://127.0.0.1:8008")
args = sys.argv[1:]
user = "tester"
if args[:1] == ["-u"]:
    user, args = args[1], args[2:]

def call(method, path, body=None, raw=None, ctype="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(HS + path, data=data, method=method)
    req.add_header("Content-Type", ctype)
    tok = f"/tmp/mxtoken-{user}"
    if os.path.exists(tok):
        req.add_header("Authorization", "Bearer " + open(tok).read().strip())
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        sys.exit(f"{e.code}: {e.read().decode()}")

q = urllib.parse.quote
cmd = args[0]
def flag(name):
    return args[args.index(name) + 1] if name in args else None

if cmd == "login":
    r = call("POST", "/_matrix/client/v3/login", {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": args[1]}, "password": args[2]})
    open(f"/tmp/mxtoken-{args[1]}", "w").write(r["access_token"])
elif cmd == "rooms":
    for r in call("GET", "/_matrix/client/v3/joined_rooms")["joined_rooms"]:
        name = call("GET", f"/_matrix/client/v3/rooms/{q(r)}/state/m.room.name/") if True else {}
        print(r, name.get("name"))
elif cmd == "join":
    print(call("POST", f"/_matrix/client/v3/join/{q(args[1])}", {}))
elif cmd == "send":
    content = {"msgtype": "m.text", "body": args[2]}
    if flag("--html"):
        content.update(format="org.matrix.custom.html", formatted_body=flag("--html"))
    if flag("--thread"):
        content["m.relates_to"] = {"rel_type": "m.thread", "event_id": flag("--thread"), "is_falling_back": True, "m.in_reply_to": {"event_id": flag("--thread")}}
    elif flag("--reply"):
        content["m.relates_to"] = {"m.in_reply_to": {"event_id": flag("--reply")}}
    print(call("PUT", f"/_matrix/client/v3/rooms/{q(args[1])}/send/m.room.message/{uuid.uuid4()}", content)["event_id"])
elif cmd == "react":
    print(call("PUT", f"/_matrix/client/v3/rooms/{q(args[1])}/send/m.reaction/{uuid.uuid4()}", {"m.relates_to": {"rel_type": "m.annotation", "event_id": args[2], "key": args[3]}})["event_id"])
elif cmd == "edit":
    print(call("PUT", f"/_matrix/client/v3/rooms/{q(args[1])}/send/m.room.message/{uuid.uuid4()}", {"msgtype": "m.text", "body": "* " + args[3], "m.new_content": {"msgtype": "m.text", "body": args[3]}, "m.relates_to": {"rel_type": "m.replace", "event_id": args[2]}})["event_id"])
elif cmd == "redact":
    print(call("PUT", f"/_matrix/client/v3/rooms/{q(args[1])}/redact/{q(args[2])}/{uuid.uuid4()}", {}))
elif cmd == "upload":
    data = open(args[2], "rb").read()
    mime = mimetypes.guess_type(args[2])[0] or "application/octet-stream"
    mxc = call("POST", "/_matrix/media/v3/upload?filename=" + q(os.path.basename(args[2])), raw=data, ctype=mime)["content_uri"]
    content = {"msgtype": "m.image" if mime.startswith("image/") else "m.file", "body": os.path.basename(args[2]), "url": mxc, "info": {"mimetype": mime, "size": len(data)}}
    print(call("PUT", f"/_matrix/client/v3/rooms/{q(args[1])}/send/m.room.message/{uuid.uuid4()}", content)["event_id"])
elif cmd == "history":
    n = args[2] if len(args) > 2 else "20"
    chunk = call("GET", f"/_matrix/client/v3/rooms/{q(args[1])}/messages?dir=b&limit={n}")["chunk"]
    for e in reversed(chunk):
        c = e.get("content", {})
        if e["type"] in ("m.room.message", "m.reaction", "m.room.redaction"):
            rel = c.get("m.relates_to", {})
            print(e["event_id"], e["sender"], e["type"], json.dumps({k: v for k, v in c.items() if k in ("body", "formatted_body", "msgtype", "url")}, ensure_ascii=False), json.dumps(rel) if rel else "")
        elif e.get("unsigned", {}).get("redacted_because"):
            print(e["event_id"], e["sender"], "(redacted)")
