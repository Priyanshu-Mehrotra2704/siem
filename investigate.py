"""Local Windows sign-in investigator. Standard-library Python 3.9+."""
import os
import re
import sqlite3
import subprocess
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

STORE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SIEMQueryGuard" / "events.sqlite"
SCHEMA = """CREATE TABLE IF NOT EXISTS events (
 host TEXT, record TEXT, stamp TEXT, account TEXT COLLATE BINARY,
 outcome TEXT, ts INTEGER, ip TEXT, kind TEXT, PRIMARY KEY(host,record,stamp))"""
MAX_BYTES = 64 * 1024 * 1024
SELECT = "SELECT host,record,stamp,account,outcome,ip,kind FROM events WHERE "
OPTIONS = ("Change outcome to successful", "Change outcome to failed", "Change time window")


def normalize(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("XML exceeds 64 MiB. Export a smaller interval.")
    root = ET.fromstring(raw)
    for element in root.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    events = [root] if root.tag == "Event" else root.findall("Event")
    if root.tag not in ("Event", "Events"):
        raise ValueError("Expected Windows Event Viewer XML with Event or Events root.")
    rows = []
    for event in events:
        sys = event.find("System")
        if sys is None:
            continue
        provider = sys.find("Provider")
        code = sys.findtext("EventID")
        if (sys.findtext("Channel") != "Security" or provider is None or
                provider.get("Name") != "Microsoft-Windows-Security-Auditing" or code not in ("4624", "4625")):
            continue
        data = {x.get("Name"): x.text or "" for x in event.findall("EventData/Data")}
        user, host, record = data.get("TargetUserName"), sys.findtext("Computer"), sys.findtext("EventRecordID")
        stamp_node = sys.find("TimeCreated")
        if not user or not host or not record or stamp_node is None:
            raise ValueError("A matching event is missing identity, record number or timestamp.")
        stamp = stamp_node.get("SystemTime", "")
        moment = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", stamp).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("An event lacks a timestamp offset.")
        domain = data.get("TargetDomainName")
        account = domain + "\\" + user if domain and domain != "-" else user
        rows.append((host, record, stamp, account, "success" if code == "4624" else "failed",
                     int(moment.timestamp()), data.get("IpAddress", ""), data.get("LogonType", "")))
    return rows


def live_xml():
    if os.name != "nt":
        raise ValueError("Local collection requires Windows. Use an exported XML file here.")
    command = ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4624 or EventID=4625)]]",
               "/rd:true", "/c:2000", "/f:xml", "/e:Events", "/uni:true"]
    result = subprocess.run(command, capture_output=True, timeout=45)
    if result.returncode:
        raw = result.stderr or result.stdout
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-16-le" if b"\x00" in raw else "mbcs"
        detail = raw.decode(encoding, errors="replace").strip() if raw else ""
        raise ValueError(f"Windows event query failed (exit {result.returncode}).\n{detail}\nYou can also import a Security log XML export.")
    return result.stdout


def read_store(path):
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def save(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(SCHEMA)
        db.execute("CREATE INDEX IF NOT EXISTS event_time ON events(account, outcome, ts)")
        db.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(host,record,stamp) DO NOTHING", rows)
        return db.total_changes


def matches(spec, account, outcome, ts, now):
    user, status, hours = spec
    return user == account and status == outcome and now - hours * 3600 <= ts <= now


def compile_sql(spec, account_mode):
    account, status, hours = spec
    clause = {"Exact": "account = ?", "Ignore case": "account = ? COLLATE NOCASE",
              "Omit account": "1=1"}[account_mode]
    def bind(now):
        prefix = () if account_mode == "Omit account" else (account,)
        return prefix + (status, now - hours * 3600, now)
    return SELECT + clause + " AND outcome = ? AND ts BETWEEN ? AND ? ORDER BY ts DESC, host, record LIMIT 200", bind


def other_account(account):
    return "Aman" if account.casefold() != "aman" else "Neha"


def investigate(old, new, now, mode, path):
    sql1, bind1 = compile_sql(old, "Exact")
    sql2, bind2 = compile_sql(new, mode)
    account, status, hours = new
    lower = now - hours * 3600
    other = "success" if status == "failed" else "failed"
    cases = [("match", account, status, now), ("other account", other_account(account), status, now),
             ("case variant", account.swapcase(), status, now), ("other outcome", account, other, now),
             ("window start", account, status, lower), ("before window", account, status, lower-1),
             ("future", account, status, now+1), ("original window start", account, status, now-old[2]*3600)]
    with closing(sqlite3.connect(":memory:")) as test:
        test.execute(SCHEMA)
        test.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",
                         [("test", label, str(ts), user, outcome, ts, "", "") for label,user,outcome,ts in cases])
        h1 = {r[1] for r in test.execute(sql1, bind1(now))}
        h2 = {r[1] for r in test.execute(sql2, bind2(now))}
    proof = []
    fault = mode == "Omit account"
    uncertain = mode == "Ignore case"
    for label,user,outcome,ts in cases:
        e1, e2 = matches(old,user,outcome,ts,now), matches(new,user,outcome,ts,now)
        observed1, observed2 = label in h1, label in h2
        if e1 != observed1:
            uncertain = True
        elif e2 != observed2:
            fault = True
        proof.append((label, f"{int(e1)}/{int(observed1)}", f"{int(e2)}/{int(observed2)}"))
    verdict = "FAIL" if fault else "INCONCLUSIVE" if uncertain else "PASS"
    rows = []
    if verdict == "PASS":
        with closing(read_store(path)) as db:
            rows = db.execute(sql2, bind2(now)).fetchall()
    return verdict, proof, rows


def main():
    root = tk.Tk()
    root.title("Windows sign-in investigation")
    root.geometry("1010x740")
    panel = ttk.Frame(root, padding=16)
    panel.pack(fill="both", expand=True)
    ttk.Label(panel, text="Windows sign-in investigation", font=("Segoe UI", 20, "bold")).pack(anchor="w")
    source = tk.StringVar(value="Import recent events, or open a Security log XML export.")
    toolbar = ttk.Frame(panel)
    toolbar.pack(anchor="w", pady=6)
    ttk.Label(panel, textvariable=source, wraplength=900).pack(anchor="w")
    fields = ttk.Frame(panel)
    fields.pack(anchor="w", pady=8)
    def combo(label, choices, width):
        col = len(fields.grid_slaves(row=0))
        ttk.Label(fields,text=label).grid(row=0,column=col,sticky="w")
        widget = ttk.Combobox(fields, values=choices, state="readonly", width=width)
        if choices:
            widget.current(0)
        widget.grid(row=1,column=col,padx=(0,6))
        return widget
    account = combo("Account", [], 25)
    status = combo("Original outcome", ["failed","success"], 12)
    window = combo("Original hours", ["24","48","168","720"], 10)
    follow = combo("Follow-up", OPTIONS, 25)
    new_hours = combo("Revised hours", ["48","24","168","720"], 10)
    modes = ttk.Frame(panel)
    modes.pack(anchor="w")
    ttk.Label(modes,text="Candidate account filter").pack(side="left")
    mode = ttk.Combobox(modes,values=["Exact","Ignore case","Omit account"],state="readonly")
    mode.current(0)
    mode.pack(side="left",padx=8)
    note = tk.StringVar()
    ttk.Label(panel,textvariable=note,wraplength=910).pack(anchor="w",pady=8)
    output = tk.Text(panel,wrap="none",height=22,font=("Consolas",10))
    def report(s):
        output.configure(state="normal")
        output.delete("1.0","end")
        output.insert("end",s)
        output.configure(state="disabled")
    state = {}
    def reset(*_):
        state.clear()
        run_button.state(["disabled"])
        report("")
        note.set("Choose the original search and a follow-up, then confirm the change.")
    def reload_accounts():
        if STORE.exists():
            with closing(read_store(STORE)) as db:
                accounts = [r[0] for r in db.execute("SELECT DISTINCT account FROM events ORDER BY account")]
            account.configure(values=accounts)
            if accounts:
                account.current(0)
    def load(local):
        reset()
        try:
            if local:
                raw = live_xml()
            else:
                filename = filedialog.askopenfilename(filetypes=[("Event Viewer XML","*.xml"),("All files","*.*")])
                if not filename:
                    return
                if Path(filename).stat().st_size > MAX_BYTES:
                    raise ValueError("Export must be under 64 MiB.")
                raw = Path(filename).read_bytes()
            rows = normalize(raw)
            added = save(rows, STORE)
            reload_accounts()
            if not rows:
                source.set("No 4624 or 4625 records in this source. Select a Security-channel export containing sign-in events.")
                return
            source.set(f"{len(rows)} matching sign-in records read. {added} newly stored. Searches cover imported events only.")
        except (ValueError, OSError, sqlite3.Error, ET.ParseError, subprocess.TimeoutExpired) as err:
            messagebox.showerror("Import",str(err))
    def confirm():
        reset()
        if not account.get():
            note.set("Import events containing a target account first.")
            return
        old = (account.get(),status.get(),int(window.get()))
        idx = follow.current()
        new = (old[0], ("success","failed")[idx], old[2]) if idx < 2 else (old[0],old[1],int(new_hours.get()))
        if new == old:
            note.set("Choose a follow-up that changes the outcome or time window.")
            return
        state.update(old=old,new=new,now=int(time.time()))
        note.set(f"Confirmed exact log label {old[0]}   |   {old[1]} → {new[1]}   |   Last {old[2]} → {new[2]} hours")
        run_button.state(["!disabled"])
    def search():
        try:
            verdict,checks,rows = investigate(state["old"],state["new"],state["now"],mode.get(),STORE)
            lines = [verdict,"", "Synthetic checks           Q1 expected/actual   Q2 expected/actual"]
            lines.extend(f"{label:26} {q1:20} {q2}" for label,q1,q2 in checks)
            if verdict == "PASS":
                lines.extend(["",f"Imported evidence: {len(rows)} displayed (latest 200 maximum).",
                              "Host | Record | Event time | Target account | Outcome | Source IP | Logon type"])
                lines.extend(" | ".join(row) for row in rows)
            else:
                lines += ["","Release blocked. Imported records were not searched."]
            report("\n".join(lines))
        except sqlite3.Error as err:
            report("Search unavailable: "+str(err))
    ttk.Button(toolbar,text="Read local Security log",command=lambda:load(True)).pack(side="left")
    ttk.Button(toolbar,text="Import XML…",command=lambda:load(False)).pack(side="left",padx=6)
    buttons = ttk.Frame(panel)
    buttons.pack(anchor="w")
    ttk.Button(buttons,text="1. Confirm change",command=confirm).pack(side="left")
    run_button=ttk.Button(buttons,text="2. Validate and search",command=search)
    run_button.pack(side="left",padx=6)
    scroll = ttk.Scrollbar(panel,orient="horizontal",command=output.xview)
    output.configure(xscrollcommand=scroll.set)
    output.pack(fill="both",expand=True,pady=(8,0))
    scroll.pack(fill="x")
    for widget in (account,status,window,follow,new_hours,mode):
        widget.bind("<<ComboboxSelected>>",reset)
    reset()
    reload_accounts()
    root.mainloop()


if __name__ == "__main__":
    main()
