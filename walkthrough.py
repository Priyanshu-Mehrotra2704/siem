"""Guided sign-in query walkthrough. Run with Python 3.9+."""
import sqlite3
import sys
import tempfile
import time
import tkinter as tk
from contextlib import closing
from pathlib import Path
from tkinter import ttk, messagebox
import investigate as engine


def sample_store(path, now):
    rows = [("Practice-PC", str(i), time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now-age*3600)),
             name, outcome, now-age*3600, "", "")
            for i, (name, outcome, age) in enumerate([
                ("Priya","success",2), ("Priya","failed",3), ("Aman","success",2),
                ("Priya","success",30)], 1)]
    engine.save(rows,path)


def open_guide(root, sample, real):
    root.title("SIEM Query Guard • Guided demo")
    root.geometry("920x680")
    root.configure(bg="#edf2f3")
    page = tk.Frame(root,bg="white",padx=24,pady=16)
    page.pack(fill="both",expand=True,padx=14,pady=14)
    def label(parent, text, size=11, color="#20383e", bold=False):
        w=tk.Label(parent,text=text,fg=color,bg="white",font=("Segoe UI",size,"bold" if bold else "normal"),
                   anchor="w",justify="left",wraplength=760)
        w.pack(anchor="w",fill="x",pady=3)
        return w
    label(page,"Login search kaise check hoti hai?",20,bold=True)
    choices=tk.Frame(page,bg="white")
    choices.pack(fill="x",pady=4)
    source=ttk.Combobox(choices,state="readonly",values=("Practice • example records","Mere imported Windows logs"),width=29)
    source.current(0)
    source.pack(side="left")
    account=ttk.Combobox(choices,state="readonly",width=36)
    account.pack(side="left",padx=8)
    content=tk.Frame(page,bg="white")
    content.pack(fill="both",expand=True)
    def clear():
        for child in content.winfo_children():
            child.destroy()
    def action(title,callback):
        ttk.Button(content,text=title,command=callback).pack(anchor="w",pady=4)
    def first(*_):
        clear()
        name=account.get()
        label(content,"1  /  Tumhara sawaal",14,bold=True)
        label(content,f'Pehle: “Pichhle 24 ghante mein {name} ke failed logins dikhao.”')
        label(content,'Ab: “Isi account ke successful logins dikhao.”',14,bold=True)
        label(content,f"Account: {name}     •     Samay: pichhle 24 ghante     •     Badlav: failed → successful")
        action("Yahi change confirm karo  →",choose)
    def choose():
        clear()
        label(content,"2  /  Kaunsi search test karni hai?",14,bold=True)
        label(content,f"Tumne {account.get()} ke successful logins maange hain. Dono options ka fark dekhne ke liye ek chuno.")
        action("Account filter ke saath test karo",lambda: show("Exact"))
        action("Galti dikhao: account filter hata kar test karo",lambda: show("Omit account"))
    def show(mode):
        clear()
        name=account.get()
        path=sample if source.current()==0 else real
        practice=source.current()==0
        try:
            verdict,checks,rows=engine.investigate((name,"failed",24),(name,"success",24),int(time.time()),mode,path)
        except (OSError,sqlite3.Error) as err:
            messagebox.showerror("Search",str(err))
            choose()
            return
        label(content,"3  /  Do banaye hue logins par test",14,bold=True)
        label(content,"Dono test logins successful hain aur ek hi waqt ke hain. Sirf account alag hai.")
        grid=ttk.Treeview(content,columns=("login","expect","got"),show="headings",height=2)
        for col,title in (("login","Test account"),("expect","Tumhari request ke hisaab se"),("got","Query ne kya kiya")):
            grid.heading(col,text=title)
            grid.column(col,width=160)
        grid.pack(fill="x",pady=6)
        for role,_,pair in checks:
            if role in ("match","other account"):
                expect,actual=pair.split("/")
                grid.insert("","end",values=(name if role=="match" else engine.other_account(name),
                            "Dikhana hai" if expect=="1" else "Chhodna hai","Dikhaya" if actual=="1" else "Chhoda"))
        if verdict=="PASS":
            label(content,"PASS  •  Search chal gayi",15,"#00654b",True)
            label(content,f"Query ne {engine.other_account(name)} ko chhoda. Sabhi {len(checks)} test pass hue.")
            dataset="practice data" if practice else "imported Windows logs"
            label(content,f"{dataset.capitalize()} se {len(rows)} matching records dikhaye gaye (adhiktam 200).")
            if rows:
                evidence=ttk.Treeview(content,columns=("host","record","when","outcome"),show="headings",height=3)
                for col,title,width in (("host","Computer",100),("record","Record ID",80),("when","Event time",240),("outcome","Outcome",90)):
                    evidence.heading(col,text=title)
                    evidence.column(col,width=width)
                for host,record,stamp,_,outcome,_,_ in rows:
                    evidence.insert("","end",values=(host,record,stamp,outcome))
                evidence.pack(fill="x")
            action("Ab wahi search bina account filter ke dekho",lambda:show("Omit account"))
        else:
            label(content,"FAIL  •  Search rok di gayi",15,"#973616",True)
            label(content,f"Tumne sirf {name} ko maanga tha. Query ne {engine.other_account(name)} ka test login bhi chun liya. Guard ne evidence database par search rok di.")
            action("Account filter wapas lagao aur dobara dekho",lambda:show("Exact"))
        action("Pehle sawaal par wapas",first)
    def switch(*_):
        clear()
        names=["Priya"]
        if source.current()==1:
            names=[]
            if real.exists():
                try:
                    with closing(engine.read_store(real)) as db:
                        names=[r[0] for r in db.execute("SELECT DISTINCT account FROM events ORDER BY account")]
                except sqlite3.Error as err:
                    messagebox.showerror("Imported logs",str(err))
        account.set("")
        account.configure(values=names)
        if names:
            account.current(0)
            first()
        else:
            label(content,"Abhi imported accounts available nahi hain. Windows investigation kholkar XML import karo, phir yahan list refresh karo.")
            action("Windows investigation kholo",advanced)
            action("Account list refresh karo",switch)
    def advanced():
        import subprocess
        subprocess.Popen([sys.executable,str(Path(engine.__file__).resolve())])
    ttk.Button(choices,text="Import / full investigation",command=advanced).pack(side="left")
    account.bind("<<ComboboxSelected>>",first)
    source.bind("<<ComboboxSelected>>",switch)
    switch()


if __name__=="__main__":
    with tempfile.TemporaryDirectory() as directory:
        sample=Path(directory)/"practice.sqlite"
        sample_store(sample,int(time.time()))
        root=tk.Tk()
        open_guide(root,sample,engine.STORE)
        root.mainloop()
