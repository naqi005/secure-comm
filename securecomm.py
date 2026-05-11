#!/usr/bin/env python3
"""
SecureComm — Encrypted Desktop Messaging Application
RSA-2048 + AES-256-CBC, single Python file, Tkinter GUI.
"""

import os, json, base64, hashlib, socket, threading, queue, datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PORT = 65432

def get_local_ip():
    """Return the machine's actual LAN IP by probing the default route (no data sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

BG="#0f0f0f"; SURFACE="#1a1a1a"; ELEVATED="#222222"; BORDER="#2a2a2a"
ACCENT="#4f8ef7"; ACCENT_H="#6ba3ff"; SUCCESS="#22c55e"; ERROR="#ef4444"
WARNING="#f59e0b"; TEXT_PRI="#e8e8e8"; TEXT_SEC="#888888"; TEXT_MUT="#555555"
BUBBLE_ME="#1e3a5f"; BUBBLE_TH="#1a1a1a"

F_HEAD=("Segoe UI",12,"bold"); F_BODY=("Segoe UI",10); F_CAP=("Segoe UI",9)
F_MONO=("Consolas",9); F_MONO_S=("Consolas",8)

# ─── Crypto ───────────────────────────────────────────────────────────────────

def generate_rsa_keypair():
    priv=rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    return priv,priv.public_key()

def serialize_private_key(k):
    return k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())

def serialize_public_key(k):
    return k.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

def load_private_key_from_pem(pem):
    if isinstance(pem,str): pem=pem.encode()
    return serialization.load_pem_private_key(pem,password=None,backend=default_backend())

def load_public_key_from_pem(pem):
    if isinstance(pem,str): pem=pem.encode()
    return serialization.load_pem_public_key(pem,backend=default_backend())

def generate_aes_key(): return os.urandom(32)
def generate_iv():      return os.urandom(16)

def encrypt_aes_cbc(pt,key,iv):
    p=sym_padding.PKCS7(128).padder(); padded=p.update(pt)+p.finalize()
    e=Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend()).encryptor()
    return e.update(padded)+e.finalize()

def decrypt_aes_cbc(ct,key,iv):
    d=Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend()).decryptor()
    padded=d.update(ct)+d.finalize()
    u=sym_padding.PKCS7(128).unpadder(); return u.update(padded)+u.finalize()

def wrap_aes_key(aes_key,pub):
    return pub.encrypt(aes_key,asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def unwrap_aes_key(enc,priv):
    return priv.decrypt(enc,asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def sha256_hex(data): return hashlib.sha256(data).hexdigest()

def sign_rsa_pss(data,priv):
    return priv.sign(data,asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH),hashes.SHA256())

def verify_rsa_pss(data,sig,pub):
    try:
        pub.verify(sig,data,asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH),hashes.SHA256())
        return True
    except Exception: return False

def build_envelope(pt,aes_key,peer_pub,my_priv,my_pub,sender_name):
    iv=generate_iv(); ct=encrypt_aes_cbc(pt,aes_key,iv)
    sig=sign_rsa_pss(pt,my_priv); ek=wrap_aes_key(aes_key,peer_pub)
    return {"ciphertext":base64.b64encode(ct).decode(),
            "iv":base64.b64encode(iv).decode(),
            "aes_key_encrypted":base64.b64encode(ek).decode(),
            "message_hash":sha256_hex(pt),
            "signature":base64.b64encode(sig).decode(),
            "sender_public_key":serialize_public_key(my_pub).decode(),
            "sender_name":sender_name,
            "timestamp":datetime.datetime.now().strftime("%H:%M:%S")}

def parse_envelope(env,my_priv):
    r={"plaintext":None,"integrity_ok":False,"signature_ok":False,
       "sender_name":env.get("sender_name","?"),
       "timestamp":env.get("timestamp",""),"error":None}
    try:
        ct=base64.b64decode(env["ciphertext"]); iv=base64.b64decode(env["iv"])
        ek=base64.b64decode(env["aes_key_encrypted"]); sig=base64.b64decode(env["signature"])
        aes_key=unwrap_aes_key(ek,my_priv); pt=decrypt_aes_cbc(ct,aes_key,iv)
        r["plaintext"]=pt; r["integrity_ok"]=(sha256_hex(pt)==env["message_hash"])
        spub=load_public_key_from_pem(env["sender_public_key"])
        r["signature_ok"]=verify_rsa_pss(pt,sig,spub)
    except Exception as e: r["error"]=str(e)
    return r

# ─── Network ──────────────────────────────────────────────────────────────────

def _recv_exact(sock,n):
    buf=b""
    while len(buf)<n:
        c=sock.recv(n-len(buf))
        if not c: return b""
        buf+=c
    return buf

def send_msg(sock,d):
    data=json.dumps(d).encode(); sock.sendall(len(data).to_bytes(4,"big")+data)

def recv_msg(sock):
    h=_recv_exact(sock,4)
    if not h: raise ConnectionError("Connection closed")
    return json.loads(_recv_exact(sock,int.from_bytes(h,"big")).decode())

# ─── Widget helpers ───────────────────────────────────────────────────────────

def mk_btn(parent,text,cmd,primary=True,**kw):
    bg=ACCENT if primary else ELEVATED; fg="#fff" if primary else TEXT_PRI
    b=tk.Button(parent,text=text,command=cmd,bg=bg,fg=fg,
                activebackground=ACCENT_H,activeforeground="#fff",
                relief="flat",bd=0,padx=16,pady=0,font=F_BODY,cursor="hand2",**kw)
    b.bind("<Enter>",lambda e:b.config(bg=ACCENT_H if primary else BORDER))
    b.bind("<Leave>",lambda e:b.config(bg=bg))
    return b

def mk_entry(parent,**kw):
    return tk.Entry(parent,bg=SURFACE,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                    relief="flat",bd=0,highlightthickness=1,
                    highlightbackground=BORDER,highlightcolor=ACCENT,font=F_BODY,**kw)

def mk_card(parent,**kw):
    return tk.Frame(parent,bg=ELEVATED,highlightthickness=1,
                    highlightbackground=BORDER,**kw)

def mk_mono_box(parent,height,readonly=False):
    outer=tk.Frame(parent,bg=ELEVATED,highlightthickness=1,highlightbackground=BORDER)
    txt=tk.Text(outer,bg=ELEVATED,fg=TEXT_PRI,font=F_MONO,relief="flat",bd=0,
                wrap="word",height=height,insertbackground=TEXT_PRI,
                selectbackground=ACCENT)
    sb=ttk.Scrollbar(outer,orient="vertical",command=txt.yview,
                     style="Slim.Vertical.TScrollbar")
    txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right",fill="y"); txt.pack(side="left",fill="both",expand=True,padx=4,pady=4)
    if readonly: txt.config(state="disabled")
    return outer,txt

def set_mono(txt,content,readonly=True):
    txt.config(state="normal"); txt.delete("1.0","end"); txt.insert("1.0",content)
    if readonly: txt.config(state="disabled")

def _safe_write(path,data):
    if not os.path.exists(path):
        with open(path,"wb") as f: f.write(data)
        return path
    base,ext=os.path.splitext(path); i=1
    while os.path.exists(f"{base}_{i}{ext}"): i+=1
    final=f"{base}_{i}{ext}"
    with open(final,"wb") as f: f.write(data)
    return final

# ─── Startup Dialog ───────────────────────────────────────────────────────────

class StartupDialog:
    def __init__(self,root,app):
        self.app=app
        self.win=tk.Toplevel(root)
        self.win.title("SecureComm — Setup")
        self.win.geometry("540x680"); self.win.resizable(False,False)
        self.win.configure(bg=BG)
        self.win.protocol("WM_DELETE_WINDOW",self._close)
        self.win.grab_set()
        self._keys_page()

    @property
    def window(self): return self.win

    def _clear(self):
        for w in self.win.winfo_children(): w.destroy()

    def _pad(self):
        f=tk.Frame(self.win,bg=BG); f.pack(fill="both",expand=True,padx=28,pady=18)
        return f

    def _keys_page(self):
        self._clear(); pad=self._pad()
        tk.Label(pad,text="SecureComm",font=("Segoe UI",20,"bold"),bg=BG,fg=TEXT_PRI).pack(pady=(0,4))
        tk.Label(pad,text="Encrypted Desktop Messaging",font=F_BODY,bg=BG,fg=TEXT_SEC).pack(pady=(0,18))

        nc=mk_card(pad); nc.pack(fill="x",pady=(0,10))
        tk.Label(nc,text="DISPLAY NAME",font=("Segoe UI",8,"bold"),bg=ELEVATED,fg=TEXT_MUT).pack(anchor="w",padx=12,pady=(10,2))
        self.name_var=tk.StringVar(value="Alice")
        mk_entry(nc,textvariable=self.name_var).pack(fill="x",padx=12,pady=(0,12),ipady=6)

        gc=mk_card(pad); gc.pack(fill="x",pady=(0,8))
        tk.Label(gc,text="Generate New Keys",font=("Segoe UI",10,"bold"),bg=ELEVATED,fg=TEXT_PRI).pack(anchor="w",padx=12,pady=(12,2))
        tk.Label(gc,text="Creates a fresh RSA-2048 key pair",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=12)
        br=tk.Frame(gc,bg=ELEVATED); br.pack(anchor="w",padx=12,pady=8)
        mk_btn(br,"Generate Keys",self._gen).pack(side="left")
        self.save_btn=mk_btn(br,"Save Keys",self._save,primary=False)
        self.save_btn.pack(side="left",padx=(8,0)); self.save_btn.config(state="disabled")
        self.pub_frame,self.pub_txt=mk_mono_box(gc,5,readonly=True)
        self.pub_frame.pack(fill="x",padx=12,pady=(0,12))

        lc=mk_card(pad); lc.pack(fill="x",pady=(0,10))
        tk.Label(lc,text="Load Existing Keys",font=("Segoe UI",10,"bold"),bg=ELEVATED,fg=TEXT_PRI).pack(anchor="w",padx=12,pady=(12,2))
        tk.Label(lc,text="Select private_key.pem — public_key.pem auto-loaded",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=12)
        mk_btn(lc,"Browse…",self._load,primary=False).pack(anchor="w",padx=12,pady=8)
        self.load_lbl=tk.Label(lc,text="",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC)
        self.load_lbl.pack(anchor="w",padx=12,pady=(0,10))

        self.key_err=tk.Label(pad,text="",font=F_CAP,bg=BG,fg=ERROR); self.key_err.pack(pady=(0,8))
        mk_btn(pad,"Continue →",self._to_role).pack()

    def _gen(self):
        priv,pub=generate_rsa_keypair()
        self.app.private_key=priv; self.app.public_key=pub
        set_mono(self.pub_txt,serialize_public_key(pub).decode())
        self.save_btn.config(state="normal")
        self.key_err.config(text="✓ RSA-2048 keys generated",fg=SUCCESS)

    def _save(self):
        if not self.app.private_key: return
        d=filedialog.askdirectory(title="Save keys to folder")
        if not d: return
        _safe_write(os.path.join(d,"private_key.pem"),serialize_private_key(self.app.private_key))
        _safe_write(os.path.join(d,"public_key.pem"),serialize_public_key(self.app.public_key))
        self.key_err.config(text="✓ Keys saved",fg=SUCCESS)

    def _load(self):
        path=filedialog.askopenfilename(title="Select private_key.pem",
            filetypes=[("PEM","*.pem"),("All","*.*")])
        if not path: return
        try:
            with open(path,"rb") as f: priv=load_private_key_from_pem(f.read())
            pub_path=os.path.join(os.path.dirname(path),"public_key.pem")
            with open(pub_path,"rb") as f: pub=load_public_key_from_pem(f.read())
            self.app.private_key=priv; self.app.public_key=pub
            self.load_lbl.config(text=f"✓ {os.path.basename(path)}",fg=SUCCESS)
        except Exception as e:
            self.load_lbl.config(text=f"Error: {e}",fg=ERROR)

    def _to_role(self):
        name=self.name_var.get().strip()
        if not name: self.key_err.config(text="Enter a display name",fg=ERROR); return
        if not self.app.private_key: self.key_err.config(text="Generate or load keys first",fg=ERROR); return
        self.app.display_name=name; self._role_page()

    def _role_page(self):
        self._clear(); pad=self._pad()
        tk.Label(pad,text="Select Role",font=("Segoe UI",16,"bold"),bg=BG,fg=TEXT_PRI).pack(pady=(0,4))
        tk.Label(pad,text=f"Signed in as  {self.app.display_name}",font=F_BODY,bg=BG,fg=TEXT_SEC).pack(pady=(0,18))

        sc=mk_card(pad); sc.pack(fill="x",pady=(0,10))
        tk.Label(sc,text="Server",font=("Segoe UI",11,"bold"),bg=ELEVATED,fg=TEXT_PRI).pack(anchor="w",padx=16,pady=(14,2))
        tk.Label(sc,text="Host the session. Wait for a client on port 65432.",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=16)
        ir=tk.Frame(sc,bg=ELEVATED); ir.pack(anchor="w",padx=16,pady=6)
        tk.Label(ir,text="Your IP:",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(side="left")
        my_ip=get_local_ip()
        tk.Label(ir,text=f"  {my_ip}",font=F_MONO,bg=ELEVATED,fg=ACCENT).pack(side="left")
        def _copy_ip():
            self.win.clipboard_clear(); self.win.clipboard_append(my_ip)
        mk_btn(ir,"Copy",_copy_ip,primary=False).pack(side="left",padx=(8,0))
        mk_btn(sc,"Start as Server",lambda:self._pick("server")).pack(anchor="w",padx=16,pady=(0,14))

        cc=mk_card(pad); cc.pack(fill="x",pady=(0,10))
        tk.Label(cc,text="Client",font=("Segoe UI",11,"bold"),bg=ELEVATED,fg=TEXT_PRI).pack(anchor="w",padx=16,pady=(14,2))
        tk.Label(cc,text="Connect to the server's IP address.",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=16)
        self.ip_var=tk.StringVar(value="192.168.1.")
        mk_entry(cc,textvariable=self.ip_var).pack(fill="x",padx=16,pady=8,ipady=6)
        mk_btn(cc,"Connect as Client",lambda:self._pick("client")).pack(anchor="w",padx=16,pady=(0,14))

        self.role_err=tk.Label(pad,text="",font=F_CAP,bg=BG,fg=ERROR); self.role_err.pack()

    def _pick(self,role):
        if role=="client":
            ip=self.ip_var.get().strip()
            if not ip: self.role_err.config(text="Enter the server IP address"); return
            self.app.server_ip=ip
        self.app.role=role; self.win.destroy()

    def _close(self):
        self.app.role=None; self.win.destroy()

# ─── Chat Tab ─────────────────────────────────────────────────────────────────

class ChatTab:
    def __init__(self,notebook,app):
        self.app=app
        self.frame=tk.Frame(notebook,bg=BG)
        self._build()

    def _build(self):
        # Scrollable canvas message area
        chat_outer=tk.Frame(self.frame,bg=BG)
        chat_outer.pack(fill="both",expand=True)
        self.canvas=tk.Canvas(chat_outer,bg=BG,bd=0,highlightthickness=0)
        self.vsb=ttk.Scrollbar(chat_outer,orient="vertical",command=self.canvas.yview,
                               style="Slim.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right",fill="y")
        self.canvas.pack(side="left",fill="both",expand=True)
        self.msg_frame=tk.Frame(self.canvas,bg=BG)
        self._win=self.canvas.create_window((0,0),window=self.msg_frame,anchor="nw")
        self.msg_frame.bind("<Configure>",lambda e:self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",lambda e:self.canvas.itemconfig(
            self._win,width=e.width))
        self.canvas.bind_all("<MouseWheel>",
            lambda e:self.canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        tk.Frame(self.frame,bg=BORDER,height=1).pack(fill="x")

        # Input bar
        bar=tk.Frame(self.frame,bg=SURFACE,pady=8); bar.pack(fill="x")
        inner=tk.Frame(bar,bg=SURFACE); inner.pack(fill="x",padx=12)
        self.inp=tk.Text(inner,bg=ELEVATED,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                         relief="flat",bd=0,font=F_BODY,height=2,
                         highlightthickness=1,highlightbackground=BORDER,
                         highlightcolor=ACCENT,wrap="word")
        self.inp.pack(side="left",fill="x",expand=True,ipady=6,padx=(0,8))
        self.inp.bind("<Return>",self._on_enter)
        self.send_btn=mk_btn(inner,"Send",self._send)
        self.send_btn.pack(side="right",ipady=6)
        self.send_btn.config(state="disabled")

    def enable_send(self):  self.send_btn.config(state="normal")
    def disable_send(self): self.send_btn.config(state="disabled")

    def _on_enter(self,e):
        if str(self.send_btn["state"])!="disabled": self._send()
        return "break"

    def _send(self):
        text=self.inp.get("1.0","end").strip()
        if not text or not self.app.session_aes_key or not self.app.conn_socket: return
        self.inp.delete("1.0","end")
        ts=datetime.datetime.now().strftime("%H:%M:%S")
        self._bubble(text,ts,mine=True,ok=True)
        threading.Thread(target=self._do_send,args=(text,),daemon=True).start()

    def _do_send(self,text):
        try:
            env=build_envelope(text.encode(),self.app.session_aes_key,
                               self.app.peer_public_key,self.app.private_key,
                               self.app.public_key,self.app.display_name)
            send_msg(self.app.conn_socket,env)
        except Exception as e:
            self.app.q.put({"type":"error","text":str(e)})

    def add_received(self,result,_env):
        if result["error"]:
            self._bubble(f"[ERR] {result['error']}",result["timestamp"],mine=False,ok=False,sender=result["sender_name"]); return
        text=result["plaintext"].decode(errors="replace")
        ok=result["integrity_ok"] and result["signature_ok"]
        self._bubble(text,result["timestamp"],mine=False,ok=ok,sender=result["sender_name"])

    def _bubble(self,text,ts,mine,ok,sender=None):
        outer=tk.Frame(self.msg_frame,bg=BG); outer.pack(fill="x",padx=12,pady=4)
        if mine:
            tk.Frame(outer,bg=BG).pack(side="left",expand=True,fill="x")
            bub=tk.Frame(outer,bg=BUBBLE_ME)
        else:
            bub=tk.Frame(outer,bg=BUBBLE_TH,highlightthickness=1,highlightbackground=BORDER)
            tk.Frame(outer,bg=BG).pack(side="right",expand=True,fill="x")
        bub.pack(side="right" if mine else "left",padx=(60 if mine else 0,0 if mine else 60))
        if sender and not mine:
            tk.Label(bub,text=sender,font=("Segoe UI",8,"bold"),
                     bg=BUBBLE_TH,fg=ACCENT).pack(anchor="w",padx=10,pady=(6,0))
        bbg=BUBBLE_ME if mine else BUBBLE_TH
        tk.Label(bub,text=text,font=F_BODY,bg=bbg,fg=TEXT_PRI,
                 wraplength=360,justify="left").pack(padx=10,pady=(6,2),anchor="w")
        meta=tk.Frame(bub,bg=bbg); meta.pack(fill="x",padx=10,pady=(0,6))
        tk.Label(meta,text=ts,font=F_MONO_S,bg=bbg,fg=TEXT_MUT).pack(side="left")
        chk=" ✓" if ok else " ✗"
        clr=SUCCESS if ok else ERROR
        tk.Label(meta,text=chk,font=F_MONO_S,bg=bbg,fg=clr).pack(side="left",padx=(4,0))
        # Scroll to bottom
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

# ─── Envelope Inspector Tab ───────────────────────────────────────────────────

class InspectorTab:
    """
    Step-by-step cryptographic dissection of the most recently received message.
    Steps unlock sequentially. A Reset button clears all state.
    """
    def __init__(self,notebook,app):
        self.app=app
        self.frame=tk.Frame(notebook,bg=BG)
        self._aes_key=None
        self._plaintext=None
        self._env=None
        self._build()

    def _build(self):
        title=tk.Frame(self.frame,bg=BG); title.pack(fill="x",padx=16,pady=(14,4))
        tk.Label(title,text="Envelope Inspector",font=F_HEAD,bg=BG,fg=TEXT_PRI).pack(side="left")
        mk_btn(title,"Reset",self._reset,primary=False).pack(side="right")

        outer=tk.Frame(self.frame,bg=BG); outer.pack(fill="both",expand=True)
        canvas=tk.Canvas(outer,bg=BG,bd=0,highlightthickness=0)
        vsb=ttk.Scrollbar(outer,orient="vertical",command=canvas.yview,
                          style="Slim.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); canvas.pack(side="left",fill="both",expand=True)
        self.scroll_frame=tk.Frame(canvas,bg=BG)
        win=canvas.create_window((0,0),window=self.scroll_frame,anchor="nw")
        self.scroll_frame.bind("<Configure>",lambda e:canvas.configure(
            scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfig(win,width=e.width))
        canvas.bind_all("<MouseWheel>",
            lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        self._build_steps()

    def _build_steps(self):
        p=self.scroll_frame
        # Step 1
        self.s1=self._step(p,"Step 1","Raw Envelope")
        self.s1_frame,self.s1_txt=mk_mono_box(self.s1,8,readonly=True)
        self.s1_frame.pack(fill="x",padx=12,pady=(0,12))
        tk.Label(self.s1,text="Waiting for a message to arrive…",font=F_CAP,
                 bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=12,pady=(0,10))

        # Step 2
        self.s2=self._step(p,"Step 2","Paste Your Private Key")
        tk.Label(self.s2,
            text="Paste your private_key.pem — headers are added automatically if you omit them",
            font=F_CAP,bg=ELEVATED,fg=TEXT_SEC).pack(anchor="w",padx=12,pady=(0,4))
        self.s2_frame,self.s2_txt=mk_mono_box(self.s2,6)
        self.s2_frame.pack(fill="x",padx=12,pady=(0,8))
        self.s2_err=tk.Label(self.s2,text="",font=F_CAP,bg=ELEVATED,fg=ERROR)
        self.s2_err.pack(anchor="w",padx=12)
        mk_btn(self.s2,"Confirm Key",self._step2_confirm,primary=False).pack(
            anchor="w",padx=12,pady=(6,12))

        # Step 3
        self.s3=self._step(p,"Step 3","Decrypt AES Session Key")
        mk_btn(self.s3,"Decrypt AES Key",self._step3,primary=False).pack(anchor="w",padx=12,pady=(6,4))
        self.s3_out=tk.Label(self.s3,text="",font=F_MONO,bg=ELEVATED,fg=TEXT_PRI,wraplength=640,justify="left")
        self.s3_out.pack(anchor="w",padx=12,pady=(0,12))

        # Step 4
        self.s4=self._step(p,"Step 4","Decrypt Message (AES-256-CBC)")
        mk_btn(self.s4,"Decrypt Message",self._step4,primary=False).pack(anchor="w",padx=12,pady=(6,4))
        self.s4_out=tk.Label(self.s4,text="",font=F_BODY,bg=ELEVATED,fg=TEXT_PRI,wraplength=640,justify="left")
        self.s4_out.pack(anchor="w",padx=12,pady=(0,12))

        # Step 5
        self.s5=self._step(p,"Step 5","Verify Integrity (SHA-256)")
        mk_btn(self.s5,"Verify Integrity",self._step5,primary=False).pack(anchor="w",padx=12,pady=(6,4))
        self.s5_out=tk.Label(self.s5,text="",font=("Segoe UI",10,"bold"),bg=ELEVATED,fg=TEXT_PRI)
        self.s5_out.pack(anchor="w",padx=12,pady=(0,12))

        # Step 6
        self.s6=self._step(p,"Step 6","Verify Signature (RSA-PSS)")
        mk_btn(self.s6,"Verify Signature",self._step6,primary=False).pack(anchor="w",padx=12,pady=(6,4))
        self.s6_out=tk.Label(self.s6,text="",font=("Segoe UI",10,"bold"),bg=ELEVATED,fg=TEXT_PRI)
        self.s6_out.pack(anchor="w",padx=12,pady=(0,12))

        self._lock_steps(1)

    def _step(self,parent,num,title):
        c=mk_card(parent); c.pack(fill="x",padx=16,pady=6)
        hdr=tk.Frame(c,bg=ELEVATED); hdr.pack(fill="x",padx=12,pady=(12,6))
        tk.Label(hdr,text=num,font=("Segoe UI",8,"bold"),bg=ELEVATED,fg=ACCENT).pack(side="left")
        tk.Label(hdr,text=f"  {title}",font=("Segoe UI",10,"bold"),bg=ELEVATED,fg=TEXT_PRI).pack(side="left")
        return c

    def _lock_steps(self,from_step):
        steps=[self.s2,self.s3,self.s4,self.s5,self.s6]
        for i,s in enumerate(steps,start=2):
            state="normal" if i<=from_step else "disabled"
            self._set_children_state(s,state)

    def _set_children_state(self,widget,state):
        try:
            if widget.winfo_class() in ("Button","Entry","Text"):
                widget.config(state=state)
        except Exception: pass
        for child in widget.winfo_children():
            self._set_children_state(child,state)

    def load_envelope(self,env):
        """Called when a new message arrives. Populates Step 1 and resets."""
        self._env=env; self._aes_key=None; self._plaintext=None
        self._pasted_priv=None
        pretty=json.dumps(env,indent=2)
        set_mono(self.s1_txt,pretty)
        # Remove 'waiting' label if present
        for w in self.s1.winfo_children():
            if isinstance(w,tk.Label) and "Waiting" in (w.cget("text") or ""): w.destroy()
        self._lock_steps(2)

    def _step2_confirm(self):
        pem=self.s2_txt.get("1.0","end").strip()
        if not pem:
            self.s2_err.config(text="Paste your private key first",fg=ERROR); return

        def _try(text):
            try: return load_private_key_from_pem(text)
            except Exception: return None

        priv=_try(pem)
        # Auto-wrap bare base64 (user copied key body without PEM headers)
        if priv is None and "-----" not in pem:
            raw="".join(pem.split())
            priv=(_try(f"-----BEGIN RSA PRIVATE KEY-----\n{raw}\n-----END RSA PRIVATE KEY-----")
                  or _try(f"-----BEGIN PRIVATE KEY-----\n{raw}\n-----END PRIVATE KEY-----"))

        if priv is not None:
            self._pasted_priv=priv
            self.s2_err.config(text="✓ Valid RSA private key",fg=SUCCESS)
            self._lock_steps(3)
        else:
            self.s2_err.config(
                text="Key validation failed — paste the full private_key.pem file content",
                fg=ERROR)

    def _step3(self):
        if not self._env or not self._pasted_priv: return
        try:
            ek=base64.b64decode(self._env["aes_key_encrypted"])
            self._aes_key=unwrap_aes_key(ek,self._pasted_priv)
            self.s3_out.config(text=f"AES Key (hex): {self._aes_key.hex()}",fg=SUCCESS)
            self._lock_steps(4)
        except Exception as e:
            self.s3_out.config(text=f"Decryption failed: key mismatch or corrupted envelope\n{e}",fg=ERROR)

    def _step4(self):
        if not self._env or not self._aes_key: return
        try:
            ct=base64.b64decode(self._env["ciphertext"])
            iv=base64.b64decode(self._env["iv"])
            self._plaintext=decrypt_aes_cbc(ct,self._aes_key,iv)
            self.s4_out.config(text=self._plaintext.decode(errors="replace"),fg=SUCCESS)
            self._lock_steps(5)
        except Exception as e:
            self.s4_out.config(text=f"Decryption error: {e}",fg=ERROR)

    def _step5(self):
        if not self._env or not self._plaintext: return
        computed=sha256_hex(self._plaintext)
        expected=self._env.get("message_hash","")
        if computed==expected:
            self.s5_out.config(text="✓ MATCH — Hash verified",fg=SUCCESS)
        else:
            self.s5_out.config(
                text="✗ MISMATCH — Hash does not match. Message may have been altered in transit.",
                fg=ERROR)
        self._lock_steps(6)  # Always unlock Step 6 so the demo can complete all steps

    def _step6(self):
        if not self._env or not self._plaintext: return
        try:
            sig=base64.b64decode(self._env["signature"])
            spub=load_public_key_from_pem(self._env["sender_public_key"])
            ok=verify_rsa_pss(self._plaintext,sig,spub)
            if ok:
                self.s6_out.config(text="✓ SIGNATURE VALID — Sender identity confirmed",fg=SUCCESS)
            else:
                self.s6_out.config(
                    text="✗ SIGNATURE INVALID — Signature verification failed. Cannot confirm sender identity.",
                    fg=ERROR)
        except Exception as e:
            self.s6_out.config(text=f"Error: {e}",fg=ERROR)

    def _reset(self):
        self._env=None; self._aes_key=None; self._plaintext=None
        self._pasted_priv=None
        set_mono(self.s1_txt,"")
        self.s2_txt.config(state="normal"); self.s2_txt.delete("1.0","end")
        self.s2_err.config(text="")
        self.s3_out.config(text=""); self.s4_out.config(text="")
        self.s5_out.config(text=""); self.s6_out.config(text="")
        self._lock_steps(1)

# ─── File Encryption Tab ──────────────────────────────────────────────────────

class FileTab:
    """
    Local AES-256-CBC file encrypt / decrypt panel.
    Uses the current session AES key. No network transfer.
    """
    def __init__(self,notebook,app):
        self.app=app; self.enc_path=None; self.dec_path=None
        self.frame=tk.Frame(notebook,bg=BG)
        self._build()

    def _build(self):
        tk.Label(self.frame,text="File Encryption",font=F_HEAD,bg=BG,fg=TEXT_PRI).pack(
            anchor="w",padx=16,pady=(14,4))
        tk.Label(self.frame,text="AES-256-CBC · uses current session key · local only",
                 font=F_CAP,bg=BG,fg=TEXT_SEC).pack(anchor="w",padx=16,pady=(0,12))

        cols=tk.Frame(self.frame,bg=BG); cols.pack(fill="both",expand=True,padx=16,pady=8)

        # Left — Encrypt
        lc=mk_card(cols); lc.pack(side="left",fill="both",expand=True,padx=(0,8))
        tk.Label(lc,text="ENCRYPT",font=("Segoe UI",8,"bold"),bg=ELEVATED,fg=TEXT_MUT).pack(
            anchor="w",padx=14,pady=(14,2))
        mk_btn(lc,"Choose File",self._enc_pick,primary=False).pack(anchor="w",padx=14,pady=6)
        self.enc_lbl=tk.Label(lc,text="No file selected",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC)
        self.enc_lbl.pack(anchor="w",padx=14)
        mk_btn(lc,"Encrypt File",self._enc_run).pack(anchor="w",padx=14,pady=8)
        self.enc_out=tk.Label(lc,text="",font=F_MONO_S,bg=ELEVATED,fg=TEXT_PRI,
                              wraplength=280,justify="left")
        self.enc_out.pack(anchor="w",padx=14,pady=(0,14))

        # Right — Decrypt
        rc=mk_card(cols); rc.pack(side="left",fill="both",expand=True,padx=(8,0))
        tk.Label(rc,text="DECRYPT",font=("Segoe UI",8,"bold"),bg=ELEVATED,fg=TEXT_MUT).pack(
            anchor="w",padx=14,pady=(14,2))
        mk_btn(rc,"Choose .enc File",self._dec_pick,primary=False).pack(anchor="w",padx=14,pady=6)
        self.dec_lbl=tk.Label(rc,text="No file selected",font=F_CAP,bg=ELEVATED,fg=TEXT_SEC)
        self.dec_lbl.pack(anchor="w",padx=14)
        mk_btn(rc,"Decrypt File",self._dec_run).pack(anchor="w",padx=14,pady=8)
        self.dec_out=tk.Label(rc,text="",font=F_MONO_S,bg=ELEVATED,fg=TEXT_PRI,
                              wraplength=280,justify="left")
        self.dec_out.pack(anchor="w",padx=14,pady=(0,14))

    def _enc_pick(self):
        p=filedialog.askopenfilename(title="Choose file to encrypt")
        if not p: return
        self.enc_path=p
        sz=os.path.getsize(p)
        self.enc_lbl.config(text=f"{os.path.basename(p)}  ({sz:,} bytes)",fg=TEXT_PRI)
        self.enc_out.config(text="")

    def _enc_run(self):
        if not self.enc_path: self.enc_out.config(text="Select a file first",fg=WARNING); return
        if not self.app.session_aes_key:
            self.enc_out.config(text="No session key — connect first",fg=ERROR); return
        try:
            with open(self.enc_path,"rb") as f: data=f.read()
            iv=generate_iv(); ct=encrypt_aes_cbc(data,self.app.session_aes_key,iv)
            out=self.enc_path+".enc"
            out=_safe_write(out,iv+ct)  # Prepend IV to ciphertext for storage
            sz_enc=os.path.getsize(out)
            hex_prev=(iv+ct)[:64].hex()
            self.enc_out.config(
                text=(f"Saved: {os.path.basename(out)}\n"
                      f"Size: {sz_enc:,} bytes\n"
                      f"IV:   {iv.hex()}\n"
                      f"Preview (64B hex):\n{hex_prev}"),
                fg=SUCCESS)
        except Exception as e:
            self.enc_out.config(text=f"Encryption error: {e}",fg=ERROR)

    def _dec_pick(self):
        p=filedialog.askopenfilename(title="Choose encrypted file",
                                     filetypes=[("Encrypted","*.enc"),("All","*.*")])
        if not p: return
        self.dec_path=p
        sz=os.path.getsize(p)
        self.dec_lbl.config(text=f"{os.path.basename(p)}  ({sz:,} bytes)",fg=TEXT_PRI)
        self.dec_out.config(text="")

    def _dec_run(self):
        if not self.dec_path: self.dec_out.config(text="Select a file first",fg=WARNING); return
        if not self.app.session_aes_key:
            self.dec_out.config(text="No session key — connect first",fg=ERROR); return
        try:
            with open(self.dec_path,"rb") as f: raw=f.read()
            if len(raw)<17: raise ValueError("File too small to contain IV")
            iv=raw[:16]; ct=raw[16:]
            pt=decrypt_aes_cbc(ct,self.app.session_aes_key,iv)
            # Build output filename
            base=self.dec_path
            if base.endswith(".enc"): base=base[:-4]
            name,ext=os.path.splitext(base)
            out=_safe_write(name+"_decrypted"+ext,pt)
            self.dec_out.config(
                text=f"✓ Decrypted successfully\nSaved: {os.path.basename(out)}",
                fg=SUCCESS)
        except Exception as e:
            self.dec_out.config(text=f"Decryption failed: {e}",fg=ERROR)

# ─── Main Application ─────────────────────────────────────────────────────────

class SecureCommApp:
    """
    Orchestrates startup dialog, networking handshake, and the main window.
    All network I/O runs on daemon threads. GUI updates arrive via self.q.
    """

    def __init__(self,root):
        self.root=root
        self.root.withdraw()
        # Shared state — written by network thread, read by GUI thread
        self.private_key=None; self.public_key=None
        self.peer_public_key=None
        self.session_aes_key=None   # AES-256 session key
        self.conn_socket=None       # active TCP socket
        self.role=None              # "server" | "client"
        self.display_name=""
        self.server_ip=""
        self.q=queue.Queue()        # thread-safe message queue → GUI
        # Run startup, then build window
        dlg=StartupDialog(root,self)
        root.wait_window(dlg.window)
        if self.role:
            self._build_window()
            self._apply_styles()
            threading.Thread(target=self._net_thread,daemon=True).start()
            root.deiconify()
            self._poll()
        else:
            root.destroy()

    # ── Window layout ─────────────────────────────────────────────────────────
    def _build_window(self):
        self.root.title(f"SecureComm — {self.display_name}")
        self.root.geometry("960x660"); self.root.minsize(800,560)
        self.root.configure(bg=BG)

        # Header
        hdr=tk.Frame(self.root,bg=SURFACE,height=46); hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr,text="SecureComm",font=("Segoe UI",13,"bold"),
                 bg=SURFACE,fg=TEXT_PRI).pack(side="left",padx=16,pady=10)
        role_lbl=f"{'Server' if self.role=='server' else 'Client'}  ·  {self.display_name}"
        tk.Label(hdr,text=role_lbl,font=F_BODY,bg=SURFACE,fg=TEXT_SEC).pack(side="left",pady=10)
        tk.Frame(self.root,bg=BORDER,height=1).pack(fill="x")

        # Notebook
        self.nb=ttk.Notebook(self.root,style="Custom.TNotebook")
        self.nb.pack(fill="both",expand=True)
        self.chat_tab=ChatTab(self.nb,self)
        self.insp_tab=InspectorTab(self.nb,self)
        self.file_tab=FileTab(self.nb,self)
        self.nb.add(self.chat_tab.frame,text="  Live Chat  ")
        self.nb.add(self.insp_tab.frame,text="  Envelope Inspector  ")
        self.nb.add(self.file_tab.frame,text="  File Encryption  ")

        # Status bar
        tk.Frame(self.root,bg=BORDER,height=1).pack(fill="x",side="bottom")
        sb=tk.Frame(self.root,bg=SURFACE,height=26); sb.pack(fill="x",side="bottom")
        sb.pack_propagate(False)
        self.dot=tk.Label(sb,text="●",font=("Segoe UI",9),bg=SURFACE,fg=ERROR)
        self.dot.pack(side="left",padx=(12,4))
        self.status_lbl=tk.Label(sb,text="Waiting for connection…",
                                 font=F_CAP,bg=SURFACE,fg=TEXT_SEC)
        self.status_lbl.pack(side="left")
        tk.Label(sb,text="AES-256-CBC  ·  RSA-2048  ·  RSA-PSS",
                 font=F_MONO_S,bg=SURFACE,fg=TEXT_MUT).pack(side="right",padx=12)

    def _apply_styles(self):
        s=ttk.Style(); s.theme_use("default")
        s.configure("Custom.TNotebook",background=BG,borderwidth=0,tabmargins=[0,0,0,0])
        s.configure("Custom.TNotebook.Tab",background=BG,foreground=TEXT_MUT,
                    padding=[16,8],font=("Segoe UI",10),borderwidth=0)
        s.map("Custom.TNotebook.Tab",
              background=[("selected",BG),("active",SURFACE)],
              foreground=[("selected",ACCENT),("active",TEXT_PRI)])
        s.configure("Slim.Vertical.TScrollbar",background=BORDER,troughcolor=BG,
                    borderwidth=0,arrowsize=0,width=5)
        s.map("Slim.Vertical.TScrollbar",background=[("active","#444444")])

    def _set_status(self,text,connected):
        self.dot.config(fg=SUCCESS if connected else ERROR)
        self.status_lbl.config(text=text)

    # ── Networking ────────────────────────────────────────────────────────────
    def _net_thread(self):
        try:
            if self.role=="server": self._run_server()
            else:                   self._run_client()
        except Exception as e:
            self.q.put({"type":"error","text":str(e)})

    def _run_server(self):
        srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        srv.bind(("0.0.0.0",PORT)); srv.listen(1)
        self.q.put({"type":"status","text":f"Listening on :{PORT}…","connected":False})
        conn,addr=srv.accept()
        srv.close()  # Only one connection accepted; release the listening socket
        self.conn_socket=conn
        # Handshake: exchange public keys
        send_msg(conn,{"op":"pubkey",
                       "key":serialize_public_key(self.public_key).decode(),
                       "name":self.display_name})
        cli=recv_msg(conn)
        self.peer_public_key=load_public_key_from_pem(cli["key"])
        peer_name=cli.get("name","Client")
        # Receive AES key (client generates and sends it)
        km=recv_msg(conn)
        self.session_aes_key=unwrap_aes_key(
            base64.b64decode(km["aes_key_encrypted"]),self.private_key)
        self.q.put({"type":"connected","peer":peer_name,"addr":addr[0]})
        self._recv_loop(conn)

    def _run_client(self):
        conn=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        conn.settimeout(10)
        self.q.put({"type":"status","text":f"Connecting to {self.server_ip}…","connected":False})
        try:
            conn.connect((self.server_ip,PORT))
        except (socket.timeout, TimeoutError):
            conn.close()
            self.q.put({"type":"conn_failed","reason":"timeout","ip":self.server_ip}); return
        except ConnectionRefusedError:
            conn.close()
            self.q.put({"type":"conn_failed","reason":"refused","ip":self.server_ip}); return
        except OSError as e:
            conn.close()
            self.q.put({"type":"conn_failed","reason":str(e),"ip":self.server_ip}); return
        conn.settimeout(None)  # Switch to blocking mode for recv loop
        self.conn_socket=conn
        # Receive server public key
        srv_msg=recv_msg(conn)
        self.peer_public_key=load_public_key_from_pem(srv_msg["key"])
        peer_name=srv_msg.get("name","Server")
        # Send our public key
        send_msg(conn,{"op":"pubkey",
                       "key":serialize_public_key(self.public_key).decode(),
                       "name":self.display_name})
        # Generate AES session key, wrap with server's public key, send
        self.session_aes_key=generate_aes_key()
        ek=wrap_aes_key(self.session_aes_key,self.peer_public_key)
        send_msg(conn,{"op":"aeskey","aes_key_encrypted":base64.b64encode(ek).decode()})
        self.q.put({"type":"connected","peer":peer_name,"addr":self.server_ip})
        self._recv_loop(conn)

    def _recv_loop(self,conn):
        """Background loop: receive envelopes and push to GUI queue."""
        while True:
            try:
                env=recv_msg(conn)
                result=parse_envelope(env,self.private_key)
                self.q.put({"type":"msg","result":result,"env":env})
            except Exception as e:
                self.q.put({"type":"disconnected","text":str(e)}); break

    # ── GUI poll ──────────────────────────────────────────────────────────────
    def _poll(self):
        """Drain the message queue and update the GUI. Called every 50 ms."""
        try:
            while True:
                item=self.q.get_nowait()
                t=item["type"]
                if t=="status":
                    self._set_status(item["text"],item.get("connected",False))
                elif t=="connected":
                    peer=item.get("peer","Peer"); addr=item.get("addr","")
                    self._set_status(f"Connected  ·  {peer}  ({addr})",True)
                    self.chat_tab.enable_send()
                elif t=="msg":
                    result=item["result"]; env=item["env"]
                    self.chat_tab.add_received(result,env)
                    self.insp_tab.load_envelope(env)
                elif t=="conn_failed":
                    reason=item.get("reason",""); ip=item.get("ip","?")
                    if reason=="timeout":
                        hint=(f"Could not reach server at {ip}:{PORT} (timed out).\n\n"
                              "Things to check:\n"
                              "1. Start the SERVER app first, then the client\n"
                              "2. Both machines must be on the same WiFi\n"
                              "3. Run this as Admin on the SERVER machine:\n"
                              "   netsh advfirewall firewall add rule "
                              "name=\"SecureComm\" dir=in action=allow "
                              "protocol=TCP localport=65432\n"
                              "4. Double-check the IP address")
                    elif reason=="refused":
                        hint=(f"Connection to {ip}:{PORT} was refused.\n\n"
                              "The server app is not running yet.\n"
                              "Start the SERVER first, wait for it to show\n"
                              "'Listening on :65432…', then click Retry.")
                    else:
                        hint=f"Connection failed: {reason}"
                    self._set_status(f"Failed to connect to {ip}",False)
                    retry=messagebox.askretrycancel("Connection Failed",hint)
                    if retry:
                        new_ip=simpledialog.askstring("Retry",
                            "Server IP address:",initialvalue=ip,parent=self.root)
                        if new_ip and new_ip.strip():
                            self.server_ip=new_ip.strip()
                        self._set_status(f"Retrying {self.server_ip}…",False)
                        threading.Thread(target=self._net_thread,daemon=True).start()
                    else:
                        self._set_status("Not connected — click Retry or restart",False)
                elif t=="disconnected":
                    self._set_status("Disconnected",False)
                    self.chat_tab.disable_send()
                    messagebox.showerror("Connection Lost",
                        "Connection lost — restart both apps to reconnect.")
                elif t=="error":
                    messagebox.showerror("Error",item.get("text","Unknown error"))
        except queue.Empty:
            pass
        self.root.after(50,self._poll)

# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__=="__main__":
    root=tk.Tk()
    root.title("SecureComm")
    root.configure(bg=BG)
    app=SecureCommApp(root)
    root.mainloop()
