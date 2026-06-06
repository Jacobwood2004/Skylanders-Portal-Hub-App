"""
Skylanders Portal Manager — VirtPort Edition
Talks directly to VirtPort's modified Cemu over HTTP.
No file pickers. No Load buttons. Just click and it loads.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, json, threading, hashlib, time, re, sys
import queue as _queue_mod
try:
    import urllib.request as _urllib
    import urllib.parse as _urlparse
    URLLIB_OK = True
except ImportError:
    URLLIB_OK = False

# ── Global keyboard hook (requires admin on Windows) ──
try:
    import keyboard as _keyboard
    KEYBOARD_OK = True
except ImportError:
    KEYBOARD_OK = False


def _is_admin():
    """Check if running as administrator on Windows."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _active_window_is_allowed():
    """
    Returns True only if Cemu or Skylanders Portal is the foreground window.
    Called synchronously from the keyboard hook thread.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        user32 = ctypes.windll.user32

        # Get foreground window handle
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return False

        # Get window title
        title_buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title_buf, 256)
        title = title_buf.value.lower()

        # Get process name for extra accuracy
        pid = ctypes.c_ulong(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        try:
            import ctypes.wintypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_INFO = 0x1000
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFO, False, pid.value)
            proc_buf = ctypes.create_unicode_buffer(256)
            size = ctypes.c_ulong(256)
            ctypes.windll.kernel32.QueryFullProcessImageNameW(
                h_proc, 0, proc_buf, ctypes.byref(size))
            kernel32.CloseHandle(h_proc)
            proc_name = proc_buf.value.lower()
        except Exception:
            proc_name = ""

        # Allow if title or process name matches
        allowed_titles = ("cemu", "skylanders portal", "emulated usb")
        allowed_procs  = ("cemu.exe", "skylanders_portal", "python")

        title_ok = any(k in title for k in allowed_titles)
        proc_ok  = any(k in proc_name for k in allowed_procs)

        return title_ok or proc_ok
    except Exception:
        return False   # fail closed — don't fire if we can't check

IS_ADMIN = _is_admin()

# ── Foreground window PID cache for keybind focus check ──
_fg_pid_cache = [0]
_ALLOWED_PIDS: set = set()
_CEMU_EXE_NAMES = {"cemu.exe", "cemu sky.exe", "cemu_virtport.exe", "cemu-virtport.exe"}

def _find_cemu_pids():
    found = set()
    if sys.platform != "win32": return found
    try:
        import ctypes, ctypes.wintypes
        kernel32 = ctypes.windll.kernel32
        user32   = ctypes.windll.user32
        TH32CS_SNAPPROCESS = 0x00000002
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [("dwSize",ctypes.wintypes.DWORD),("cntUsage",ctypes.wintypes.DWORD),
                        ("th32ProcessID",ctypes.wintypes.DWORD),("th32DefaultHeapID",ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID",ctypes.wintypes.DWORD),("cntThreads",ctypes.wintypes.DWORD),
                        ("th32ParentProcessID",ctypes.wintypes.DWORD),("pcPriClassBase",ctypes.c_long),
                        ("dwFlags",ctypes.wintypes.DWORD),("szExeFile",ctypes.c_char*260)]
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap != ctypes.wintypes.HANDLE(-1).value:
            entry = PROCESSENTRY32(); entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if kernel32.Process32First(snap, ctypes.byref(entry)):
                while True:
                    name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
                    if name in _CEMU_EXE_NAMES or name.startswith("cemu"):
                        found.add(entry.th32ProcessID)
                    if not kernel32.Process32Next(snap, ctypes.byref(entry)): break
            kernel32.CloseHandle(snap)
        title_buf = ctypes.create_unicode_buffer(256)
        pid_buf   = ctypes.c_ulong(0)
        def enum_cb(hwnd, _):
            user32.GetWindowTextW(hwnd, title_buf, 256)
            if "cemu" in title_buf.value.lower():
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
                if pid_buf.value: found.add(pid_buf.value)
            return True
        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        user32.EnumWindows(EnumWindowsProc(enum_cb), 0)
    except Exception as e:
        pass
    return found

def _is_pid_alive(pid):
    if sys.platform != "win32": return False
    try:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h: return False
        ec = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(ec))
        ctypes.windll.kernel32.CloseHandle(h)
        return ec.value == 259
    except: return False

def _start_fg_pid_poller():
    if sys.platform != "win32": return
    import ctypes
    user32 = ctypes.windll.user32
    def poll():
        global _ALLOWED_PIDS
        cemu_pids_found = set()
        last_cemu_scan  = 0.0
        cemu_confirmed  = False
        no_pad_logged   = False
        while True:
            now = time.time()
            try:
                hwnd = user32.GetForegroundWindow()
                if hwnd:
                    pid_buf = ctypes.c_ulong(0)
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
                    _fg_pid_cache[0] = pid_buf.value
                else: _fg_pid_cache[0] = 0
            except: _fg_pid_cache[0] = 0
            if now - last_cemu_scan >= 2.0:
                try:
                    title_buf = ctypes.create_unicode_buffer(256)
                    pid_buf2  = ctypes.c_ulong(0)
                    new_pids  = set()
                    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
                    def enum_cb(hwnd, _):
                        user32.GetWindowTextW(hwnd, title_buf, 256)
                        if "cemu" in title_buf.value.lower():
                            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf2))
                            if pid_buf2.value: new_pids.add(pid_buf2.value)
                        return True
                    user32.EnumWindows(EnumWindowsProc(enum_cb), 0)
                    added = new_pids - cemu_pids_found
                    if added:
                        cemu_pids_found.update(added); _ALLOWED_PIDS.update(added)
                        _dbg(f"Cemu window found: pids={added}"); cemu_confirmed = True
                    if cemu_confirmed and not new_pids:
                        _ALLOWED_PIDS -= cemu_pids_found; cemu_pids_found.clear(); cemu_confirmed = False
                    elif cemu_confirmed:
                        gone = cemu_pids_found - new_pids
                        if gone: _ALLOWED_PIDS -= gone; cemu_pids_found -= gone
                except Exception as ex: _dbg(f"Cemu scan error: {ex}")
                last_cemu_scan = now
            time.sleep(0.1)
    t = threading.Thread(target=poll, daemon=True); t.start()

def _active_window_is_allowed():
    global _ALLOWED_PIDS
    if sys.platform != "win32": return True
    try:
        fg_pid = _fg_pid_cache[0]
        if not fg_pid: return False
        allowed = fg_pid in _ALLOWED_PIDS
        _dbg(f"KEYBIND CHECK: fg_pid={fg_pid} allowed={_ALLOWED_PIDS} -> {'ALLOW' if allowed else 'BLOCK'}")
        return allowed
    except Exception as e:
        _dbg(f"KEYBIND EXCEPTION: {e}"); return False

# ── Controller support ──
try:
    import inputs as _inputs
    INPUTS_OK = True
except ImportError:
    INPUTS_OK = False

_BTN_RS   = {"BTN_THUMBR"}
_BTN_DPAD = {"up":{"ABS_HAT0Y_neg","BTN_DPAD_UP"},"down":{"ABS_HAT0Y_pos","BTN_DPAD_DOWN"},
             "left":{"ABS_HAT0X_neg","BTN_DPAD_LEFT"},"right":{"ABS_HAT0X_pos","BTN_DPAD_RIGHT"}}
_ctrl_pick_mode     = False
_ctrl_pick_timer    = None
_ctrl_callback      = None       # fn(direction) -> load
_ctrl_cancel_cb     = None       # fn("open"/"close"/"cycle")
_ctrl_wheel_enabled = [False]
_ctrl_rs_last_fire  = [0.0]
_ctrl_dpad_last_fire= [0.0]
_ctrl_wheel_index   = [0]        # which wheel preset is currently shown
_ctrl_wheel_presets = [[]]       # list of preset dicts for active category
_ctrl_active_category = ["Other"]  # currently active category

def _ctrl_enter_pick_mode():
    """RS click: if wheel closed → open first/last preset.
       If wheel open → cycle to next preset, close if we've gone through all."""
    global _ctrl_pick_mode, _ctrl_pick_timer
    if not _ctrl_wheel_enabled[0]: return
    now = time.time()
    if now - _ctrl_rs_last_fire[0] < 0.6: return
    _ctrl_rs_last_fire[0] = now
    if not _active_window_is_allowed(): return

    presets = _ctrl_wheel_presets[0]
    if not presets:
        if _ctrl_cancel_cb: _ctrl_cancel_cb("no_presets")
        return

    if not _ctrl_pick_mode:
        # Open wheel on first preset
        _ctrl_wheel_index[0] = 0
        _ctrl_pick_mode = True
        if _ctrl_cancel_cb: _ctrl_cancel_cb("open")
        _dbg(f"Controller: wheel opened — preset 1/{len(presets)}")
        # Auto-cancel after 3s
        _ctrl_pick_timer = threading.Timer(3.0, _ctrl_cancel_pick)
        _ctrl_pick_timer.daemon = True; _ctrl_pick_timer.start()
    else:
        # Already open — cycle to next preset
        if _ctrl_pick_timer:
            try: _ctrl_pick_timer.cancel()
            except: pass
        next_idx = _ctrl_wheel_index[0] + 1
        if next_idx >= len(presets):
            # Cycled through all — close
            _ctrl_pick_mode = False
            _ctrl_pick_timer = None
            if _ctrl_cancel_cb: _ctrl_cancel_cb("close")
            _dbg("Controller: wheel closed (cycled through all presets)")
        else:
            _ctrl_wheel_index[0] = next_idx
            if _ctrl_cancel_cb: _ctrl_cancel_cb("cycle")
            _dbg(f"Controller: wheel cycled to preset {next_idx+1}/{len(presets)}")
            # Restart timer
            _ctrl_pick_timer = threading.Timer(3.0, _ctrl_cancel_pick)
            _ctrl_pick_timer.daemon = True; _ctrl_pick_timer.start()

def _ctrl_cancel_pick():
    global _ctrl_pick_mode, _ctrl_pick_timer
    _ctrl_pick_mode = False
    if _ctrl_pick_timer:
        try: _ctrl_pick_timer.cancel()
        except: pass
        _ctrl_pick_timer = None
    if _ctrl_cancel_cb: _ctrl_cancel_cb("close")
    _dbg("Controller: wheel closed")

def _ctrl_fire(direction):
    global _ctrl_pick_mode
    if not _ctrl_pick_mode: return
    now = time.time()
    if now - _ctrl_dpad_last_fire[0] < 0.4: return
    _ctrl_dpad_last_fire[0] = now
    _ctrl_cancel_pick()
    if _ctrl_callback: _ctrl_callback(direction)
    _dbg(f"Controller: fired direction={direction}")

def _normalise_event(ev):
    names = set()
    try:
        code = ev.code; val = ev.state; etype = ev.ev_type
        if etype == "Key":
            if code in _BTN_RS:
                if val in (0, 1): names.add(code)
            elif val == 1: names.add(code)
        elif etype == "Absolute":
            if code == "ABS_HAT0Y":
                if val == -1: names.add("ABS_HAT0Y_neg")
                elif val == 1: names.add("ABS_HAT0Y_pos")
            elif code == "ABS_HAT0X":
                if val == -1: names.add("ABS_HAT0X_neg")
                elif val == 1: names.add("ABS_HAT0X_pos")
        # Any other event type (Misc, Sync, etc.) — silently ignore
    except Exception:
        pass
    return names

def _start_controller_thread():
    if not INPUTS_OK: return
    def run():
        _dbg("Controller thread started")
        no_pad_logged = False
        while True:
            try:
                if not _ctrl_wheel_enabled[0]: time.sleep(1); continue
                gamepads = _inputs.devices.gamepads
                if not gamepads:
                    if not no_pad_logged:
                        _dbg("CTRL: no gamepad detected")
                        no_pad_logged = True
                    try: _inputs.devices.__init__()
                    except: pass
                    time.sleep(5); continue
                if no_pad_logged:
                    _dbg("CTRL: gamepad connected"); no_pad_logged = False
                events = _inputs.get_gamepad()
                for ev in events:
                    try:
                        if ev.code == "SYN_REPORT": continue
                        vnames = _normalise_event(ev)
                        for vn in vnames:
                            if vn in _BTN_RS: _ctrl_enter_pick_mode()
                            for direction, aliases in _BTN_DPAD.items():
                                if vn in aliases: _ctrl_fire(direction)
                    except Exception:
                        pass  # skip individual bad events silently
            except Exception as e:
                err = str(e)
                # Suppress the noisy "We don't know what kind of event" spam
                if "don't know what kind of event" not in err:
                    _dbg(f"CTRL thread exception: {err}")
                no_pad_logged = False
                time.sleep(0.5)
    t = threading.Thread(target=run, daemon=True); t.start()

# ─────────────────────────────────────────────
# DEBUG LOG
# ─────────────────────────────────────────────
_debug_log = []
def _dbg(msg):
    import time as _t
    line = f"[{_t.strftime('%H:%M:%S')}] {msg}"
    _debug_log.append(line)
    print(line)

# Start after _dbg is defined
_ALLOWED_PIDS.add(os.getpid())
_start_fg_pid_poller()
_start_controller_thread()

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

# All save data in one AppData folder
APP_DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "SkylandersPortal")
os.makedirs(APP_DATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")
CACHE_FILE  = os.path.join(APP_DATA_DIR, "cache.json")

THEMES_DIR = os.path.join(APP_DATA_DIR, "themes")
os.makedirs(THEMES_DIR, exist_ok=True)

def save_theme(name, cfg):
    keys = ["theme_accent","theme_bg","theme_card","theme_hover",
            "theme_text","theme_text2","theme_border","theme_scrollbar"]
    theme = {k: cfg.get(k) for k in keys if cfg.get(k)}
    theme["name"] = name
    with open(os.path.join(THEMES_DIR, f"{name}.json"), "w") as f:
        json.dump(theme, f, indent=2)

def list_themes():
    themes = []
    for fname in os.listdir(THEMES_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(THEMES_DIR, fname)) as f:
                    themes.append(json.load(f))
            except Exception: pass
    return sorted(themes, key=lambda x: x.get("name",""))

def load_theme_to_cfg(theme_data, cfg):
    for k in ["theme_accent","theme_bg","theme_card","theme_hover",
              "theme_text","theme_text2","theme_border","theme_scrollbar"]:
        if k in theme_data:
            cfg[k] = theme_data[k]

def save_keybind_preset(name, keybinds):
    path = os.path.join(PRESETS_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump({"name": name, "keybinds": keybinds}, f, indent=2)

def list_keybind_presets():
    presets = []
    for fname in os.listdir(PRESETS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(PRESETS_DIR, fname)) as f:
                    presets.append(json.load(f))
            except Exception: pass
    return sorted(presets, key=lambda x: x.get("name",""))

def delete_keybind_preset(name):
    try: os.remove(os.path.join(PRESETS_DIR, f"{name}.json"))
    except Exception: pass

# ── Keybind presets ──────────────────────────────────────────────────────────
PRESETS_DIR = os.path.join(APP_DATA_DIR, "presets")
os.makedirs(PRESETS_DIR, exist_ok=True)

# ── Controller wheel presets ──────────────────────────────────────────────────
CTRL_PRESETS_DIR = os.path.join(APP_DATA_DIR, "ctrl_presets")
os.makedirs(CTRL_PRESETS_DIR, exist_ok=True)

CTRL_WHEEL_GAMES = ["Spyro's Adventure","Giants","Swap Force","Trap Team","SuperChargers","Imaginators","Other"]

def save_ctrl_preset(name, ctrl_binds, trigger_code, category="Other"):
    path = os.path.join(CTRL_PRESETS_DIR, f"{name}.json")
    with open(path,"w") as f:
        json.dump({"name":name,"ctrl_binds":ctrl_binds,
                   "trigger_code":trigger_code,"category":category},f,indent=2)

def list_ctrl_presets(category=None):
    presets=[]
    for fname in os.listdir(CTRL_PRESETS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(CTRL_PRESETS_DIR,fname)) as f:
                    p=json.load(f)
                if category is None or p.get("category","Other")==category:
                    presets.append(p)
            except: pass
    return sorted(presets,key=lambda x:x.get("name",""))

def delete_ctrl_preset(name):
    try: os.remove(os.path.join(CTRL_PRESETS_DIR,f"{name}.json"))
    except: pass

def get_ctrl_active_category(cfg):
    return cfg.get("ctrl_active_category","Other")

def set_ctrl_active_category(cfg, cat):
    cfg["ctrl_active_category"] = cat


GAME_FOLDER_HINTS    = ["Spyros Adventure","Giants","Swap Force","Trap Team","SuperChargers","Imaginators"]
GAME_DISPLAY_NAMES   = {
    "Spyros Adventure":"Spyro's Adventure","Giants":"Giants","Swap Force":"Swap Force",
    "Trap Team":"Trap Team","SuperChargers":"SuperChargers","Imaginators":"Imaginators","Unknown":"Other",
}
GAME_COLORS = {
    "Spyros Adventure":"#4a90d9","Giants":"#e8a020","Swap Force":"#3dba6f",
    "Trap Team":"#c0392b","SuperChargers":"#8e44ad","Imaginators":"#e67e22",
    "Favorites":"#e91e8c","All":"#555e6e","Vehicles":"#2196F3","Unknown":"#555e6e",
}
ELEMENT_COLORS = {
    "fire":   "#e74c3c",
    "water":  "#2980b9",
    "earth":  "#8B6914",
    "air":    "#85c1e9",
    "life":   "#27ae60",
    "undead": "#4a4a4a",
    "tech":   "#f39c12",
    "magic":  "#8e44ad",
    "light":  "#f7dc6f",
    "dark":   "#1a1a2e",
}
ELEMENT_NAME_MAP = {
    "eruptor":"fire","flameslinger":"fire","ignitor":"fire","sunburn":"fire",
    "hot head":"fire","fire kraken":"fire","fryno":"fire","smolderdash":"fire",
    "ka-boom":"fire","torch":"fire","wildfire":"fire","spitfire":"fire",
    "blast zone":"fire","food fight":"fire","trail blazer":"fire",
    "hot streak":"fire","burn-cycle":"fire","crypt crusher":"fire",
    "gill grunt":"water","zap":"water","slam bam":"water","chill":"water",
    "thumpback":"water","wash buckler":"water","rattle shake":"water",
    "freeze blade":"water","snap shot":"water","lob-star":"water",
    "dive-clops":"water","reef ripper":"water","soda skimmer":"water",
    "dive bomber":"water","splatter splasher":"water","punk shock":"water",
    "prism break":"earth","bash":"earth","dino-rang":"earth","crusher":"earth",
    "flashwing":"earth","slobber tooth":"earth","scorp":"earth","rubble rouser":"earth",
    "doom stone":"earth","wallop":"earth","head rush":"earth","smash hit":"earth",
    "thump truck":"earth","terrafin":"earth","shark tank":"earth","gold rusher":"earth",
    "rocky roll":"earth",
    "jet-vac":"air","whirlwind":"air","sonic boom":"air","warnado":"air",
    "lightning rod":"air","swarm":"air","boom jet":"air","free ranger":"air",
    "fling kong":"air","stormblade":"air","sky slicer":"air","stealth stinger":"air",
    "buzz wing":"air","jet stream":"air","sun runner":"air","astroblast":"air",
    "fiesta":"air",
    "stealth elf":"life","camo":"life","zook":"life","stump smash":"life",
    "shroomboom":"life","zoo lou":"life","bumble blast":"life","tree rex":"life",
    "high five":"life","splat":"life","knight light":"life",
    "ghost roaster":"undead","hex":"undead","chop chop":"undead","cynder":"undead",
    "roller brawl":"undead","bat spin":"undead","funny bone":"undead",
    "night shift":"undead","eye-brawl":"undead","wolfgang":"undead",
    "tomb buggy":"undead",
    "trigger happy":"tech","drill sergeant":"tech","drobot":"tech","boomer":"tech",
    "sprocket":"tech","wind-up":"tech","countdown":"tech","tread head":"tech",
    "bouncer":"tech","magna charge":"tech","spy rise":"tech","high volt":"tech",
    "shield striker":"tech","chopper":"tech","jawbreaker":"tech","gearshift":"tech",
    "spyro":"magic","voodood":"magic","wrecking ball":"magic","pop fizz":"magic",
    "dune bug":"magic","ninjini":"magic","scratch":"magic","pop thorn":"magic",
    "cobra cadabra":"magic","deja vu":"magic","clown cruiser":"magic","lava lance eruptor":"magic",
    "spotlight":"light","knight light":"light",
    "blackout":"dark","nightfall":"dark","doom jet":"dark","sea shadow":"dark",
    # Known variants with no element subfolder
    "gnarly tree rex":"life","gnarly swarm":"air",
    "granite crusher":"earth","jade flash wing":"earth",
    "legendary bouncer":"tech","legendary crusher":"earth",
    "legendary jet-vac":"air","legendary slam bam":"water",
    "legendary spyro":"magic","legendary ninjini":"magic",
    "legendary chop chop":"undead","legendary prism break":"earth",
    "legendary stealth elf":"life","legendary trigger happy":"tech",
    "legendary bash":"earth","legendary flameslinger":"fire",
    "legendary cynder":"undead","legendary gill grunt":"water",
    "scarlet ninjini":"magic","jade flashwing":"earth",
    "polar whirlwind":"air","royal double trouble":"magic",
    "dark spyro":"magic","dark blast zone":"fire",
    "dark food fight":"life","dark snap shot":"dark",
    "dark spitfire":"fire","dark super shot stealth elf":"life",
    "dark wildfire":"fire","dark slobber tooth":"earth",
    "nitro magna charge":"tech","nitro freeze blade":"water",
    "nitro head rush":"earth","nitro krypt king":"undead",
    "horn blast whirlwind":"air","biter's bane snap shot":"water",
    "enchanted hitch rider":"magic","legendary dreadwind":"air",
    "legendary jawbreaker":"tech","legendary grim creeper":"undead",
    "legendary night shift":"undead","legendary star strike":"magic",
    "legendary enigma":"air","legendary rocky roll":"earth",
    "legendary tuff luck":"life","legendary snap shot":"water",
    # Missing Skylanders added
    "star strike":"magic","grim creeper":"undead","rip tide":"water",
    "punk shock":"water","hoot loop":"magic","trap shadow":"life",
    "grilla drilla":"life","flip wreck":"water","echo":"water","blades":"air",
    "short cut":"undead","tuff luck":"life","déjà vu":"magic","deja vu":"magic",
    "roller brawl":"undead","fling kong":"air","fryno":"fire","smolderdash":"fire",
    "countdown":"tech","wind-up":"tech","sprocket":"tech",
    # SuperCharger vehicles missing
    "scale biter":"earth","spirit dragster":"undead","chompy buster":"life",
    "clunker":"tech","blunder bucket":"water",
    # Expansion packs & magic items → use item icon
    "darklight crypt":"item","dragon's peak":"item","empire of ice":"item",
    "pirate seas":"item","leviathan lagoon":"item","mirror of mystery":"item",
    "nightmare express":"item","sheep wreck island":"item","tower of time":"item",
    "anvil rain":"item","battle hammer":"item","healing elixir":"item",
    "hourglass":"item","iron fist of arkus":"item","platinum sheep":"item",
    "winged boots":"item","sparx the dragonfly":"item","ghost swords":"item",
    "sky iron shield":"item","volcanic vault":"item","hidden treasure":"item",
    "secret vault of spheres":"item","wow pow":"item","legendary treasure":"item",
    "hat":"item","bomb":"item","soul gem":"item","win condition":"item",
    "rocket":"item","sharktooth throne":"item","arkeyan throne":"item",
}

# Folder name → element (most reliable detection method)
FOLDER_ELEMENT_MAP = {
    "fire":"fire","water":"water","earth":"earth","air":"air",
    "life":"life","undead":"undead","tech":"tech","magic":"magic",
    "light":"light","dark":"dark",
    "items":"item","item":"item","magic items":"item",
    "adventure packs":"item","adventure pack":"item","expansions":"item",
}

# Crystal name prefixes for Imaginators creation crystals
CRYSTAL_ELEMENT_MAP = {
    "fire":["fire","flame","inferno","blaze","ember","magma","lava","volcanic","cinder"],
    "water":["water","aqua","wave","tide","frost","ice","glacier","coral","splash","blizzard"],
    "earth":["earth","stone","rock","boulder","granite","crystal","gem","jade","quartz","terra"],
    "air":["air","wind","storm","thunder","lightning","gale","cyclone","breeze","cloud","sky"],
    "life":["life","leaf","vine","forest","jungle","nature","fern","bloom","grove","wild"],
    "undead":["undead","bone","skull","ghost","shadow","death","crypt","grave","specter","phantom","fang","fanged"],
    "tech":["tech","gear","iron","steel","bolt","circuit","reactor","armor","mechano","gadget","cog"],
    "magic":["magic","spell","arcane","mystic","rune","enchant","lantern","pyramid","pyrmid","star","cosmic"],
    "light":["light","solar","shine","glow","radiant","dawn","beacon","halo","sunstone"],
    "dark":["dark","void","abyss","shadow","obsidian","dusk","eclipse","noir","midnight"],
}

def detect_element(name, path=""):
    """Detect element from subfolder path, then crystal name, then name map."""
    if path:
        parts = path.replace("\\", "/").replace("\\\\", "/").lower().split("/")
        # Walk ALL folder parts (skip filename) — keep going past unrecognized folders
        # like "Alternate types", "Variants", "Lightcore" etc.
        for part in reversed(parts[:-1]):
            part = part.strip()
            if part in FOLDER_ELEMENT_MAP:
                return FOLDER_ELEMENT_MAP[part]
            # Skip known non-element subfolders and keep walking up
            # (don't return None just because we hit "alternate types")
    # Fallback: crystal name detection (Imaginators)
    lower = name.lower().strip()
    for el, keywords in CRYSTAL_ELEMENT_MAP.items():
        for kw in keywords:
            if lower.startswith(kw):
                return el
    # Final fallback: exact name map
    if lower in ELEMENT_NAME_MAP:
        return ELEMENT_NAME_MAP[lower]
    return None

def el_color(name, path=""):
    el = detect_element(name, path)
    return ELEMENT_COLORS.get(el) if el else None

def get_portal_slot(name, path="", game="", is_sf_combo=False, is_sf_bottom=False, user_slot=1):
    """
    Determine the correct VirtPort slot for a Skylander based on type.
    Slot 1 — Core Skylanders, Swap Force tops, Trap Team Skylanders, Giants
    Slot 2 — Swap Force bottoms only
    Slot 3 — Items, expansion pack levels
    Slot 4 — Physical Trap ITEMS only (not regular Trap Team Skylanders)
    Slot 5 — Vehicles (SuperChargers)
    """
    name_lower = name.lower()
    path_lower = path.lower().replace("\\\\","/").replace("\\","/")

    # Swap Force bottom half → slot 2
    if is_sf_bottom or "(bottom)" in name_lower or "(bottom)" in path_lower:
        return 2

    # Vehicles (SuperChargers) → slot 5
    vehicle_keywords = ["hot streak","reef ripper","buzz wing","stealth bomber",
                        "thump truck","crypt crusher","splatter splasher",
                        "shield striker","sun runner","sea shadow","sky trophy",
                        "barrel blaster","sky slicer","burn-cycle","dive bomber",
                        "tomb buggy","clown cruiser","gold rusher","shark tank",
                        "stealth stinger vehicle","hurricane jet vac","jet stream",
                        "big air","dark sea shadow","dark hot streak","legendary gold rusher"]
    if any(v in name_lower for v in vehicle_keywords):
        return 5

    # FIXED: Only physical Trap ITEMS go to slot 4.
    # Trap Team Skylanders (Snap Shot, Wallop, etc.) stay on slot 1.
    # A trap item has "trap" in the name AND an element word — e.g. "Fire Trap", "Water Trap"
    # Regular Trap Team Skylanders never have just "trap" + element as their full name structure.
    trap_elements = ["fire","water","air","earth","life","undead","magic","tech","light","dark","kaos","villain"]
    if game == "Trap Team" and "trap" in name_lower:
        # Check if it's a path in a "traps" subfolder (not "trap team" folder)
        parts = path_lower.split("/")
        in_traps_folder = any(p == "traps" or (p.endswith("trap") and p != "trap team") for p in parts)
        # Or name is like "Fire Trap", "Kaos Trap" etc — short name with element
        name_parts = name_lower.replace("-"," ").split()
        looks_like_trap_item = (len(name_parts) <= 3 and
                                any(el in name_lower for el in trap_elements) and
                                "trap" in name_parts)
        if in_traps_folder or looks_like_trap_item:
            return 4

    # Items / expansion packs → slot 3
    el = detect_element(name, path)
    if el == "item":
        return 3

    # Default → slot 1
    return 1

def should_clear_slots(new_slot, prev_was_sf_combo):
    """
    Returns which slots to clear before loading a new Skylander.
    When transitioning away from SF combo, clear BOTH slots so no ghost remains.
    Never clear anything when loading items/traps/vehicles (slot 3/4/5).
    """
    if new_slot >= 3:
        return []  # items/traps/vehicles never touch SF slots
    if prev_was_sf_combo:
        return [1, 2]  # clear both — slot 1 had the top, slot 2 had the bottom
    return []  # regular swap — just overwrite slot 1 directly



# Swap Force movement type by bottom-half character name
SWAP_MOVEMENT_MAP = {
    "rattle shake":  "Bounce",
    "freeze blade":  "Bounce",
    "wash buckler":  "Climb",
    "spy rise":      "Climb",
    "grilla drilla": "Dig",
    "trap shadow":   "Dig",
    "blast zone":    "Rocket",
    "boom jet":      "Rocket",
    "magna charge":  "Speed",
    "stink bomb":    "Sneak",
    "night shift":   "Teleport",
    "hoot loop":     "Teleport",
    "free ranger":   "Spin",
    "fire kraken":   "Spin",
}

SWAP_MOVEMENT_ICONS = {
    "Bounce":   "🌀",
    "Climb":    "🪜",
    "Dig":      "⛏",
    "Rocket":   "🚀",
    "Speed":    "⚡",
    "Sneak":    "🥷",
    "Teleport": "✨",
    "Spin":     "🌪",
}

SWAP_MOVEMENT_ICON_FILES = {
    "Bounce":   "Bounce_symbol.png",
    "Climb":    "Climb_symbol.png",
    "Dig":      "Dig_symbol.png",
    "Rocket":   "Rocket_symbol.png",
    "Sneak":    "Sneak_symbol.png",
    "Speed":    "Speed_symbol.png",
    "Spin":     "Spin_symbol.png",
    "Teleport": "Teleport_symbol.png",
}
_movement_images = {}

SWAP_BOTTOM_MOVEMENT = {
    "Blast Zone":"Rocket","Dark Blast Zone":"Rocket","Boom Jet":"Rocket",
    "Wash Buckler":"Climb","Dark Wash Buckler":"Climb","Spy Rise":"Climb",
    "Magna Charge":"Speed","Nitro Magna Charge":"Speed","Freeze Blade":"Speed","Nitro Freeze Blade":"Speed",
    "Hoot Loop":"Teleport","Enchanted Hoot Loop":"Teleport","Night Shift":"Teleport","Legendary Night Shift":"Teleport",
    "Grilla Drilla":"Dig","Rubble Rouser":"Dig",
    "Stink Bomb":"Sneak","Trap Shadow":"Sneak",
    "Fire Kraken":"Bounce","Jade Fire Kraken":"Bounce","Rattle Shake":"Bounce","Quickdraw Rattle Shake":"Bounce",
    "Free Ranger":"Spin","Legendary Free Ranger":"Spin","Doom Stone":"Spin",
}

ELEMENT_ICON_FILES = {
    "fire":"FireSymbolSkylanders.png","water":"WaterSymbolSkylanders.png",
    "earth":"EarthSymbolSkylanders.png","air":"AirSymbolSkylanders.png",
    "life":"LifeSymbolSkylanders.png","undead":"UndeadSymbolSkylanders.png",
    "tech":"TechSymbolSkylanders.png","magic":"MagicSymbolSkylanders.png",
    "light":"LightSymbolSkylanders.png","dark":"DarkSymbolSkylanders.png",
}
_element_images = {}

def get_resource_path(relative):
    """Get path to resource — works for dev and PyInstaller exe."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative)

def load_element_icons(script_dir=None):
    icons_dir = get_resource_path("icons")
    if not os.path.isdir(icons_dir): return
    try:
        from PIL import Image, ImageTk
        elements_dir = os.path.join(icons_dir, "Elements")
        if not os.path.isdir(elements_dir): elements_dir = icons_dir
        for el, fname in ELEMENT_ICON_FILES.items():
            path = os.path.join(elements_dir, fname)
            if not os.path.exists(path): path = os.path.join(icons_dir, fname)
            if os.path.exists(path):
                img = Image.open(path).convert("RGBA").resize((28,28), Image.LANCZOS)
                _element_images[el] = ImageTk.PhotoImage(img)
        for d in (elements_dir, icons_dir):
            item_path = os.path.join(d, "MagicItemSymbol.webp")
            if os.path.exists(item_path):
                img = Image.open(item_path).convert("RGBA").resize((28,28), Image.LANCZOS)
                _element_images["item"] = ImageTk.PhotoImage(img)
                break
        movement_dir = os.path.join(icons_dir, "Movement Icons")
        if not os.path.isdir(movement_dir): movement_dir = os.path.join(icons_dir, "Movment Icons")
        if not os.path.isdir(movement_dir): movement_dir = icons_dir
        for move, fname in SWAP_MOVEMENT_ICON_FILES.items():
            path = os.path.join(movement_dir, fname)
            if not os.path.exists(path): path = os.path.join(icons_dir, fname)
            if os.path.exists(path):
                img = Image.open(path).convert("RGBA").resize((28,28), Image.LANCZOS)
                _movement_images[move] = ImageTk.PhotoImage(img)
    except ImportError:
        pass

VEHICLES = {
    "Land":["Hot Streak","Burn-Cycle","Crypt Crusher","Shark Tank","Gold Rusher","Shield Striker",
            "Thump Truck","Tomb Buggy","Barrel Blaster",
            "Dark Hot Streak","Dark Crypt Crusher","Dark Barrel Blaster"],
    "Sky": ["Sky Slicer","Jet Stream","Stealth Stinger","Buzz Wing","Sun Runner","Clown Cruiser",
            "Dark Clown Cruiser"],
    "Sea": ["Reef Ripper","Sea Shadow","Dive Bomber","Soda Skimmer","Splatter Splasher",
            "Dark Sea Shadow"],
}

# Villain vehicles — unlocked in-game, no physical figure
VILLAIN_VEHICLES = [
    # Land Trophy
    {"name":"Scale Biter",      "terrain":"Land","villain":"Dragon Hunter",  "unlock":"Land Trophy"},
    {"name":"Steam Roller",     "terrain":"Land","villain":"Glumshanks",    "unlock":"Land Trophy"},
    {"name":"Chompy Buster",    "terrain":"Land","villain":"Chompy Mage",    "unlock":"Land Trophy"},
    {"name":"Spirit Dragster",  "terrain":"Land","villain":"Dreamcatcher",   "unlock":"Land Trophy"},
    {"name":"Clunker",          "terrain":"Land","villain":"Wolfgang",        "unlock":"Land Trophy"},
    {"name":"Brawl & Chain",    "terrain":"Land","villain":"Broccoli Guy",    "unlock":"Land Trophy"},
    # Sea Trophy
    {"name":"Slime Slider",     "terrain":"Sea", "villain":"Mesmeralda",      "unlock":"Sea Trophy"},
    {"name":"Lil Phantom Tide", "terrain":"Sea", "villain":"Nightshade",      "unlock":"Sea Trophy"},
    {"name":"Shark Shooter",    "terrain":"Sea", "villain":"Gulper",          "unlock":"Sea Trophy"},
    {"name":"Shark Shooter",    "terrain":"Sea", "villain":"Cap'n Cluck",    "unlock":"Sea Trophy"},
    # Sky Trophy
    {"name":"Storm Striker",    "terrain":"Sky", "villain":"Lord Stratosfear","unlock":"Sky Trophy"},
    {"name":"Toaster Bomber",   "terrain":"Sky", "villain":"Chef Pepper Jack","unlock":"Sky Trophy"},
    {"name":"Sky Scrambler",    "terrain":"Sky", "villain":"Cap'n Cluck",    "unlock":"Sky Trophy"},
    {"name":"Dragon Hunter",    "terrain":"Sky", "villain":"Dragon Hunter",   "unlock":"Sky Trophy"},
    # Kaos Trophy
    {"name":"Doom Jet",         "terrain":"Sky", "villain":"Kaos",            "unlock":"Kaos Trophy"},
]

TROPHY_COLORS = {
    "Land Trophy": "#8B6914",
    "Sea Trophy":  "#2980b9",
    "Sky Trophy":  "#85c1e9",
    "Kaos Trophy": "#8e44ad",
}

def _load_theme():
    """Load theme colors from config, fallback to defaults."""
    defaults = {
        "theme_bg":     "#0f1117",
        "theme_card":   "#1e2330",
        "theme_hover":  "#272d3f",
        "theme_accent": "#5b9bd5",
        "theme_text":   "#eaf0fb",
        "theme_text2":  "#7a8499",
        "theme_border": "#2a3147",
        "theme_scrollbar": "#1e2330",
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            for k, v in defaults.items():
                defaults[k] = cfg.get(k, v)
    except Exception:
        pass
    return defaults

_theme = _load_theme()
DARK_BG    = _theme["theme_bg"]
PANEL_BG   = _theme["theme_bg"]
CARD_BG    = _theme["theme_card"]
CARD_HOVER = _theme["theme_hover"]
ACCENT     = _theme["theme_accent"]
TEXT_PRI   = _theme["theme_text"]
TEXT_SEC   = _theme["theme_text2"]
BORDER     = _theme["theme_border"]
SCROLLBAR  = _theme.get("theme_scrollbar", "#1e2330")

# ─────────────────────────────────────────────
# VIRTPORT HTTP API
# ─────────────────────────────────────────────

def virtport_load(path, slot=1, host="localhost", port=5678, timeout=3):
    """
    Sends a SUMMON command to VirtPort's Cemu.
    VirtPort slots are 0-indexed, so we subtract 1 from our 1-indexed slot.
    Returns (True, "") on success or (False, error_msg) on failure.
    """
    try:
        vp_slot  = slot - 1   # convert: our slot 1 = VirtPort slot 0
        win_path = path.replace("/", "\\")
        encoded  = _urlparse.quote(win_path, safe=":\\")
        url      = f"http://{host}:{port}/?cmd=SUMMON&slot={vp_slot}&file={encoded}"
        req      = _urllib.Request(url)
        with _urllib.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return True, ""
    except Exception as e:
        return False, str(e)

_virtport_clear_url = [None]  # cache the working clear URL format

def virtport_clear(slot=1, host="localhost", port=5678, timeout=3):
    """
    Clears a portal slot using cmd=CLEAR which VirtPort supports.
    Falls back to other formats if CLEAR fails.
    """
    vp_slot = slot - 1

    # Known working formats — CLEAR first since we confirmed it works
    formats = [
        "http://{host}:{port}/?cmd=CLEAR&slot={vp_slot}",
        "http://{host}:{port}/?cmd=SUMMON&slot={vp_slot}&file=",
        "http://{host}:{port}/?cmd=REMOVE&slot={vp_slot}",
        "http://{host}:{port}/?cmd=SUMMON&slot={vp_slot}",
    ]

    # If cached, use it directly
    if _virtport_clear_url[0]:
        formats = [_virtport_clear_url[0]] + [f for f in formats if f != _virtport_clear_url[0]]

    for fmt in formats:
        url = fmt.format(host=host, port=port, vp_slot=vp_slot)
        try:
            req = _urllib.Request(url)
            with _urllib.urlopen(req, timeout=1) as resp:
                resp.read()
            _virtport_clear_url[0] = fmt
            _dbg(f"virtport_clear slot {slot} OK: {url}")
            return True, ""
        except Exception as e:
            _dbg(f"virtport_clear tried: {url} → {e}")
            continue

    return False, "No working clear format found"

def virtport_ping(host="localhost", port=5678, timeout=2):
    """Check if VirtPort's server is reachable by sending a test request."""
    try:
        # Try a socket connection first — fastest way to check if port is open
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

# ─────────────────────────────────────────────
# CONFIG + CACHE
# ─────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f: return json.load(f)
        except Exception: pass
    return {"root_folder":"","favorites":[],"vp_host":"localhost","vp_port":5678,"keybinds":[],"theme_accent":"#5b9bd5","theme_bg":"#0f1117"}

def save_config(cfg):
    with open(CONFIG_FILE,"w") as f: json.dump(cfg,f,indent=2)

def folder_fingerprint(root_folder):
    parts = []
    try:
        for entry in sorted(os.scandir(root_folder), key=lambda e: e.name):
            if entry.is_dir():
                sky_count = sum(1 for _,_,fs in os.walk(entry.path) for f in fs if f.lower().endswith(".sky"))
                parts.append(f"{entry.name}:{sky_count}:{int(entry.stat().st_mtime)}")
    except Exception: pass
    return hashlib.md5("|".join(parts).encode()).hexdigest()

def load_cache(root_folder):
    if not os.path.exists(CACHE_FILE): return None
    try:
        with open(CACHE_FILE) as f: cache = json.load(f)
        if cache.get("folder")==root_folder and cache.get("fingerprint")==folder_fingerprint(root_folder):
            return cache["data"]
    except Exception: pass
    return None

def save_cache(root_folder, data):
    with open(CACHE_FILE,"w") as f:
        json.dump({"folder":root_folder,"fingerprint":folder_fingerprint(root_folder),"data":data},f)

def discover_skylanders(root_folder):
    result = {g:[] for g in GAME_FOLDER_HINTS}
    result["Unknown"] = []
    if not root_folder or not os.path.isdir(root_folder): return result
    for entry in os.scandir(root_folder):
        if not entry.is_dir(): continue
        matched = None
        for hint in GAME_FOLDER_HINTS:
            if hint.lower().replace("'","") in entry.name.lower().replace("'",""):
                matched = hint; break
        sky_files = []
        for root,_,files in os.walk(entry.path):
            for fname in sorted(files):
                if fname.lower().endswith(".sky"):
                    sky_files.append({"name":os.path.splitext(fname)[0],"path":os.path.join(root,fname)})
        (result[matched] if matched else result["Unknown"]).extend(sky_files)
    for fname in sorted(os.listdir(root_folder)):
        if fname.lower().endswith(".sky"):
            result["Unknown"].append({"name":os.path.splitext(fname)[0],"path":os.path.join(root_folder,fname)})
    return result

def copy_to_clipboard(root_win, text):
    root_win.clipboard_clear(); root_win.clipboard_append(text); root_win.update()

# ─────────────────────────────────────────────
# CONTROLLER + FAVORITES WHEEL
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# VIRTUAL LIST
# ─────────────────────────────────────────────

class VirtualList(tk.Frame):
    ROW_H = 52

    def __init__(self, parent, items, favorites, on_select, on_fav_toggle, game_colors, bg=PANEL_BG, app_ref=None, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.items        = items
        self.favorites    = favorites
        self.on_select    = on_select
        self.on_fav_toggle= on_fav_toggle
        self.game_colors  = game_colors
        self._app_ref     = app_ref
        self._hover_row   = -1
        self._prev_hover  = -1
        self._draw_pending = False
        self._width       = 0

        self.canvas = tk.Canvas(self, bg=PANEL_BG, highlightthickness=0)
        self.sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.canvas.bind("<Configure>",  self._on_resize)
        self.canvas.bind("<MouseWheel>", self._on_scroll)
        self.canvas.bind("<Motion>",     self._on_motion)
        self.canvas.bind("<Button-1>",   self._on_click)
        self.canvas.bind("<Button-3>",   self._on_right_click)
        self.canvas.bind("<Leave>",      self._on_leave)
        self._draw()

    def _total_h(self):
        return len(self.items) * self.ROW_H

    def _schedule_draw(self):
        """Schedule a single redraw, collapsing multiple calls into one."""
        if not self._draw_pending:
            self._draw_pending = True
            self.canvas.after_idle(self._do_draw)

    def _do_draw(self):
        self._draw_pending = False
        self._draw()

    def _draw(self):
        cx = self.canvas
        w  = self._width
        cx.delete("all")
        cx.configure(scrollregion=(0, 0, w, self._total_h()))
        if w == 0:
            return
        top    = cx.canvasy(0)
        bottom = cx.canvasy(cx.winfo_height() or 600)
        first  = max(0, int(top // self.ROW_H))
        last   = min(len(self.items), int(bottom // self.ROW_H) + 2)
        for i in range(first, last):
            self._draw_row(i, w)

    def _draw_row(self, i, w):
        item = self.items[i]
        y0   = i * self.ROW_H
        y1   = y0 + self.ROW_H - 2
        cx   = self.canvas
        bg   = CARD_HOVER if i == self._hover_row else CARD_BG
        gc   = self.game_colors.get(item.get("game", ""), ACCENT)
        path = item.get("path", "")
        el   = detect_element(item["name"], path)
        img  = _element_images.get("item") if el == "item" else (
               _element_images.get(el) if el else None)
        ec   = ELEMENT_COLORS.get(el) if el and el != "item" else None

        cx.create_rectangle(8, y0+2, w-8, y1, fill=bg, outline="", tags=f"r{i}")
        cx.create_rectangle(8, y0+2, 13,  y1, fill=gc, outline="", tags=f"r{i}")
        cx.create_text(20, y0+16, text=item["name"], anchor="w",
                       fill=TEXT_PRI, font=("Segoe UI",10,"bold"), tags=f"r{i}")
        cx.create_text(20, y0+34, text=GAME_DISPLAY_NAMES.get(item.get("game",""),""),
                       anchor="w", fill=TEXT_SEC, font=("Segoe UI",8), tags=f"r{i}")
        if img:
            cx.create_image(w-56, y0+self.ROW_H//2, image=img,
                            anchor="center", tags=f"r{i}")
        elif ec:
            cx.create_oval(w-68, y0+16, w-44, y0+36,
                           fill=ec, outline="", tags=f"r{i}")
        is_fav   = item["path"] in self.favorites
        is_combo = item.get("is_sf_combo", False)
        star_col = "#4488ff" if is_combo else ("#f5c518" if is_fav else TEXT_SEC)
        star_txt = "★" if (is_fav or is_combo) else "☆"
        cx.create_text(w-18, y0+self.ROW_H//2,
                       text=star_txt, anchor="center",
                       fill=star_col,
                       font=("Segoe UI",12), tags=f"r{i}")

    def _row_at(self, y):
        r = int(y // self.ROW_H)
        return r if 0 <= r < len(self.items) else -1

    def _on_resize(self, e):
        self._width = e.width
        # Debounce resize — only redraw after resizing stops
        if hasattr(self, '_resize_after'):
            try: self.canvas.after_cancel(self._resize_after)
            except Exception: pass
        self._resize_after = self.canvas.after(80, self._schedule_draw)

    def _on_scroll(self, e):
        self.canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._schedule_draw()

    def _on_motion(self, e):
        row = self._row_at(self.canvas.canvasy(e.y))
        if row != self._hover_row:
            self._hover_row = row
            self._schedule_draw()

    def _on_leave(self, e):
        self._hover_row = -1
        self._schedule_draw()

    def _on_right_click(self, e):
        row = self._row_at(self.canvas.canvasy(e.y))
        if row < 0 or row >= len(self.items): return
        item = self.items[row]
        if not item.get("is_sf_combo"): return
        menu = tk.Menu(self, tearoff=0, bg=CARD_BG, fg=TEXT_PRI,
                       activebackground=ACCENT, activeforeground="#fff",
                       font=("Segoe UI",9))
        def del_combo():
            if not self._app_ref: return
            combos = self._app_ref.cfg.get("sf_combos",[])
            self._app_ref.cfg["sf_combos"] = [
                c for c in combos
                if c.get("top_path","") != item.get("path","")
                or c.get("bot_path","") != item.get("bot_path","")
            ]
            save_config(self._app_ref.cfg)
            self._app_ref._refresh_active_tab()
        menu.add_command(label="✕  Delete Combo", command=del_combo,
                         foreground="#e74c3c", activeforeground="#e74c3c")
        menu.tk_popup(e.x_root, e.y_root)

    def _on_click(self, e):
        row = self._row_at(self.canvas.canvasy(e.y))
        if row < 0:
            return
        item = self.items[row]
        if e.x > self._width - 30:
            self.on_fav_toggle(item["path"])
        else:
            self.on_select(item)

    def refresh_favorites(self, favorites):
        self.favorites = favorites
        self._schedule_draw()

    def update_items(self, items):
        self.items = items
        self._hover_row = -1
        self.canvas.yview_moveto(0)
        self._schedule_draw()

# ─────────────────────────────────────────────
# VEHICLE LIST
# ─────────────────────────────────────────────

class VehicleList(tk.Frame):
    ROW_H=58; HDR_H=32
    def __init__(self,parent,rows,favorites,on_select,on_fav_toggle,on_locate,bg=PANEL_BG,**kw):
        super().__init__(parent,bg=bg,**kw)
        self.rows=rows; self.favorites=favorites; self.on_select=on_select
        self.on_fav_toggle=on_fav_toggle; self.on_locate=on_locate
        self._hover_row=-1; self._type_colors={"Land":"#8B6914","Sky":"#85c1e9","Sea":"#2980b9"}
        self._locate_btns={}
        self.canvas=tk.Canvas(self,bg=PANEL_BG,highlightthickness=0)
        self.sb=ttk.Scrollbar(self,orient="vertical",command=self._on_yscroll)
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.sb.pack(side="right",fill="y"); self.canvas.pack(side="left",fill="both",expand=True)
        self.canvas.bind("<Configure>",self._on_resize)
        self.canvas.bind("<MouseWheel>",self._on_scroll)
        self.canvas.bind("<Motion>",self._on_motion)
        self.canvas.bind("<Button-1>",self._on_click)
        self.canvas.bind("<Leave>",self._on_leave)
        self._width=0; self._build_offsets(); self._draw()

    def _build_offsets(self):
        self._offsets=[]; y=0
        for row in self.rows:
            self._offsets.append(y)
            y+=self.HDR_H if row["type"]=="header" else self.ROW_H
        self._total=y

    def _on_yscroll(self,*a): self.canvas.yview(*a); self._reposition_buttons()
    def _reposition_buttons(self):
        top=self.canvas.canvasy(0)
        for idx,btn in self._locate_btns.items():
            y0=self._offsets[idx]; sy=y0-top
            if 0<=sy<=(self.canvas.winfo_height() or 600): btn.place(x=self._width-110,y=int(sy)+14); btn.lift()
            else: btn.place_forget()

    def _draw(self):
        cx=self.canvas; cx.delete("all"); w=self._width
        cx.configure(scrollregion=(0,0,w,self._total))
        if w==0: return
        for btn in self._locate_btns.values(): btn.destroy()
        self._locate_btns.clear()
        top=cx.canvasy(0); bottom=cx.canvasy(cx.winfo_height() or 600)
        for i,row in enumerate(self.rows):
            y0=self._offsets[i]; h=self.HDR_H if row["type"]=="header" else self.ROW_H
            y1=y0+h
            if y1<top-10 or y0>bottom+10: continue
            sy=y0-top
            if row["type"]=="header":
                tc=self._type_colors.get(row["vtype"],ACCENT)
                cx.create_rectangle(8,y0+6,w-8,y1-2,fill=PANEL_BG,outline=tc,tags=f"r{i}")
                cx.create_text(20,y0+h//2,text=f"── {row['label']} ──",anchor="w",fill=tc,font=("Segoe UI",9,"bold"),tags=f"r{i}")
            else:
                bg=CARD_HOVER if i==self._hover_row else CARD_BG
                tc=self._type_colors.get(row["vtype"],ACCENT); se=row.get("sky_entry")
                cx.create_rectangle(8,y0+2,w-8,y1-2,fill=bg,outline="",tags=f"r{i}")
                cx.create_rectangle(8,y0+2,13,y1-2,fill=tc,outline="",tags=f"r{i}")
                cx.create_rectangle(18,y0+16,56,y0+36,fill=tc,outline="",tags=f"r{i}")
                cx.create_text(37,y0+26,text=row["vtype"],anchor="center",fill="#fff",font=("Segoe UI",7,"bold"),tags=f"r{i}")
                cx.create_text(64,y0+17,text=row["label"],anchor="w",fill=TEXT_PRI,font=("Segoe UI",10,"bold"),tags=f"r{i}")
                if se:
                    cx.create_text(64,y0+37,text="✔ Found on disk",anchor="w",fill="#3dba6f",font=("Segoe UI",8),tags=f"r{i}")
                    is_fav=se["path"] in self.favorites
                    cx.create_text(w-22,y0+self.ROW_H//2,text="★" if is_fav else "☆",anchor="center",fill="#f5c518" if is_fav else TEXT_SEC,font=("Segoe UI",14),tags=f"r{i}")
                else:
                    cx.create_text(64,y0+37,text="⚠ No .sky file — click Locate",anchor="w",fill="#e67e22",font=("Segoe UI",8),tags=f"r{i}")
                    btn=tk.Button(self.canvas,text="📂 Locate",bg="#e67e22",fg="#fff",relief="flat",cursor="hand2",font=("Segoe UI",8,"bold"),padx=8,pady=3,activebackground="#f39c12",activeforeground="#fff",command=lambda idx=i,vn=row["label"]:self.on_locate(idx,vn))
                    btn.place(x=w-110,y=int(sy)+14); btn.lift(); self._locate_btns[i]=btn

    def update_row_found(self,row_idx,sky_entry):
        self.rows[row_idx]["sky_entry"]=sky_entry
        if row_idx in self._locate_btns: self._locate_btns[row_idx].destroy(); del self._locate_btns[row_idx]
        self._draw()

    def _row_at_y(self,y):
        for i,y0 in enumerate(self._offsets):
            h=self.HDR_H if self.rows[i]["type"]=="header" else self.ROW_H
            if y0<=y<y0+h: return i
        return -1

    def _on_resize(self,e): self._width=e.width; self._draw()
    def _on_scroll(self,e): self.canvas.yview_scroll(int(-1*(e.delta/120)),"units"); self._draw()
    def _on_motion(self,e):
        cy=self.canvas.canvasy(e.y); row=self._row_at_y(cy)
        if 0<=row<len(self.rows) and self.rows[row]["type"]=="header": row=-1
        if row!=self._hover_row: self._hover_row=row; self._draw()
    def _on_leave(self,e): self._hover_row=-1; self._draw()
    def _on_click(self,e):
        cy=self.canvas.canvasy(e.y); idx=self._row_at_y(cy)
        if idx<0 or self.rows[idx]["type"]=="header": return
        se=self.rows[idx].get("sky_entry")
        if not se: return
        if e.x>self._width-45: self.on_fav_toggle(se["path"])
        else: self.on_select(se)
    def refresh_favorites(self,favorites): self.favorites=favorites; self._draw()

# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────

class SkylandersPortalApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Skylanders Portal Manager")
        self.geometry("860x700"); self.configure(bg=DARK_BG); self.minsize(640,520)
        # Set window icon
        try:
            icon_path = get_resource_path("skylanders_portal.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
                self._icon_path = icon_path
            else:
                self._icon_path = None
        except Exception:
            pass
        self.cfg=load_config(); self.all_skylanders={}
        self.search_var=tk.StringVar(); self._search_after=None
        self.search_var.trace_add("write",self._on_search_change)
        self.active_tab=tk.StringVar(value="All")
        self._status_var=tk.StringVar(value="Select your Skylanders folder to get started.")
        self._dropdown_open=False; self._dropdown_win=None; self._vlist=None

        load_element_icons()

        self._manual_mode = False
        self._active_slot = 1   # which portal slot to load into
        self._mode = "portal"   # "portal" or "randomizer"
        self._build_ui()
        if self.cfg.get("root_folder"): self._load_folder_startup(self.cfg["root_folder"])
        self.after(1000, self._check_virtport_connection)
        self.bind_all("<Shift-M>", self._toggle_manual_mode)
        self.bind_all("<Control-Shift-D>", lambda e: self._show_debug_log())
        # Force redraw when window is restored from minimized
        self.bind("<Map>", self._on_restore)
        self._registered_keys = []
        self._register_all_keybinds()
        self._setup_controller_callbacks()


    def _set_win_icon(self, win):
        try:
            if getattr(self, "_icon_path", None):
                win.iconbitmap(self._icon_path)
        except Exception:
            pass

    def _setup_controller_callbacks(self):
        global _ctrl_callback, _ctrl_cancel_cb, _ctrl_wheel_enabled
        self._ctrl_overlay = None

        # Guard — cfg must exist before we proceed
        if not hasattr(self, "cfg") or self.cfg is None:
            _dbg("_setup_controller_callbacks: cfg not ready, skipping")
            return

        _ctrl_wheel_enabled[0] = self.cfg.get("ctrl_wheel_enabled", False)
        trigger = self.cfg.get("ctrl_trigger_code", "BTN_THUMBR")
        global _BTN_RS; _BTN_RS = {trigger}

        # Build wheel presets list from saved ctrl_presets folder (filtered by active category)
        def _load_wheel_presets():
            try:
                cat = get_ctrl_active_category(self.cfg)
                _ctrl_active_category[0] = cat
                presets = list_ctrl_presets(category=cat)
                return presets
            except Exception as e:
                _dbg(f"_load_wheel_presets error: {e}")
                return []

        _ctrl_wheel_presets[0] = _load_wheel_presets()
        self._reload_ctrl_presets = _load_wheel_presets

        def on_direction(direction):
            presets = _ctrl_wheel_presets[0]
            idx = _ctrl_wheel_index[0]
            if not presets or idx >= len(presets):
                self.after(0, lambda: self._status_var.set(f"🎮 No wheel presets configured"))
                return
            binds = presets[idx].get("ctrl_binds", {})

            # 1. Check for dedicated manual Swap Combo entry first
            sf_entry = binds.get(f"sf_{direction}")
            if sf_entry and sf_entry.get("is_swap_combo"):
                name = sf_entry.get("nickname","Combo")
                top_path = sf_entry.get("top_path","")
                bot_path = sf_entry.get("bot_path","")
                host=self.cfg.get("vp_host","localhost"); port=self.cfg.get("vp_port",5678)
                self.after(0, lambda: self._status_var.set(f"🎮 Loading {name}…"))
                def run_combo(tp=top_path, bp=bot_path, n=name):
                    import concurrent.futures as _cf
                    # Clear both slots in parallel, wait for completion
                    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                        _cf.wait([ex.submit(virtport_clear,1,host,port),
                                  ex.submit(virtport_clear,2,host,port)])
                    # Load both slots in parallel
                    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                        f1=ex.submit(virtport_load,tp,1,host,port)
                        f2=ex.submit(virtport_load,bp,2,host,port)
                        ok1,_=f1.result(); ok2,_=f2.result()
                    if ok1 and ok2: self._sf_combo_active = True
                    msg = f"🎮 {n} loaded!" if (ok1 and ok2) else f"🎮 {n} — not loaded"
                    self.after(0, lambda: self._status_var.set(msg))
                threading.Thread(target=run_combo,daemon=True).start()
                return

            # 2. Grab standard entry
            entry = binds.get(direction)
            if not entry or not entry.get("path"):
                self.after(0, lambda: self._status_var.set(f"🎮 No Skylander on D-pad {direction}"))
                return

            # 2b. Entry is an SF combo saved via the picker (is_sf_combo flag)
            if entry.get("is_sf_combo"):
                name = entry.get("name","Custom Swap")
                top_path = entry.get("path","")
                bot_path = entry.get("bot_path","")
                host = self.cfg.get("vp_host","localhost")
                port = self.cfg.get("vp_port",5678)
                self.after(0, lambda: self._status_var.set(f"🎮 Loading {name}…"))
                def run_custom_swap(tp=top_path, bp=bot_path, n=name):
                    import concurrent.futures as _cf
                    # Clear both slots in parallel, wait for completion
                    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                        _cf.wait([ex.submit(virtport_clear,1,host,port),
                                  ex.submit(virtport_clear,2,host,port)])
                    # Load both slots in parallel
                    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                        f1=ex.submit(virtport_load,tp,1,host,port)
                        f2=ex.submit(virtport_load,bp,2,host,port)
                        ok1,_=f1.result(); ok2,_=f2.result()
                    if ok1 and ok2: self._sf_combo_active = True
                    msg = f"🎮 {n} loaded!" if (ok1 and ok2) else f"🎮 {n} — load failed"
                    self.after(0, lambda: self._status_var.set(msg))
                threading.Thread(target=run_custom_swap,daemon=True).start()
                return

            path = entry["path"]
            name = entry["name"]
            game = entry.get("game","")
            epath = entry.get("path","")
            host = self.cfg.get("vp_host","localhost")
            port = self.cfg.get("vp_port",5678)

            # 3. Standard single Skylander load
            was_combo = getattr(self,"_sf_combo_active",False)
            self._sf_combo_active = False
            is_sf_bot = "(bottom)" in name.lower() or "(bottom)" in epath.lower().replace("\\","/")
            slot = get_portal_slot(name=name,path=epath,game=game,
                                   is_sf_bottom=is_sf_bot,user_slot=1)
            clear_slots = should_clear_slots(slot, was_combo)
            self.after(0, lambda: self._status_var.set(f"🎮 Loading {name}…"))
            _dbg(f"Controller load: {name} slot={slot} clear={clear_slots} was_combo={was_combo}")
            def run(p=path, n=name, s=slot, cs=clear_slots):
                try:
                    if cs:
                        import concurrent.futures as _cf
                        with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                            futs = [ex.submit(virtport_clear,cl,host,port) for cl in cs]
                            _cf.wait(futs)
                    ok, err = virtport_load(p,slot=s,host=host,port=port)
                    _dbg(f"Controller load result: {n} ok={ok} err={err}")
                    self.after(0, lambda: self._status_var.set(f"🎮 {n} → slot {s}" if ok else f"🎮 {n} — not loaded"))
                    if not ok: _dbg(f"Controller load failed: {n} — {err}")
                except Exception as e:
                    _dbg(f"Controller load EXCEPTION: {n} — {e}")
                    self.after(0, lambda: self._status_var.set(f"🎮 {n} — error: {e}"))
            threading.Thread(target=run, daemon=True).start()

        def on_overlay(action):
            if action in ("open","cycle"):
                self.after(0, self._show_ctrl_overlay)
            elif action == "no_presets":
                self.after(0, lambda: self._show_ctrl_toast(
                    f"No presets in '{_ctrl_active_category[0]}'"))
            else:
                self.after(0, self._hide_ctrl_overlay)

        _ctrl_callback  = on_direction
        _ctrl_cancel_cb = on_overlay

    def _show_ctrl_overlay(self):
        self._hide_ctrl_overlay()
        # Get current preset
        presets = _ctrl_wheel_presets[0]
        idx     = _ctrl_wheel_index[0]
        if presets and idx < len(presets):
            preset      = presets[idx]
            binds       = preset.get("ctrl_binds", {})
            preset_name = preset.get("name", "")
        else:
            binds = self.cfg.get("ctrl_binds", {})
            preset_name = ""; idx = 0; presets = [{}]

        alpha    = self.cfg.get("ctrl_overlay_alpha", 0.92)
        SIZE     = self.cfg.get("ctrl_wheel_size", 300)  # configurable size
        cat      = _ctrl_active_category[0]

        CHROMA = "#010101"
        ov = tk.Toplevel(self); ov.overrideredirect(True)
        ov.attributes("-topmost", True); ov.attributes("-alpha", alpha)
        ov.configure(bg=CHROMA)
        try: ov.wm_attributes("-transparentcolor", CHROMA)
        except: pass
        self._ctrl_overlay = ov

        sw_screen = self.winfo_screenwidth(); sh_screen = self.winfo_screenheight()
        ov.geometry(f"{SIZE}x{SIZE+30}+{(sw_screen-SIZE)//2}+{(sh_screen-SIZE)//2}")

        cv = tk.Canvas(ov, width=SIZE, height=SIZE+30, bg=CHROMA, highlightthickness=0)
        cv.pack(fill="both", expand=True)

        cx = cy = SIZE // 2
        scale   = SIZE / 300
        r_outer = int(138 * scale)
        r_inner = int(52  * scale)
        slot_r  = int(90  * scale)
        sw2     = int(58  * scale)
        sh2     = int(46  * scale)
        fnt_s   = max(7, int(14*scale))
        fnt_xs  = max(6, int(6*scale))
        fnt_m   = max(8, int(10*scale))

        # Outer circle
        cv.create_oval(cx-r_outer, cy-r_outer, cx+r_outer, cy+r_outer,
                       fill=CARD_BG, outline=ACCENT, width=2)

        # Category + preset info bar at top inside circle
        cv.create_text(cx, cy-r_outer+14, text=f"📂 {cat}",
                       fill=ACCENT, font=("Segoe UI",fnt_xs,"bold"))
        if len(presets) > 1:
            cv.create_text(cx, cy-r_outer+26, text=f"{preset_name}  ({idx+1}/{len(presets)})",
                           fill=TEXT_PRI, font=("Segoe UI",fnt_xs))
        elif preset_name:
            cv.create_text(cx, cy-r_outer+26, text=preset_name,
                           fill=TEXT_PRI, font=("Segoe UI",fnt_xs))

        # Center circle
        cv.create_oval(cx-r_inner, cy-r_inner, cx+r_inner, cy+r_inner,
                       fill=DARK_BG, outline=ACCENT, width=2)
        cv.create_text(cx, cy-int(10*scale), text="🎮", font=("Segoe UI",fnt_m))
        page_txt = f"{idx+1}/{len(presets)}" if len(presets)>1 else "✓"
        cv.create_text(cx, cy+int(10*scale), text=page_txt,
                       fill=ACCENT, font=("Segoe UI",fnt_xs,"bold"))

        # D-pad slots
        slot_cfg = [
            ("up",    "▲", cx,        cy-slot_r),
            ("down",  "▼", cx,        cy+slot_r),
            ("left",  "◀", cx-slot_r, cy),
            ("right", "▶", cx+slot_r, cy),
        ]
        # Keep refs to images so they aren't GC'd
        _img_refs = []
        for direction, arrow, sx, sy in slot_cfg:
            b       = binds.get(direction, {})
            name    = b.get("name","—") if b else "—"
            element = b.get("element","") if b else ""
            has     = bool(b and b.get("path"))
            arr_col  = ACCENT   if has else BORDER
            text_col = TEXT_PRI if has else TEXT_SEC
            # Slot box
            cv.create_rectangle(sx-sw2//2, sy-sh2//2, sx+sw2//2, sy+sh2//2,
                                 fill=CARD_BG, outline=arr_col,
                                 width=2 if has else 1)
            # Element icon if available, else arrow
            el_img_raw = _element_images.get(element) if has and element else None
            el_img = None
            if el_img_raw:
                try:
                    from PIL import Image, ImageTk
                    icon_size = max(16, int(24*scale))
                    pil_img = ImageTk.getimage(el_img_raw).resize(
                        (icon_size, icon_size), Image.LANCZOS)
                    el_img = ImageTk.PhotoImage(pil_img)
                    _img_refs.append(el_img)
                except Exception:
                    el_img = el_img_raw
                    _img_refs.append(el_img)
            if el_img:
                cv.create_image(sx, sy-int(8*scale), image=el_img, anchor="center")
            else:
                cv.create_text(sx, sy-int(8*scale), text=arrow, fill=arr_col,
                               font=("Segoe UI",fnt_s,"bold"))
            short = name if len(name)<=10 else name[:9]+"…"
            cv.create_text(sx, sy+int(10*scale), text=short, fill=text_col,
                           font=("Segoe UI",fnt_xs), width=sw2-4)
        # Store refs on canvas to prevent GC
        cv._img_refs = _img_refs

        # Hint row below circle
        cv.create_text(cx, SIZE+16,
                       text="RS cycle/close  •  3s timeout",
                       fill=TEXT_SEC, font=("Segoe UI",fnt_xs))

    def _hide_ctrl_overlay(self):
        if self._ctrl_overlay and self._ctrl_overlay.winfo_exists():
            try: self._ctrl_overlay.destroy()
            except: pass
        self._ctrl_overlay = None

    def _show_ctrl_toast(self, msg):
        """Show a small 2-second dismissing popup for controller errors."""
        toast = tk.Toplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.attributes("-alpha", 0.92)
        toast.configure(bg=CARD_BG)
        try: toast.wm_attributes("-transparentcolor", "")
        except: pass
        lbl = tk.Label(toast, text=msg, bg=CARD_BG, fg=TEXT_PRI,
                       font=("Segoe UI",10,"bold"), padx=24, pady=14)
        lbl.pack()
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        toast.update_idletasks()
        w = toast.winfo_reqwidth(); h = toast.winfo_reqheight()
        toast.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        # Auto-dismiss after 2 seconds
        toast.after(2000, lambda: toast.destroy() if toast.winfo_exists() else None)
        # Click to dismiss early
        lbl.bind("<Button-1>", lambda e: toast.destroy())

    def _on_search_change(self,*_):
        if self._search_after: self.after_cancel(self._search_after)
        self._search_after=self.after(180,self._refresh_active_tab)

    # ── UI ───────────────────────────────────

    def _build_ui(self):
        # Style scrollbars dark
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        self._apply_scrollbar_style()
        # Header
        header=tk.Frame(self,bg=DARK_BG,pady=10); header.pack(fill="x",padx=16)
        # Portal logo button — click for mode dropdown
        self._logo_btn = tk.Label(header, text="⬡", bg=DARK_BG, fg=ACCENT,
                                  font=("Segoe UI",22,"bold"), cursor="hand2")
        self._logo_btn.pack(side="left", padx=(0,6))
        self._logo_btn.bind("<Button-1>", lambda e: self._toggle_mode_dropdown(self._logo_btn))

        tk.Label(header,text="SKYLANDERS PORTAL",bg=DARK_BG,fg=TEXT_PRI,font=("Segoe UI",16,"bold")).pack(side="left")

        # VirtPort status indicator
        self._vp_dot=tk.Label(header,text="●",bg=DARK_BG,fg="#555e6e",font=("Segoe UI",14))
        self._vp_dot.pack(side="left",padx=(10,2))
        self._vp_lbl=tk.Label(header,text="VirtPort",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",8))
        self._vp_lbl.pack(side="left")

        # Global keybind status removed from header — see Settings > Keybinds

        tk.Button(header,text="📁  Folder",bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",font=("Segoe UI",9),padx=8,pady=4,activebackground=CARD_HOVER,activeforeground=TEXT_PRI,command=self._pick_folder).pack(side="right")
        tk.Button(header,text="🔄",bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",font=("Segoe UI",9),padx=8,pady=4,activebackground=CARD_HOVER,activeforeground=TEXT_PRI,command=self._force_rescan).pack(side="right",padx=(0,4))
        tk.Button(header,text="⚙",bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",font=("Segoe UI",11),padx=8,pady=4,activebackground=CARD_HOVER,activeforeground=TEXT_PRI,command=self._show_settings).pack(side="right",padx=(0,4))


        # Element legend
        # Element filter bar — icons as buttons
        self._el_filter = tk.StringVar(value="")
        self._el_filter_btns = {}
        leg=tk.Frame(self,bg=DARK_BG); leg.pack(fill="x",padx=16,pady=(0,4))
        tk.Label(leg,text="Filter:",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",8)).pack(side="left",padx=(0,4))

        def make_el_filter(el, color):
            def toggle():
                if self._el_filter.get() == el:
                    self._el_filter.set("")
                else:
                    self._el_filter.set(el)
                self._refresh_active_tab()
                for e2, b2 in self._el_filter_btns.items():
                    active = self._el_filter.get() == e2
                    b2.config(relief="solid" if active else "flat",
                              bg=ELEMENT_COLORS[e2] if active else CARD_BG)
            return toggle

        for el, color in ELEMENT_COLORS.items():
            img = _element_images.get(el)
            if img:
                btn = tk.Button(leg, image=img, bg=CARD_BG,
                                relief="flat", cursor="hand2",
                                bd=1, padx=1, pady=1,
                                activebackground=color,
                                command=make_el_filter(el, color))
            else:
                btn = tk.Button(leg, text=el[:2].capitalize(),
                                bg=CARD_BG, fg=color, relief="flat",
                                cursor="hand2", font=("Segoe UI",7,"bold"),
                                padx=4, pady=2,
                                command=make_el_filter(el, color))
            btn.pack(side="left", padx=1)
            self._el_filter_btns[el] = btn

        tk.Button(leg, text="✕", bg=CARD_BG, fg=TEXT_SEC, relief="flat",
                  cursor="hand2", font=("Segoe UI",8), padx=4, pady=2,
                  command=lambda: (self._el_filter.set(""),
                      [b.config(relief="flat", bg=CARD_BG) for b in self._el_filter_btns.values()],
                      self._refresh_active_tab())).pack(side="left", padx=(4,0))

        # Search
        # Slot selector — pick which portal slot to load into
        slot_row = tk.Frame(self, bg=DARK_BG)
        slot_row.pack(fill="x", padx=16, pady=(0,4))
        tk.Label(slot_row, text="Slot:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left", padx=(0,6))
        self._slot_btns = {}
        def make_slot_btn(s):
            btn = tk.Label(slot_row, text=str(s),
                           bg=CARD_BG if s!=1 else ACCENT,
                           fg="#fff" if s==1 else TEXT_SEC,
                           font=("Segoe UI",9,"bold"),
                           width=3, cursor="hand2", pady=3)
            btn.pack(side="left", padx=2)
            def click(slot=s):
                self._active_slot = slot
                for ss, b in self._slot_btns.items():
                    b.config(bg=ACCENT if ss==slot else CARD_BG,
                             fg="#fff" if ss==slot else TEXT_SEC)

            btn.bind("<Button-1>", lambda e, f=click: f())
            self._slot_btns[s] = btn
        for s in range(1, 6):
            make_slot_btn(s)

        # Clear button — removes whatever is on the active slot
        def do_clear():
            host = self.cfg.get("vp_host","localhost")
            port = self.cfg.get("vp_port",5678)
            slot = self._active_slot
            self._status_var.set(f"⏳ Clearing slot {slot}…")
            def run():
                ok, err = virtport_clear(slot=slot, host=host, port=port)
                # Always clear slot 2 as well to remove SF bottom halves
                if slot == 1:
                    virtport_clear(slot=2, host=host, port=port)
                if ok:
                    self.after(0, lambda: self._status_var.set(
                        f"✔ Slot {slot} cleared" + (" + slot 2" if slot==1 else "")))
                else:
                    self.after(0, lambda: self._status_var.set(f"⚠ Clear failed: {err}"))
                self._sf_combo_active = False
            threading.Thread(target=run, daemon=True).start()

        tk.Label(slot_row, text="", bg=DARK_BG, width=2).pack(side="left")
        clear_btn = tk.Label(slot_row, text="✕ Clear", bg=CARD_BG, fg="#e74c3c",
                             font=("Segoe UI",9,"bold"), padx=10, pady=3, cursor="hand2")
        clear_btn.pack(side="left", padx=(4,0))
        clear_btn.bind("<Button-1>", lambda e: do_clear())
        clear_btn.bind("<Enter>", lambda e: clear_btn.config(bg=CARD_HOVER))
        clear_btn.bind("<Leave>", lambda e: clear_btn.config(bg=CARD_BG))



        sf=tk.Frame(self,bg=DARK_BG); sf.pack(fill="x",padx=16,pady=(0,8))
        tk.Label(sf,text="🔍",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",11)).pack(side="left",padx=(0,6))
        tk.Entry(sf,textvariable=self.search_var,bg=CARD_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,relief="flat",font=("Segoe UI",11)).pack(side="left",fill="x",expand=True,ipady=6,ipadx=8)
        tk.Button(sf,text="✕",bg=CARD_BG,fg=TEXT_SEC,relief="flat",cursor="hand2",font=("Segoe UI",10),command=lambda:self.search_var.set("")).pack(side="left",padx=(4,0))

        self.tab_bar=tk.Frame(self,bg=DARK_BG); self.tab_bar.pack(fill="x",padx=16,pady=(0,4))
        # Container holds all tab frames — we pack_forget/pack to switch with no flicker
        self._content_container=tk.Frame(self,bg=PANEL_BG)
        self._content_container.pack(fill="both",expand=True,padx=16,pady=(0,8))
        self._tab_frames={}       # tab_name -> tk.Frame (cached, never destroyed)
        self._active_frame=None   # currently visible frame
        self._default_content=None
        # self.content always points to the active frame for backward compat
        self.content=tk.Frame(self._content_container,bg=PANEL_BG)
        self.content.pack(fill="both",expand=True)
        self._default_content=self.content


        sbar=tk.Frame(self,bg=DARK_BG,height=28); sbar.pack(fill="x",padx=16,pady=(0,8))
        tk.Label(sbar,textvariable=self._status_var,bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),anchor="w").pack(side="left",fill="x",expand=True)
        self.clip_lbl=tk.Label(sbar,text="",bg=DARK_BG,fg="#3dba6f",font=("Segoe UI",9,"bold")); self.clip_lbl.pack(side="right")

        self._build_tabs(); self._show_empty_state()

    def _toggle_manual_mode(self, e=None):
        self._manual_mode = not self._manual_mode
        if self._manual_mode:
            self._enter_manual_mode()
        else:
            self._exit_manual_mode()

    def _enter_manual_mode(self):
        RBORDER  = "#3a0a0a"
        RCARD    = "#2a0808"
        RCARD_HV = "#3a1010"
        RACCENT  = "#c0392b"
        RTXT_PRI = "#ffdddd"
        RTXT_SEC = "#aa6666"
        RBG      = "#140303"

        # Close any open Toplevel windows
        for win in self.winfo_children():
            if isinstance(win, tk.Toplevel):
                try: win.destroy()
                except Exception: pass

        # Recursively tint everything red including the window itself
        self.configure(bg=RBG)

        def tint(widget):
            try:
                cls = widget.winfo_class()
                if cls in ("Frame","Label","Checkbutton","Canvas","Scrollbar"):
                    widget.configure(bg=RBG)
                elif cls == "Entry":
                    widget.configure(bg="#2a0808", fg="#ff9999",
                                     insertbackground="#ff9999",
                                     disabledbackground=RBG,
                                     highlightbackground=RBG,
                                     highlightcolor=RBG)
                elif cls == "Button":
                    widget.configure(bg="#2a0808", fg="#884444",
                                     activebackground="#3a1010",
                                     activeforeground="#ffaaaa")
            except Exception: pass
            for child in widget.winfo_children():
                tint(child)

        for child in self.winfo_children():
            if child is not self.content:
                tint(child)

        # Replace tab bar with a single "All" button that exits manual mode
        for w in self.tab_bar.winfo_children(): w.destroy()
        tk.Label(self.tab_bar, text="⚠ MANUAL MODE",
                 bg=RBG, fg=RACCENT,
                 font=("Segoe UI",9,"bold")).pack(side="left", padx=8)

        # Clear and rebuild content
        for w in self.content.winfo_children(): w.destroy()
        self.content.configure(bg=RBG)
        self._vlist = None

        # Banner
        banner = tk.Frame(self.content, bg=RACCENT, pady=8)
        banner.pack(fill="x")
        tk.Label(banner, text="⚠  MANUAL MODE  —  Shift+M to exit",
                 bg=RACCENT, fg="#fff",
                 font=("Segoe UI",12,"bold")).pack(side="left", padx=12)
        tk.Button(banner, text="✕ Exit",
                  bg="#8b0000", fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=10, pady=3,
                  activebackground="#600000",
                  command=self._exit_manual_mode).pack(side="right", padx=8)

        tk.Label(self.content, text="Direct file loading — bypasses VirtPort auto-load",
                 bg=RBG, fg=RTXT_SEC, font=("Segoe UI",8)).pack(pady=(6,2))
        tk.Frame(self.content, bg=RBORDER, height=1).pack(fill="x", padx=12, pady=(0,6))

        # Query VirtPort for current slot state
        self._manual_slots = {}
        slot_labels = {}

        slots_frame = tk.Frame(self.content, bg=RBG)
        slots_frame.pack(fill="both", expand=True, padx=16)

        for slot in range(1, 9):
            row = tk.Frame(slots_frame, bg=RCARD, pady=7, padx=10)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=f"Skylander {slot}",
                     bg=RCARD, fg=RTXT_SEC,
                     font=("Segoe UI",9,"bold"), width=12, anchor="w").pack(side="left")
            file_lbl = tk.Label(row, text="Checking…", bg=RCARD, fg=RTXT_SEC,
                                font=("Segoe UI",9), anchor="w")
            file_lbl.pack(side="left", fill="x", expand=True, padx=(0,8))
            slot_labels[slot] = file_lbl

            def make_load(s=slot, lbl=file_lbl):
                def load():
                    path = filedialog.askopenfilename(
                        title=f"Load into Slot {s}",
                        filetypes=[("Skylander files","*.sky"),("All files","*.*")],
                        initialdir=self.cfg.get("root_folder") or os.path.expanduser("~"),
                    )
                    if not path: return
                    name = os.path.splitext(os.path.basename(path))[0]
                    lbl.config(text=name[:24]+"…" if len(name)>24 else name, fg="#ff9999")
                    self._manual_slots[s] = path
                    host=self.cfg.get("vp_host","localhost")
                    port=self.cfg.get("vp_port",5678)
                    def run():
                        ok,err=virtport_load(path,slot=s,host=host,port=port)
                        self.after(0,lambda: lbl.config(fg="#ff6666") if ok
                                   else lbl.config(text=f"⚠ {err[:20]}",fg="#ff4444"))
                    threading.Thread(target=run,daemon=True).start()
                return load

            def make_clear(s=slot, lbl=file_lbl):
                def clear():
                    lbl.config(text="None", fg=RTXT_PRI)
                    self._manual_slots.pop(s, None)
                return clear

            tk.Button(row, text="Load", bg=RACCENT, fg="#fff", relief="flat", cursor="hand2",
                      font=("Segoe UI",8,"bold"), padx=10, pady=2,
                      activebackground="#e74c3c",
                      command=make_load()).pack(side="right", padx=(2,0))
            tk.Button(row, text="Clear", bg=RCARD_HV, fg=RTXT_SEC, relief="flat", cursor="hand2",
                      font=("Segoe UI",8), padx=8, pady=2,
                      activebackground="#4a1010",
                      command=make_clear()).pack(side="right", padx=(0,2))

        # Set all slots to None by default
        for s in range(1,9):
            slot_labels[s].config(text="None", fg=RTXT_PRI)
    def _exit_manual_mode(self):
        self._manual_mode = False
        # Nuke all widgets and do a full clean rebuild
        for w in self.winfo_children():
            w.destroy()
        self.configure(bg=DARK_BG)
        self._build_ui()
        if self.cfg.get("root_folder"):
            self._load_folder_startup(self.cfg["root_folder"])
        # Re-register keybind (lost after widget destroy)
        self.bind_all("<Shift-M>", self._toggle_manual_mode)

    def _toggle_mode_dropdown(self, anchor):
        self._close_dropdown()
        self._dropdown_open = True
        win = tk.Toplevel(self)
        win.overrideredirect(True)
        win.configure(bg=BORDER)
        self._dropdown_win = win
        win.geometry(f"+{anchor.winfo_rootx()}+{anchor.winfo_rooty()+anchor.winfo_height()}")
        inner = tk.Frame(win, bg=CARD_BG)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Label(inner, text="MODE", bg=CARD_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8,"bold"), padx=12, pady=6).pack(fill="x")
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
        for label, mode, icon in [
            ("Skylanders Portal", "portal", "⬡"),
            ("Randomizer", "randomizer", "🎲"),
        ]:
            row = tk.Frame(inner, bg=CARD_BG, cursor="hand2")
            row.pack(fill="x")
            strip = tk.Frame(row, bg=ACCENT, width=3)
            strip.pack(side="left", fill="y")
            it = tk.Label(row, text=f"  {icon}  {label}",
                          bg=CARD_BG, fg=TEXT_PRI,
                          font=("Segoe UI",10), anchor="w",
                          cursor="hand2", padx=8, pady=9)
            it.pack(side="left", fill="x", expand=True)
            if self._mode == mode:
                it.config(fg=ACCENT, font=("Segoe UI",10,"bold"))
            for w in (row, it, strip):
                w.bind("<Enter>", lambda e, r=row, i=it: (r.config(bg=CARD_HOVER), i.config(bg=CARD_HOVER)))
                w.bind("<Leave>", lambda e, r=row, i=it: (r.config(bg=CARD_BG), i.config(bg=CARD_BG)))
                w.bind("<Button-1>", lambda e, m=mode: self._set_mode(m))
        self.bind("<Button-1>", self._on_outside_click)
        win.bind("<Button-1>", lambda e: None)

    def _set_mode(self, mode):
        self._close_dropdown()
        self._mode = mode
        if mode == "randomizer":
            self._show_randomizer()
        else:
            self._logo_btn.config(fg=ACCENT)
            self._refresh_active_tab()

    def _show_randomizer(self, mode="normal"):
        """Randomizer with 3 subtabs. Layout: filters left, result+box right."""
        self._logo_btn.config(fg="#e67e22")
        for w in self.content.winfo_children(): w.destroy()
        self._vlist = None
        self.tab_bar.pack_forget()

        GAMES_WITH_LIGHT_DARK = {"Trap Team","SuperChargers","Imaginators"}
        ALL_GAMES = ["Spyros Adventure","Giants","Swap Force","Trap Team","SuperChargers","Imaginators"]
        ALL_ELEMENTS = ["fire","water","earth","air","life","undead","tech","magic","light","dark"]

        nuz_file = os.path.join(APP_DATA_DIR, "nuzlocke.json")
        def load_nuz():
            try:
                if os.path.exists(nuz_file):
                    with open(nuz_file) as f2: return json.load(f2)
            except Exception: pass
            return {"collected":[],"defeated":[]}
        def save_nuz(state):
            with open(nuz_file,"w") as f2: json.dump(state,f2,indent=2)
        nuz_state = load_nuz()

        # ── Main frame (no scroll — everything fits side by side) ──
        main = tk.Frame(self.content, bg=PANEL_BG)
        main.pack(fill="both", expand=True, padx=16, pady=12)

        # Header
        hdr = tk.Frame(main, bg=PANEL_BG)
        hdr.pack(fill="x", pady=(0,8))
        tk.Label(hdr, text="🎲  Randomizer", bg=PANEL_BG, fg=TEXT_PRI,
                 font=("Segoe UI",14,"bold")).pack(side="left")
        tk.Button(hdr, text="← Back to Portal",
                  bg=CARD_BG, fg=TEXT_SEC, relief="flat", cursor="hand2",
                  font=("Segoe UI",9), padx=10, pady=4,
                  activebackground=CARD_HOVER,
                  command=lambda: self._set_mode("portal")).pack(side="right")

        # Subtab bar
        subtab_bar = tk.Frame(main, bg=PANEL_BG)
        subtab_bar.pack(fill="x")
        subtab_btns = {}
        subtab_panels = {}
        active_subtab = [mode]

        def switch_subtab(name):
            active_subtab[0] = name
            for p in subtab_panels.values(): p.pack_forget()
            subtab_panels[name].pack(fill="both", expand=True)
            for n, b in subtab_btns.items():
                b.config(fg=ACCENT if n==name else TEXT_SEC,
                         font=("Segoe UI",9,"bold") if n==name else ("Segoe UI",9),
                         highlightthickness=2 if n==name else 0,
                         highlightbackground=ACCENT)

        for tname, tlabel in [("normal","🎲 Random"),("swapforce","🔀 Swap Force"),("nuzlocke","☠ Nuzlocke")]:
            btn = tk.Label(subtab_bar, text=tlabel, bg=PANEL_BG, fg=TEXT_SEC,
                           font=("Segoe UI",9), cursor="hand2", padx=10, pady=5)
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda e, n=tname: switch_subtab(n))
            subtab_btns[tname] = btn
            subtab_panels[tname] = tk.Frame(main, bg=PANEL_BG)

        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", pady=(4,0))

        # ── Build filters (left column) ──
        def build_filters(parent):
            f = tk.Frame(parent, bg=PANEL_BG)
            game_col = tk.Frame(f, bg=PANEL_BG)
            game_col.pack(side="left", fill="y", padx=(0,20), anchor="n")
            tk.Label(game_col, text="Games", bg=PANEL_BG, fg=TEXT_PRI,
                     font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,4))
            game_vars = {}
            for g in ALL_GAMES:
                var = tk.BooleanVar(value=True)
                game_vars[g] = var
                tk.Checkbutton(game_col, text=GAME_DISPLAY_NAMES.get(g,g),
                               variable=var, bg=PANEL_BG, fg=TEXT_PRI,
                               selectcolor=CARD_BG, activebackground=PANEL_BG,
                               font=("Segoe UI",9)).pack(anchor="w")

            el_col = tk.Frame(f, bg=PANEL_BG)
            el_col.pack(side="left", fill="y", anchor="n")
            tk.Label(el_col, text="Elements", bg=PANEL_BG, fg=TEXT_PRI,
                     font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,4))
            all_el_var = tk.BooleanVar(value=True)
            el_vars = {}
            def toggle_all():
                for v in el_vars.values(): v.set(all_el_var.get())
            def on_el_change():
                all_el_var.set(all(v.get() for v in el_vars.values()))
            tk.Checkbutton(el_col, text="All Elements", variable=all_el_var,
                           bg=PANEL_BG, fg=ACCENT, selectcolor=CARD_BG,
                           activebackground=PANEL_BG, font=("Segoe UI",9,"bold"),
                           command=toggle_all).pack(anchor="w")
            tk.Frame(el_col, bg=BORDER, height=1).pack(fill="x", pady=3)
            for el in ALL_ELEMENTS:
                var = tk.BooleanVar(value=True)
                el_vars[el] = var
                row = tk.Frame(el_col, bg=PANEL_BG); row.pack(anchor="w")
                tk.Frame(row, bg=ELEMENT_COLORS.get(el,TEXT_SEC),
                         width=10, height=10).pack(side="left", padx=(0,4), pady=1)
                tk.Checkbutton(row, text=el.capitalize(), variable=var,
                               bg=PANEL_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                               activebackground=PANEL_BG, font=("Segoe UI",9),
                               command=on_el_change).pack(side="left")
            return f, game_vars, all_el_var, el_vars

        def build_pool(game_vars, all_el_var, el_vars, exclude_paths=None, sf_halves=False):
            """Build candidate pool. sf_halves=True includes (Top)/(Bottom) files."""
            selected_games = [g for g,v in game_vars.items() if v.get()]
            selected_els   = None if all_el_var.get() else [e for e,v in el_vars.items() if v.get()]
            pool = []
            for game in selected_games:
                for s in self.all_skylanders.get(game,[]):
                    p = s["path"].lower().replace("\\","/")
                    parts = p.split("/")
                    # Always exclude items/sidekicks
                    if "item" in parts or "items" in parts: continue
                    if "sidekick" in p or "sidekick" in s["name"].lower(): continue
                    # Exclude swap force halves unless sf_halves mode
                    if not sf_halves:
                        nl = s["name"].lower()
                        if "(top)" in nl or "(bottom)" in nl: continue
                    el = detect_element(s["name"], s["path"])
                    if selected_els and el not in selected_els: continue
                    if el in ("light","dark") and game not in GAMES_WITH_LIGHT_DARK: continue
                    if exclude_paths and s["path"] in exclude_paths: continue
                    pool.append((s, game))
            return pool

        # ── NORMAL panel ──
        np = subtab_panels["normal"]
        body_n = tk.Frame(np, bg=PANEL_BG)
        body_n.pack(fill="both", expand=True, pady=8)

        filt_n, gv_n, aev_n, ev_n = build_filters(body_n)
        filt_n.pack(side="left", fill="y", padx=(0,16), anchor="n")

        right_n = tk.Frame(body_n, bg=PANEL_BG)
        right_n.pack(side="left", fill="both", expand=True, anchor="n")

        # Result card (blue circle area)
        res_n = tk.Frame(right_n, bg=CARD_BG, pady=18)
        res_n.pack(fill="x", pady=(0,8))
        tk.Frame(res_n, bg=ACCENT, width=4).pack(side="left", fill="y")
        ri_n = tk.Frame(res_n, bg=CARD_BG); ri_n.pack(side="left", fill="both", expand=True, padx=12)
        rl_n = tk.Label(ri_n, text="Press Randomize!", bg=CARD_BG, fg=TEXT_SEC,
                        font=("Segoe UI",13,"bold"))
        rl_n.pack(anchor="w")
        rs_n = tk.Label(ri_n, text="", bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",9))
        rs_n.pack(anchor="w")
        st_n = tk.Label(right_n, text="", bg=PANEL_BG, fg="#3dba6f", font=("Segoe UI",9))
        st_n.pack(anchor="w", pady=(0,6))

        # Randomize button (green circle area)
        tk.Button(right_n, text="🎲  Randomize!",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",12,"bold"), pady=10,
                  activebackground="#2980b9",
                  command=lambda: do_rand(gv_n, aev_n, ev_n, rl_n, rs_n, st_n, None)).pack(fill="x")

        # ── SWAP FORCE panel ──
        sp = subtab_panels["swapforce"]
        body_s = tk.Frame(sp, bg=PANEL_BG)
        body_s.pack(fill="both", expand=True, pady=8)

        filt_s, gv_s, aev_s, ev_s = build_filters(body_s)
        filt_s.pack(side="left", fill="y", padx=(0,16), anchor="n")

        right_s = tk.Frame(body_s, bg=PANEL_BG)
        right_s.pack(side="left", fill="both", expand=True, anchor="n")

        tk.Label(right_s, text="ℹ Picks random top + bottom halves",
                 bg=PANEL_BG, fg=TEXT_SEC, font=("Segoe UI",8)).pack(anchor="w", pady=(0,4))

        res_s = tk.Frame(right_s, bg=CARD_BG, pady=18)
        res_s.pack(fill="x", pady=(0,8))
        tk.Frame(res_s, bg=GAME_COLORS["Swap Force"], width=4).pack(side="left", fill="y")
        ri_s = tk.Frame(res_s, bg=CARD_BG); ri_s.pack(side="left", fill="both", expand=True, padx=12)
        rl_s = tk.Label(ri_s, text="Press Randomize!", bg=CARD_BG, fg=TEXT_SEC,
                        font=("Segoe UI",13,"bold"))
        rl_s.pack(anchor="w")
        rs_s = tk.Label(ri_s, text="", bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",9))
        rs_s.pack(anchor="w")
        st_s = tk.Label(right_s, text="", bg=PANEL_BG, fg="#3dba6f", font=("Segoe UI",9))
        st_s.pack(anchor="w", pady=(0,6))

        tk.Button(right_s, text="🎲  Random Swap Force Combo!",
                  bg=GAME_COLORS["Swap Force"], fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",12,"bold"), pady=10,
                  activebackground="#2ecc71",
                  command=lambda: do_rand_sf(rl_s, rs_s, st_s)).pack(fill="x")

        # ── NUZLOCKE panel ──
        nzp = subtab_panels["nuzlocke"]
        body_z = tk.Frame(nzp, bg=PANEL_BG)
        body_z.pack(fill="both", expand=True, pady=8)

        filt_z, gv_z, aev_z, ev_z = build_filters(body_z)
        filt_z.pack(side="left", fill="y", padx=(0,16), anchor="n")

        right_z = tk.Frame(body_z, bg=PANEL_BG)
        right_z.pack(side="left", fill="both", expand=True, anchor="n")

        # Result card
        res_z = tk.Frame(right_z, bg=CARD_BG, pady=18)
        res_z.pack(fill="x", pady=(0,4))
        tk.Frame(res_z, bg="#e74c3c", width=4).pack(side="left", fill="y")
        ri_z = tk.Frame(res_z, bg=CARD_BG); ri_z.pack(side="left", fill="both", expand=True, padx=12)
        rl_z = tk.Label(ri_z, text="Press Randomize!", bg=CARD_BG, fg=TEXT_SEC,
                        font=("Segoe UI",13,"bold"))
        rl_z.pack(anchor="w")
        rs_z = tk.Label(ri_z, text="", bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",9))
        rs_z.pack(anchor="w")
        st_z = tk.Label(right_z, text="", bg=PANEL_BG, fg="#3dba6f", font=("Segoe UI",9))
        st_z.pack(anchor="w", pady=(0,2))

        # Nuzlocke box (red circle area — right side, below result)
        nuz_hdr = tk.Frame(right_z, bg=PANEL_BG)
        nuz_hdr.pack(fill="x", pady=(4,2))
        tk.Label(nuz_hdr, text="☠ Nuzlocke Team",
                 bg=PANEL_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(side="left")
        tk.Button(nuz_hdr, text="Clear All",
                  bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                  font=("Segoe UI",8), padx=6, pady=2,
                  activebackground=CARD_HOVER,
                  command=lambda: (nuz_state.update({"collected":[],"defeated":[]}),
                                   save_nuz(nuz_state), refresh_nuz())).pack(side="right")

        # Scrollable collected box
        box_outer = tk.Frame(right_z, bg=CARD_BG, height=220)
        box_outer.pack(fill="x", pady=(0,6))
        box_outer.pack_propagate(False)
        box_canvas = tk.Canvas(box_outer, bg=CARD_BG, highlightthickness=0)
        box_sb = ttk.Scrollbar(box_outer, orient="vertical", command=box_canvas.yview)
        box_canvas.configure(yscrollcommand=box_sb.set)
        box_sb.pack(side="right", fill="y")
        box_canvas.pack(side="left", fill="both", expand=True)
        box_inner = tk.Frame(box_canvas, bg=CARD_BG)
        box_win = box_canvas.create_window((0,0), window=box_inner, anchor="nw")
        box_inner.bind("<Configure>", lambda e: box_canvas.configure(scrollregion=box_canvas.bbox("all")))
        box_canvas.bind("<Configure>", lambda e: box_canvas.itemconfig(box_win, width=e.width))
        box_canvas.bind("<MouseWheel>", lambda e: box_canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        def refresh_nuz():
            for w in box_inner.winfo_children(): w.destroy()
            col = nuz_state["collected"]
            if not col:
                tk.Label(box_inner, text="No Skylanders yet",
                         bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",9),
                         padx=8, pady=8).pack(anchor="w")
                return
            for entry in col:
                is_dead = entry["path"] in nuz_state["defeated"]
                row = tk.Frame(box_inner,
                               bg="#1a0a0a" if is_dead else CARD_BG,
                               pady=4, padx=8)
                row.pack(fill="x")
                el = detect_element(entry.get("name",""), entry.get("path",""))
                tk.Frame(row, bg=ELEMENT_COLORS.get(el,BORDER),
                         width=3).pack(side="left", fill="y", padx=(0,6))
                tk.Label(row, text=entry["name"],
                         bg=row["bg"],
                         fg="#444" if is_dead else TEXT_PRI,
                         font=("Segoe UI",9,"bold" if not is_dead else "normal")
                         ).pack(side="left", fill="x", expand=True)
                if is_dead:
                    tk.Label(row, text="💀", bg=row["bg"],
                             font=("Segoe UI",10)).pack(side="right")
                else:
                    def mk_defeat(e=entry):
                        def do():
                            nuz_state["defeated"].append(e["path"])
                            save_nuz(nuz_state); refresh_nuz()
                        return do
                    def mk_load(e=entry):
                        def do():
                            host=self.cfg.get("vp_host","localhost")
                            port=self.cfg.get("vp_port",5678)
                            threading.Thread(
                                target=lambda: virtport_load(e["path"],self._active_slot,host,port),
                                daemon=True).start()
                            st_z.config(text=f"⏳ Loading {e['name']}…", fg="#3dba6f")
                        return do
                    tk.Button(row, text="▶",
                              bg=CARD_BG, fg=ACCENT, relief="flat", cursor="hand2",
                              font=("Segoe UI",9), padx=4,
                              activebackground=CARD_HOVER,
                              command=mk_load()).pack(side="right")
                    tk.Button(row, text="💀",
                              bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                              font=("Segoe UI",9), padx=4,
                              activebackground=CARD_HOVER,
                              command=mk_defeat()).pack(side="right")

        refresh_nuz()

        # Nuzlocke randomize button
        tk.Button(right_z, text="🎲  Roll Nuzlocke Skylander!",
                  bg="#c0392b", fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",12,"bold"), pady=10,
                  activebackground="#e74c3c",
                  command=lambda: do_rand(gv_z, aev_z, ev_z, rl_z, rs_z, st_z, nuz_state)).pack(fill="x")

        # ── Shared randomize logic ──
        def do_rand(game_vars, all_el_var, el_vars, rl, rs, st, nuz):
            import random
            exclude = {e["path"] for e in nuz["collected"]} if nuz else None
            pool = build_pool(game_vars, all_el_var, el_vars, exclude_paths=exclude)
            if not pool:
                st.config(text="⚠ No matching Skylanders!" + (" All used!" if nuz else ""), fg="#e67e22")
                return
            sky, game = random.choice(pool)
            rl.config(text="???", fg=TEXT_SEC)
            rs.config(text=f"From: {GAME_DISPLAY_NAMES.get(game,game)}  ·  Slot {self._active_slot}")
            if nuz is not None:
                entry = {"name":sky["name"],"path":sky["path"],"game":game}
                nuz["collected"].append(entry)
                save_nuz(nuz)
                refresh_nuz()
            host=self.cfg.get("vp_host","localhost"); port=self.cfg.get("vp_port",5678)
            slot=self._active_slot
            def run():
                ok,err=virtport_load(sky["path"],slot,host,port)
                self.after(0,lambda:st.config(
                    text="✔ Mystery Skylander loaded!" if ok else f"⚠ {err}",
                    fg="#3dba6f" if ok else "#e67e22"))
            threading.Thread(target=run,daemon=True).start()

        def do_rand_sf(rl, rs, st):
            import random, re as _re
            sf_files = self.all_skylanders.get("Swap Force",[])
            tops    = [s for s in sf_files if "(top)" in s["name"].lower()]
            bottoms = [s for s in sf_files if "(bottom)" in s["name"].lower()]
            if not tops or not bottoms:
                st.config(text="⚠ No Swap Force halves found", fg="#e67e22"); return
            top = random.choice(tops)
            bot = random.choice(bottoms)
            tn = _re.sub("\\s*\\(Top\\)\\s*","",top["name"],flags=_re.IGNORECASE).strip()
            bn = _re.sub("\\s*\\(Bottom\\)\\s*","",bot["name"],flags=_re.IGNORECASE).strip()
            rl.config(text=f"??? + ???", fg=TEXT_SEC)
            rs.config(text="Random Swap Force combo → slots 1 & 2")
            host=self.cfg.get("vp_host","localhost"); port=self.cfg.get("vp_port",5678)
            def run():
                virtport_load(top["path"],1,host,port)
                virtport_load(bot["path"],2,host,port)
                self.after(0,lambda:st.config(text="✔ Combo loaded!",fg="#3dba6f"))
            threading.Thread(target=run,daemon=True).start()

        switch_subtab(mode)


    # ─── Controller preset functions ─────────────────────────────────────────
    def _show_controller_settings(self):
        win=tk.Toplevel(self); win.title("Controller Bindings"); self._set_win_icon(win)
        win.geometry("520x540"); win.configure(bg=DARK_BG); win.resizable(False,True); win.transient(self)
        tk.Label(win,text="🎮  Controller Bindings",bg=DARK_BG,fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold"),pady=12).pack()
        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=20)

        scroll_f=tk.Frame(win,bg=DARK_BG); scroll_f.pack(fill="both",expand=True,padx=20,pady=8)
        cv=tk.Canvas(scroll_f,bg=DARK_BG,highlightthickness=0)
        sb=ttk.Scrollbar(scroll_f,orient="vertical",command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        inner=tk.Frame(cv,bg=DARK_BG); cwin=cv.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",lambda e:cv.itemconfig(cwin,width=e.width))
        def _wheel(e): cv.yview_scroll(int(-1*(e.delta/120)),"units")
        cv.bind("<MouseWheel>",_wheel)
        inner.bind("<MouseWheel>",_wheel)
        win.bind("<MouseWheel>",_wheel)

        # ── Presets ────────────────────────────────────────────────────────
        phdr=tk.Frame(inner,bg=DARK_BG); phdr.pack(fill="x",pady=(8,6))
        tk.Label(phdr,text="Presets",bg=DARK_BG,fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(side="left")

        def refresh_presets():
            for w in plist_frame.winfo_children(): w.destroy()
            all_presets=list_ctrl_presets()
            if not all_presets:
                tk.Label(plist_frame,text="No presets yet — click ＋ New Preset to create one.",
                         bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",8),pady=8).pack(anchor="w")
                return
            by_cat={}
            for p in all_presets:
                by_cat.setdefault(p.get("category","Other"),[]).append(p)
            for cat in CTRL_WHEEL_GAMES:
                if cat not in by_cat: continue
                tk.Label(plist_frame,text=f"  {cat}",bg=DARK_BG,fg=ACCENT,
                         font=("Segoe UI",8,"bold")).pack(anchor="w",pady=(8,2))
                for p in by_cat[cat]:
                    pr=tk.Frame(plist_frame,bg=CARD_BG,pady=5,padx=10); pr.pack(fill="x",pady=1)
                    tk.Frame(pr,bg=ACCENT,width=3).pack(side="left",fill="y",padx=(0,8))
                    tk.Label(pr,text=p["name"],bg=CARD_BG,fg=TEXT_PRI,
                             font=("Segoe UI",9),anchor="w").pack(side="left",fill="x",expand=True)
                    def del_p(preset=p):
                        delete_ctrl_preset(preset["name"])
                        if hasattr(self,"_reload_ctrl_presets"):
                            _ctrl_wheel_presets[0]=self._reload_ctrl_presets()
                        refresh_presets()
                    tk.Button(pr,text="✕",bg=CARD_BG,fg="#e74c3c",relief="flat",cursor="hand2",
                              font=("Segoe UI",9),padx=6,
                              command=del_p).pack(side="right")
                    def edit_p(preset=p):
                        self._show_preset_editor(preset,refresh_presets)
                    tk.Button(pr,text="✎ Edit",bg=CARD_BG,fg=ACCENT,relief="flat",cursor="hand2",
                              font=("Segoe UI",8),command=edit_p).pack(side="right",padx=4)
                    # Bind mousewheel to preset rows
                    for w in pr.winfo_children():
                        try: w.bind("<MouseWheel>",_wheel)
                        except: pass
                    pr.bind("<MouseWheel>",_wheel)

        # New Preset button
        def new_preset_dialog():
            all_sky2=[dict(sky,game=game) for game,skys in self.all_skylanders.items() for sky in skys]
            all_sky2.sort(key=lambda x:x["name"])
            dlg=tk.Toplevel(win); dlg.title("New Preset"); self._set_win_icon(dlg)
            dlg.geometry("520x640"); dlg.configure(bg=DARK_BG)
            dlg.resizable(False,True); dlg.transient(win)
            tk.Label(dlg,text="New Controller Preset",bg=DARK_BG,fg=TEXT_PRI,
                     font=("Segoe UI",12,"bold"),pady=12).pack()
            tk.Frame(dlg,bg=BORDER,height=1).pack(fill="x")
            top=tk.Frame(dlg,bg=DARK_BG); top.pack(fill="x",padx=20,pady=10)
            nr=tk.Frame(top,bg=DARK_BG); nr.pack(fill="x",pady=(0,8))
            tk.Label(nr,text="Name:",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),width=8,anchor="w").pack(side="left")
            pname_var=tk.StringVar(value="My Preset")
            tk.Entry(nr,textvariable=pname_var,bg=CARD_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                     relief="flat",font=("Segoe UI",10),
                     highlightthickness=1,highlightbackground=BORDER).pack(side="left",fill="x",expand=True,ipady=4)
            gr=tk.Frame(top,bg=DARK_BG); gr.pack(fill="x")
            tk.Label(gr,text="Game:",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),width=8,anchor="w").pack(side="left")
            cat_var=tk.StringVar(value=get_ctrl_active_category(self.cfg))
            cat_om=tk.OptionMenu(gr,cat_var,*CTRL_WHEEL_GAMES)
            cat_om.config(bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",
                          font=("Segoe UI",9),activebackground=CARD_HOVER,
                          activeforeground=TEXT_PRI,highlightthickness=0,bd=0)
            cat_om["menu"].config(bg=CARD_BG,fg=TEXT_PRI,activebackground=ACCENT,
                                  activeforeground="#fff",relief="flat",font=("Segoe UI",9))
            cat_om.pack(side="left")
            tk.Frame(dlg,bg=BORDER,height=1).pack(fill="x",padx=20,pady=(8,0))
            tk.Label(dlg,text="D-pad Bindings",bg=DARK_BG,fg=TEXT_PRI,
                     font=("Segoe UI",10,"bold"),padx=20,pady=6).pack(anchor="w")
            sf2=tk.Frame(dlg,bg=DARK_BG); sf2.pack(fill="both",expand=True,padx=20)
            cv2=tk.Canvas(sf2,bg=DARK_BG,highlightthickness=0)
            sb2=ttk.Scrollbar(sf2,orient="vertical",command=cv2.yview)
            cv2.configure(yscrollcommand=sb2.set)
            sb2.pack(side="right",fill="y"); cv2.pack(side="left",fill="both",expand=True)
            inn2=tk.Frame(cv2,bg=DARK_BG); cw2=cv2.create_window((0,0),window=inn2,anchor="nw")
            inn2.bind("<Configure>",lambda e:cv2.configure(scrollregion=cv2.bbox("all")))
            cv2.bind("<Configure>",lambda e:cv2.itemconfig(cw2,width=e.width))
            def _wh2(e): cv2.yview_scroll(int(-1*(e.delta/120)),"units")
            cv2.bind("<MouseWheel>",_wh2); inn2.bind("<MouseWheel>",_wh2)
            new_binds={}
            directions=[("up","▲ Up"),("down","▼ Down"),("left","◀ Left"),("right","▶ Right")]
            def refresh_new():
                for w in inn2.winfo_children(): w.destroy()
                for direction,label in directions:
                    entry=new_binds.get(direction,{})
                    row=tk.Frame(inn2,bg=CARD_BG,pady=8,padx=12); row.pack(fill="x",pady=3)
                    row.bind("<MouseWheel>",_wh2)
                    tk.Label(row,text=label,bg=CARD_BG,fg=TEXT_SEC,
                             font=("Segoe UI",9,"bold"),width=12,anchor="w").pack(side="left")
                    nl=tk.Label(row,text=entry.get("name","— not set —"),bg=CARD_BG,
                                fg=TEXT_PRI if entry else TEXT_SEC,font=("Segoe UI",9),anchor="w")
                    nl.pack(side="left",fill="x",expand=True)
                    def open_np(d=direction,nll=nl):
                        pick=tk.Toplevel(dlg); pick.title("Pick Skylander"); self._set_win_icon(pick)
                        pick.geometry("360x460"); pick.configure(bg=DARK_BG); pick.transient(dlg)
                        sv2=tk.StringVar()
                        sf3=tk.Frame(pick,bg=DARK_BG); sf3.pack(fill="x",padx=10,pady=8)
                        tk.Label(sf3,text="🔍",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",10)).pack(side="left",padx=(0,4))
                        tk.Entry(sf3,textvariable=sv2,bg=CARD_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                                 relief="flat",font=("Segoe UI",10)).pack(side="left",fill="x",expand=True,ipady=4)
                        fav_only3=[False]; combo_only3=[False]
                        fr3=tk.Frame(pick,bg=DARK_BG); fr3.pack(fill="x",padx=10,pady=(0,4))
                        fb3=tk.Label(fr3,text="☆ Favorites",bg=DARK_BG,fg=TEXT_SEC,
                                     font=("Segoe UI",9),padx=8,pady=4,cursor="hand2"); fb3.pack(side="left")
                        cb3=tk.Label(fr3,text="⬡ Combos",bg=DARK_BG,fg=TEXT_SEC,
                                     font=("Segoe UI",9),padx=8,pady=4,cursor="hand2"); cb3.pack(side="left")
                        clb3=tk.Label(fr3,text="✕ Clear",bg=DARK_BG,fg="#e74c3c",
                                      font=("Segoe UI",9),padx=8,pady=4,cursor="hand2"); clb3.pack(side="right")
                        def do_clr3():
                            new_binds.pop(d,None); nll.config(text="— not set —",fg=TEXT_SEC)
                            pick.destroy(); refresh_new()
                        clb3.bind("<Button-1>",lambda e:do_clr3())
                        def tog3():
                            fav_only3[0]=not fav_only3[0]; combo_only3[0]=False
                            fb3.config(text="★ Favorites" if fav_only3[0] else "☆ Favorites",
                                       fg="#f5a623" if fav_only3[0] else TEXT_SEC,
                                       bg=CARD_BG if fav_only3[0] else DARK_BG)
                            cb3.config(fg=TEXT_SEC,bg=DARK_BG)
                            bld3(sv2.get())
                        fb3.bind("<Button-1>",lambda e:tog3())
                        def tog_combo3():
                            combo_only3[0]=not combo_only3[0]; fav_only3[0]=False
                            cb3.config(text="⬡ Combos",
                                       fg="#4488ff" if combo_only3[0] else TEXT_SEC,
                                       bg=CARD_BG if combo_only3[0] else DARK_BG)
                            fb3.config(text="☆ Favorites",fg=TEXT_SEC,bg=DARK_BG)
                            bld3(sv2.get())
                        cb3.bind("<Button-1>",lambda e:tog_combo3())
                        tk.Frame(pick,bg=BORDER,height=1).pack(fill="x")
                        lf3=tk.Frame(pick,bg=DARK_BG); lf3.pack(fill="both",expand=True)
                        lc3=tk.Canvas(lf3,bg=DARK_BG,highlightthickness=0)
                        ls3=ttk.Scrollbar(lf3,orient="vertical",command=lc3.yview)
                        lc3.configure(yscrollcommand=ls3.set)
                        ls3.pack(side="right",fill="y"); lc3.pack(side="left",fill="both",expand=True)
                        ROW_H3=34; _it3=[None]; _vt3=[0]; _wd3={}
                        def _rnd3(items,vt,ch,cw):
                            first=max(0,vt//ROW_H3); last=min(len(items)-1,(vt+ch)//ROW_H3)
                            for idx in list(_wd3.keys()):
                                if idx<first or idx>last: _wd3[idx].destroy(); del _wd3[idx]
                            for idx in range(first,last+1):
                                if idx in _wd3: continue
                                sky=items[idx]; y=idx*ROW_H3-vt
                                rw=tk.Frame(lc3,bg=DARK_BG,cursor="hand2",height=ROW_H3-1)
                                lc3.create_window(2,y,window=rw,anchor="nw",width=cw-4,height=ROW_H3-1)
                                lb=tk.Label(rw,text=sky["name"],bg=DARK_BG,fg=TEXT_PRI,
                                            font=("Segoe UI",9),anchor="w",padx=8); lb.pack(side="left",fill="x",expand=True)
                                tk.Label(rw,text=sky.get("game",""),bg=DARK_BG,fg=TEXT_SEC,
                                         font=("Segoe UI",7),padx=6).pack(side="right")
                                def pck(s=sky):
                                    if s.get("is_sf_combo"):
                                        new_binds[d]={"name":s["name"],"path":s["path"],
                                                      "bot_path":s.get("bot_path",""),
                                                      "is_sf_combo":True,"slot":1,"element":""}
                                    else:
                                        new_binds[d]={"name":s["name"],"path":s["path"],"slot":1,"element":s.get("element","")}
                                    nll.config(text=s["name"],fg=TEXT_PRI); pick.destroy(); refresh_new()
                                for ww in (rw,lb):
                                    ww.bind("<Button-1>",lambda e,f=pck:f())
                                    ww.bind("<Enter>",lambda e,r=rw,l=lb:(r.config(bg=CARD_HOVER),l.config(bg=CARD_HOVER)))
                                    ww.bind("<Leave>",lambda e,r=rw,l=lb:(r.config(bg=DARK_BG),l.config(bg=DARK_BG)))
                                    ww.bind("<MouseWheel>",lambda e:_whl3(e))
                                _wd3[idx]=rw
                        def _rfr3():
                            items=_it3[0]; h=lc3.winfo_height(); w=lc3.winfo_width()
                            lc3.configure(scrollregion=(0,0,w,max(len(items)*ROW_H3,h)))
                            _rnd3(items,_vt3[0],h,w)
                        def _whl3(e):
                            delta=int(-1*(e.delta/120))*ROW_H3
                            maxt=max(0,len(_it3[0])*ROW_H3-lc3.winfo_height())
                            _vt3[0]=max(0,min(maxt,_vt3[0]+delta))
                            lc3.yview_moveto(_vt3[0]/max(1,len(_it3[0])*ROW_H3)); _rfr3()
                        lc3.bind("<MouseWheel>",lambda e:_whl3(e))
                        lc3.bind("<Configure>",lambda e:_rfr3())
                        def bld3(q=""):
                            for idx,w in list(_wd3.items()): w.destroy(); del _wd3[idx]
                            _vt3[0]=0; cur_favs=set(self.cfg.get("favorites",[]))
                            sf_combos3=self.cfg.get("sf_combos",[])
                            if combo_only3[0]:
                                _it3[0]=[dict(name=c["nickname"],path=c["top_path"],
                                              bot_path=c.get("bot_path",""),is_sf_combo=True,
                                              game="Swap Force",element="")
                                         for c in sf_combos3
                                         if not q or q.lower() in c["nickname"].lower()]
                            else:
                                _it3[0]=[s for s in all_sky2
                                          if (not q or q.lower() in s["name"].lower())
                                          and (not fav_only3[0] or s["path"] in cur_favs)]
                            lc3.yview_moveto(0); pick.after(10,_rfr3)
                        bld3(); sv2.trace_add("write",lambda *a:bld3(sv2.get()))
                    tk.Button(row,text="Pick",bg=ACCENT,fg="#fff",relief="flat",cursor="hand2",
                              font=("Segoe UI",8,"bold"),padx=8,pady=3,activebackground=CARD_HOVER,
                              command=open_np).pack(side="right")
                    if entry:
                        def clr_dir(d=direction,nll=nl):
                            new_binds.pop(d,None); nll.config(text="— not set —",fg=TEXT_SEC); refresh_new()
                        tk.Button(row,text="✕",bg=CARD_BG,fg="#e74c3c",relief="flat",cursor="hand2",
                                  font=("Segoe UI",9),padx=6,command=clr_dir).pack(side="right",padx=(0,4))
            refresh_new()
            tk.Frame(dlg,bg=BORDER,height=1).pack(fill="x",padx=20,pady=(8,0))
            btn_r=tk.Frame(dlg,bg=DARK_BG); btn_r.pack(fill="x",padx=20,pady=10)
            def save_new():
                name=pname_var.get().strip()
                if not name: return
                save_ctrl_preset(name,new_binds,self.cfg.get("ctrl_trigger_code","BTN_THUMBR"),
                                 category=cat_var.get())
                if hasattr(self,"_reload_ctrl_presets"):
                    _ctrl_wheel_presets[0]=self._reload_ctrl_presets()
                refresh_presets()
                self._status_var.set(f"✔ Preset '{name}' saved!")
                dlg.destroy()
            tk.Button(btn_r,text="💾 Save Preset",bg=ACCENT,fg="#fff",relief="flat",cursor="hand2",
                      font=("Segoe UI",10,"bold"),padx=20,pady=8,activebackground=CARD_HOVER,
                      command=save_new).pack(side="left")
            tk.Button(btn_r,text="Cancel",bg=CARD_BG,fg=TEXT_SEC,relief="flat",cursor="hand2",
                      font=("Segoe UI",9),padx=12,pady=8,activebackground=CARD_HOVER,
                      command=dlg.destroy).pack(side="left",padx=(8,0))

        tk.Button(phdr,text="＋ New Preset",bg=ACCENT,fg="#fff",relief="flat",cursor="hand2",
                  font=("Segoe UI",9,"bold"),padx=10,pady=4,activebackground=CARD_HOVER,
                  command=new_preset_dialog).pack(side="right")

        plist_frame=tk.Frame(inner,bg=DARK_BG); plist_frame.pack(fill="x")
        plist_frame.bind("<MouseWheel>",_wheel)
        refresh_presets()


    def _show_preset_editor(self, preset, on_save_callback=None):
        """Edit an existing controller preset — change bindings without remaking it."""
        all_sky = [dict(sky,game=game)
                   for game,skys in self.all_skylanders.items() for sky in skys]
        all_sky.sort(key=lambda x: x["name"])

        win = tk.Toplevel(self); win.title(f"Edit Preset — {preset['name']}")
        self._set_win_icon(win)
        win.geometry("520x580"); win.configure(bg=DARK_BG)
        win.resizable(False,False); win.transient(self)

        tk.Label(win, text=f"✎  {preset['name']}", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold"), pady=12).pack()

        # Rename field
        rename_row = tk.Frame(win,bg=DARK_BG); rename_row.pack(fill="x",padx=20,pady=(0,8))
        tk.Label(rename_row,text="Name:",bg=DARK_BG,fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left",padx=(0,8))
        name_var = tk.StringVar(value=preset["name"])
        tk.Entry(rename_row,textvariable=name_var,bg=CARD_BG,fg=TEXT_PRI,
                 insertbackground=TEXT_PRI,relief="flat",font=("Segoe UI",9),
                 highlightthickness=1,highlightbackground=BORDER).pack(
                 side="left",fill="x",expand=True,ipady=4)

        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=20,pady=(0,8))

        # Editable bindings — one row per direction
        scroll_f = tk.Frame(win,bg=DARK_BG); scroll_f.pack(fill="both",expand=True,padx=20)
        cv = tk.Canvas(scroll_f,bg=DARK_BG,highlightthickness=0)
        sb = ttk.Scrollbar(scroll_f,orient="vertical",command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        inner = tk.Frame(cv,bg=DARK_BG)
        cwin = cv.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",lambda e:cv.itemconfig(cwin,width=e.width))
        cv.bind("<MouseWheel>",lambda e:cv.yview_scroll(int(-1*(e.delta/120)),"units"))
        inner.bind("<MouseWheel>",lambda e:cv.yview_scroll(int(-1*(e.delta/120)),"units"))

        binds = dict(preset.get("ctrl_binds",{}))  # work on a copy
        directions = [("up","▲ Up"),("down","▼ Down"),("left","◀ Left"),("right","▶ Right")]

        def refresh_binds():
            for w in inner.winfo_children(): w.destroy()
            for direction,label in directions:
                entry = binds.get(direction,{})
                row = tk.Frame(inner,bg=CARD_BG,pady=8,padx=12)
                row.pack(fill="x",pady=3)
                tk.Label(row,text=label,bg=CARD_BG,fg=TEXT_SEC,
                         font=("Segoe UI",9,"bold"),width=12,anchor="w").pack(side="left")
                name_lbl = tk.Label(row,text=entry.get("name","— not set —"),
                                    bg=CARD_BG,fg=TEXT_PRI if entry else TEXT_SEC,
                                    font=("Segoe UI",9),anchor="w")
                name_lbl.pack(side="left",fill="x",expand=True)

                def open_pick(d=direction,nl=name_lbl):
                    pick=tk.Toplevel(win); pick.title("Pick Skylander")
                    self._set_win_icon(pick)
                    pick.geometry("360x440"); pick.configure(bg=DARK_BG); pick.transient(win)
                    sv=tk.StringVar()
                    sf=tk.Frame(pick,bg=DARK_BG); sf.pack(fill="x",padx=10,pady=8)
                    tk.Label(sf,text="🔍",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",10)).pack(side="left",padx=(0,4))
                    tk.Entry(sf,textvariable=sv,bg=CARD_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                             relief="flat",font=("Segoe UI",10)).pack(side="left",fill="x",expand=True,ipady=4)
                    tk.Frame(pick,bg=BORDER,height=1).pack(fill="x")
                    lf2=tk.Frame(pick,bg=DARK_BG); lf2.pack(fill="both",expand=True)
                    lcv=tk.Canvas(lf2,bg=DARK_BG,highlightthickness=0)
                    lsb=ttk.Scrollbar(lf2,orient="vertical",command=lcv.yview)
                    lcv.configure(yscrollcommand=lsb.set)
                    lsb.pack(side="right",fill="y"); lcv.pack(side="left",fill="both",expand=True)
                    li=tk.Frame(lcv,bg=DARK_BG); lw=lcv.create_window((0,0),window=li,anchor="nw")
                    li.bind("<Configure>",lambda e:lcv.configure(scrollregion=lcv.bbox("all")))
                    lcv.bind("<Configure>",lambda e:lcv.itemconfig(lw,width=e.width))
                    lcv.bind("<MouseWheel>",lambda e:lcv.yview_scroll(int(-1*(e.delta/120)),"units"))
                    # Virtual scroll — only renders visible rows
                    ROW_H = 34
                    _items2  = [None]
                    _vtop2   = [0]
                    _wids2   = {}

                    def _render2(items,vt,ch,cw):
                        first=max(0,vt//ROW_H); last=min(len(items)-1,(vt+ch)//ROW_H)
                        for idx in list(_wids2.keys()):
                            if idx<first or idx>last: _wids2[idx].destroy(); del _wids2[idx]
                        for idx in range(first,last+1):
                            if idx in _wids2: continue
                            sky=items[idx]; y=idx*ROW_H-vt
                            row=tk.Frame(lcv,bg=DARK_BG,cursor="hand2",height=ROW_H-1)
                            lcv.create_window(2,y,window=row,anchor="nw",width=cw-4,height=ROW_H-1)
                            lbl=tk.Label(row,text=sky["name"],bg=DARK_BG,fg=TEXT_PRI,
                                         font=("Segoe UI",9),anchor="w",padx=8)
                            lbl.pack(side="left",fill="x",expand=True)
                            tk.Label(row,text=sky.get("game",""),bg=DARK_BG,fg=TEXT_SEC,
                                     font=("Segoe UI",7),padx=6).pack(side="right")
                            def pick_it(s=sky):
                                if s.get("is_sf_combo"):
                                    binds[d]={"name":s["name"],"path":s["path"],
                                              "bot_path":s.get("bot_path",""),
                                              "is_sf_combo":True,"slot":1,"element":""}
                                else:
                                    binds[d]={"name":s["name"],"path":s["path"],
                                              "slot":1,"element":s.get("element","")}
                                nl.config(text=s["name"],fg=TEXT_PRI)
                                pick.destroy(); refresh_binds()
                            for w in (row,lbl):
                                w.bind("<Button-1>",lambda e,f=pick_it:f())
                                w.bind("<Enter>",lambda e,r=row,l=lbl:(r.config(bg=CARD_HOVER),l.config(bg=CARD_HOVER)))
                                w.bind("<Leave>",lambda e,r=row,l=lbl:(r.config(bg=DARK_BG),l.config(bg=DARK_BG)))
                                w.bind("<MouseWheel>",lambda e:_wheel2(e))
                            _wids2[idx]=row

                    def _refresh2():
                        items=_items2[0]; n=len(items)
                        h=lcv.winfo_height(); w=lcv.winfo_width()
                        lcv.configure(scrollregion=(0,0,w,max(n*ROW_H,h)))
                        _render2(items,_vtop2[0],h,w)

                    def _wheel2(e):
                        items=_items2[0]
                        delta=int(-1*(e.delta/120))*ROW_H
                        maxt=max(0,len(items)*ROW_H-lcv.winfo_height())
                        _vtop2[0]=max(0,min(maxt,_vtop2[0]+delta))
                        lcv.yview_moveto(_vtop2[0]/max(1,len(items)*ROW_H))
                        _refresh2()

                    lcv.bind("<MouseWheel>",lambda e:_wheel2(e))
                    lcv.bind("<Configure>",lambda e:_refresh2())

                    # Filter row — favorites + clear
                    filt_row=tk.Frame(pick,bg=DARK_BG); filt_row.pack(fill="x",padx=10,pady=(4,0))
                    fav_only2=[False]; combo_only2=[False]
                    fav_btn2=tk.Label(filt_row,text="☆ Favorites",bg=DARK_BG,fg=TEXT_SEC,
                                      font=("Segoe UI",9),padx=8,pady=4,cursor="hand2")
                    fav_btn2.pack(side="left")
                    combo_btn2=tk.Label(filt_row,text="⬡ Combos",bg=DARK_BG,fg=TEXT_SEC,
                                       font=("Segoe UI",9),padx=8,pady=4,cursor="hand2")
                    combo_btn2.pack(side="left")
                    clrl=tk.Label(filt_row,text="✕  Clear",bg=DARK_BG,fg="#e74c3c",
                                  font=("Segoe UI",9),padx=8,pady=4,cursor="hand2",anchor="w")
                    clrl.pack(side="right")
                    def do_clr():
                        binds.pop(d,None); nl.config(text="— not set —",fg=TEXT_SEC)
                        pick.destroy(); refresh_binds()
                    clrl.bind("<Button-1>",lambda e:do_clr())
                    def toggle_fav2():
                        fav_only2[0]=not fav_only2[0]; combo_only2[0]=False
                        fav_btn2.config(text="★ Favorites" if fav_only2[0] else "☆ Favorites",
                                        fg="#f5a623" if fav_only2[0] else TEXT_SEC,
                                        bg=CARD_BG if fav_only2[0] else DARK_BG)
                        combo_btn2.config(fg=TEXT_SEC,bg=DARK_BG)
                        build2(sv.get())
                    fav_btn2.bind("<Button-1>",lambda e:toggle_fav2())
                    def toggle_combo2():
                        combo_only2[0]=not combo_only2[0]; fav_only2[0]=False
                        combo_btn2.config(fg="#4488ff" if combo_only2[0] else TEXT_SEC,
                                          bg=CARD_BG if combo_only2[0] else DARK_BG)
                        fav_btn2.config(text="☆ Favorites",fg=TEXT_SEC,bg=DARK_BG)
                        build2(sv.get())
                    combo_btn2.bind("<Button-1>",lambda e:toggle_combo2())
                    tk.Frame(pick,bg=BORDER,height=1).pack(fill="x")

                    def build2(q=""):
                        for idx,w in list(_wids2.items()): w.destroy(); del _wids2[idx]
                        _vtop2[0]=0
                        cur_favs=set(self.cfg.get("favorites",[]))
                        if combo_only2[0]:
                            sf_c2=self.cfg.get("sf_combos",[])
                            filtered=[dict(name=c["nickname"],path=c["top_path"],
                                          bot_path=c.get("bot_path",""),is_sf_combo=True,
                                          game="Swap Force",element="")
                                      for c in sf_c2 if not q or q.lower() in c["nickname"].lower()]
                        else:
                            filtered=[s for s in all_sky
                                      if (not q or q.lower() in s["name"].lower())
                                      and (not fav_only2[0] or s["path"] in cur_favs)]
                        _items2[0]=filtered
                        lcv.yview_moveto(0)
                        pick.after(10,_refresh2)
                    build=build2
                    build2(); sv.trace_add("write",lambda *a:build2(sv.get()))

                tk.Button(row,text="Change",bg=ACCENT,fg="#fff",relief="flat",
                          cursor="hand2",font=("Segoe UI",8,"bold"),padx=8,pady=3,
                          activebackground=CARD_HOVER,
                          command=open_pick).pack(side="right")
                if entry:
                    def clr_dir(d=direction,nl=name_lbl):
                        binds.pop(d,None); nl.config(text="— not set —",fg=TEXT_SEC); refresh_binds()
                    tk.Button(row,text="✕",bg=CARD_BG,fg="#e74c3c",relief="flat",
                              cursor="hand2",font=("Segoe UI",9),padx=6,
                              command=clr_dir).pack(side="right",padx=(0,4))

        refresh_binds()

        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=20,pady=(8,0))

        def save_edit():
            new_name = name_var.get().strip()
            if not new_name: return
            if new_name != preset["name"]:
                delete_ctrl_preset(preset["name"])
            save_ctrl_preset(new_name, binds,
                             preset.get("trigger_code","BTN_THUMBR"),
                             category=preset.get("category","Other"))
            # Immediately reload wheel presets so changes apply without toggling category
            if hasattr(self,"_reload_ctrl_presets"):
                _ctrl_wheel_presets[0] = self._reload_ctrl_presets()
            if on_save_callback: on_save_callback()
            self._status_var.set(f"✔ Preset '{new_name}' saved!")
            win.destroy()

        btn_row = tk.Frame(win,bg=DARK_BG); btn_row.pack(fill="x",padx=20,pady=12)
        tk.Button(btn_row,text="✔  Save Changes",bg=ACCENT,fg="#fff",relief="flat",
                  cursor="hand2",font=("Segoe UI",10,"bold"),padx=20,pady=8,
                  activebackground=CARD_HOVER,command=save_edit).pack(side="left")
        tk.Button(btn_row,text="Cancel",bg=CARD_BG,fg=TEXT_SEC,relief="flat",
                  cursor="hand2",font=("Segoe UI",9),padx=12,pady=8,
                  activebackground=CARD_HOVER,command=win.destroy).pack(side="left",padx=(8,0))

    def _show_controller_test(self):
        win=tk.Toplevel(self); win.title("Controller Test — Raw Events"); self._set_win_icon(win)
        win.geometry("560x500"); win.configure(bg=DARK_BG); win.resizable(True,True); win.transient(self)
        tk.Label(win,text="🎮  Controller Event Viewer",bg=DARK_BG,fg=TEXT_PRI,
                 font=("Segoe UI",12,"bold"),pady=10).pack()
        tk.Label(win,text="Press any button or D-pad on your controller.",
                 bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",8)).pack()
        try:
            pads=_inputs.devices.gamepads
            pad_name=pads[0].name if pads else "No controller detected"
        except: pad_name="Could not read controller list"
        tk.Label(win,text=f"Controller: {pad_name}",bg=DARK_BG,fg=ACCENT,font=("Segoe UI",8,"bold"),pady=4).pack()
        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=16,pady=(4,0))
        btn_row=tk.Frame(win,bg=DARK_BG); btn_row.pack(fill="x",padx=16,pady=6)
        clear_btn=tk.Button(btn_row,text="Clear",bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",
                            font=("Segoe UI",8),padx=10,pady=4,activebackground=CARD_HOVER)
        clear_btn.pack(side="left")
        tk.Label(btn_row,text="Yellow=RS click  Green=D-pad  Shared mode — won't affect Cemu",
                 bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",7)).pack(side="left",padx=10)
        log_frame=tk.Frame(win,bg=DARK_BG); log_frame.pack(fill="both",expand=True,padx=16,pady=(0,8))
        log_sb=ttk.Scrollbar(log_frame,orient="vertical")
        log_sb.pack(side="right",fill="y")
        log_txt=tk.Text(log_frame,bg="#0a0c12",fg=TEXT_PRI,font=("Consolas",9),relief="flat",
                        wrap="none",yscrollcommand=log_sb.set,state="disabled",height=18)
        log_txt.pack(side="left",fill="both",expand=True)
        log_sb.config(command=log_txt.yview)
        log_txt.tag_config("rs",foreground="#f1c40f",font=("Consolas",9,"bold"))
        log_txt.tag_config("dpad",foreground="#2ecc71",font=("Consolas",9,"bold"))
        log_txt.tag_config("dim",foreground="#3a4255")
        def append(text,tag=""):
            log_txt.config(state="normal")
            if log_txt.index("end-1c")!="1.0": log_txt.insert("end","\n")
            log_txt.insert("end",text,tag); log_txt.see("end"); log_txt.config(state="disabled")
        def do_clear():
            log_txt.config(state="normal"); log_txt.delete("1.0","end"); log_txt.config(state="disabled")
        clear_btn.config(command=do_clear)
        append("Waiting for controller input…","dim")
        running=[True]
        win.protocol("WM_DELETE_WINDOW",lambda:(running.__setitem__(0,False),win.destroy()))
        def poll():
            import time as _t
            while running[0]:
                try:
                    pads=_inputs.devices.gamepads
                    if not pads: _t.sleep(2); continue
                    events=_inputs.get_gamepad()
                    for ev in events:
                        if not running[0]: return
                        if ev.code=="SYN_REPORT": continue
                        code=ev.code; val=ev.state; etype=ev.ev_type
                        tag=""
                        if code in("BTN_THUMBR",): tag="rs"
                        elif code in{"ABS_HAT0Y","ABS_HAT0X","BTN_DPAD_UP","BTN_DPAD_DOWN","BTN_DPAD_LEFT","BTN_DPAD_RIGHT"}: tag="dpad"
                        import time as t2
                        line=f"[{t2.strftime('%H:%M:%S')}]  {etype:<10} {code:<22} val={val}"
                        win.after(0,lambda l=line,tg=tag:append(l,tg))
                except Exception: _t.sleep(0.5)
        import threading as _thr
        _thr.Thread(target=poll,daemon=True).start()
        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=16,pady=(0,4))
        tk.Label(win,text="💡 Use Settings → Controller → D-pad Mapping to override button codes.",
                 bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",7),wraplength=520,justify="left",padx=16).pack(anchor="w",pady=(0,8))

    def _register_all_keybinds(self):
        """Register keybinds globally via the keyboard library (works even when Cemu is focused)."""
        # Remove ALL old hooks and bindings first
        if KEYBOARD_OK:
            try: _keyboard.unhook_all()
            except Exception: pass
        if hasattr(self, "_registered_keys"):
            for key in self._registered_keys:
                # unbind both raw (<F1>) and stripped (f1) forms
                for fmt in [key, f"<{key}>", f"<{key.upper()}>",
                            f"<{key.lower()}>"]:
                    try: self.unbind_all(fmt)
                    except Exception: pass
        self._registered_keys = []

        # Skip registering if global keybinds are disabled
        if not self.cfg.get("global_keybinds_enabled", True):
            _dbg("Global keybinds disabled — skipping registration")
            return

        for kb in self.cfg.get("keybinds", []):
            raw_key = kb.get("key","")   # stored as <F1>, <a>, etc.
            path    = kb.get("path","")
            slot    = kb.get("slot", 1)
            name    = kb.get("name","")
            if not raw_key or not path: continue

            # Convert tkinter key format <F1> → keyboard format f1
            kb_key = raw_key.strip("<>").lower()

            def make_handler(p=path, s=slot, n=name):
                def handler(event=None):
                    if not _active_window_is_allowed(): return
                    if self._manual_mode: return
                    host = self.cfg.get("vp_host","localhost")
                    port = self.cfg.get("vp_port",5678)
                    name_lower = n.lower()
                    path_lower = p.lower().replace("\\","/")
                    is_sf_bot = "(bottom)" in name_lower or "(bottom)" in path_lower
                    target_slot = get_portal_slot(n, p, game="", is_sf_bottom=is_sf_bot)
                    was_combo = getattr(self, "_sf_combo_active", False)
                    self._sf_combo_active = False
                    clear_slots = should_clear_slots(target_slot, was_combo)
                    self.after(0, lambda: self._status_var.set(f"⌨ {n} loading…"))
                    def run():
                        import concurrent.futures as _cf
                        if clear_slots:
                            with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                                _cf.wait([ex.submit(virtport_clear,cl,host,port)
                                          for cl in clear_slots])
                        ok,err = virtport_load(p, slot=target_slot, host=host, port=port)
                        self.after(0, lambda: self._status_var.set(
                            f"✔ {n} loaded!" if ok else f"⚠ Keybind failed: {err}"))
                    threading.Thread(target=run, daemon=True).start()
                return handler

            if KEYBOARD_OK:
                # Use global keyboard hook — works with or without admin on Windows
                try:
                    key_str = kb_key.strip("<>")
                    def make_suppressed(handler_fn=make_handler(), k=key_str, n=name):
                        def suppressed(event):
                            if event.event_type != _keyboard.KEY_DOWN:
                                return
                            allowed = _active_window_is_allowed()
                            _dbg(f"Key pressed: {k} → {n} | {'FIRED' if allowed else 'BLOCKED'}")
                            if allowed:
                                handler_fn()
                        return suppressed
                    _keyboard.hook_key(key_str, make_suppressed(), suppress=False)
                    self._registered_keys.append(key_str)
                    _dbg(f"Global keybind registered: {key_str} → {name}")
                except Exception as e:
                    _dbg(f"Failed global keybind {kb_key}: {e}")
                    # Fallback to local tkinter binding
                    try:
                        self.bind_all(raw_key, make_handler())
                        self._registered_keys.append(raw_key)
                    except Exception: pass
            else:
                # No keyboard lib — use local tkinter binding (app focus only)
                try:
                    self.bind_all(raw_key, make_handler())
                    self._registered_keys.append(raw_key)
                    _dbg(f"Local keybind (no keyboard lib): {raw_key} → {name}")
                except Exception as e:
                    _dbg(f"Failed keybind {raw_key}: {e}")

    def _show_keybind_manager(self):
        """Full keybind management window inside settings."""
        all_sky = [dict(sky, game=game)
                   for game, skys in self.all_skylanders.items()
                   for sky in skys]
        all_sky.sort(key=lambda x: x["name"])

        win = tk.Toplevel(self)
        win.title("Keybind Manager")
        win.geometry("620x680")
        win.configure(bg=DARK_BG)
        win.transient(self)

        # ── Header ──
        hdr = tk.Frame(win, bg=DARK_BG, pady=10)
        hdr.pack(fill="x", padx=16)
        tk.Label(hdr, text="⌨  Keybind Manager",
                 bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Button(hdr, text="＋  Add Keybind",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=10, pady=4,
                  activebackground="#2980b9",
                  command=lambda: add_keybind_dialog(win, all_sky)
                  ).pack(side="right")

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16)

        # ── Keybind list ──
        list_frame = tk.Frame(win, bg=DARK_BG)
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)

        def refresh_list():
            for w in list_frame.winfo_children(): w.destroy()
            kbs = self.cfg.get("keybinds", [])
            if not kbs:
                tk.Label(list_frame,
                         text="No keybinds yet.\nClick  ＋ Add Keybind  to create one.",
                         bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",10), justify="center").pack(expand=True, pady=40)
                return
            # Column headers
            hrow = tk.Frame(list_frame, bg=DARK_BG)
            hrow.pack(fill="x", pady=(0,4))
            for txt, w in [("Key",100),("Skylander",220),("Slot",40),("",80)]:
                tk.Label(hrow, text=txt, bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8,"bold"), width=w//8, anchor="w").pack(side="left")
            tk.Frame(list_frame, bg=BORDER, height=1).pack(fill="x", pady=(0,4))

            for i, kb in enumerate(kbs):
                row = tk.Frame(list_frame, bg=CARD_BG, pady=6, padx=8)
                row.pack(fill="x", pady=2)
                # Key badge
                key_lbl = tk.Label(row, text=kb.get("key","?"),
                                   bg=ACCENT, fg="#fff",
                                   font=("Segoe UI",9,"bold"),
                                   padx=6, pady=2)
                key_lbl.pack(side="left", padx=(0,10))
                # Name
                tk.Label(row, text=kb.get("name","Unknown"),
                         bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10), anchor="w").pack(side="left", fill="x", expand=True)
                # Slot
                tk.Label(row, text=f"Slot {kb.get('slot',1)}",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=8)
                # Delete button
                def make_delete(idx=i):
                    def delete():
                        self.cfg["keybinds"].pop(idx)
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        refresh_list()
                    return delete

                # Edit button — opens add dialog pre-filled, deletes old only on save
                def make_edit(idx=i, kb_data=kb):
                    def edit():
                        def on_save_callback():
                            # Remove the old keybind after new one is saved
                            # Find and remove by matching original key
                            for j, kb2 in enumerate(self.cfg.get("keybinds",[])):
                                if kb2.get("key") == kb_data.get("key") and j != len(self.cfg["keybinds"])-1:
                                    self.cfg["keybinds"].pop(j)
                                    save_config(self.cfg)
                                    self._register_all_keybinds()
                                    break
                            refresh_list()
                        add_keybind_dialog(win, all_sky, prefill=kb_data, on_save=on_save_callback)
                    return edit

                tk.Button(row, text="🖊",
                          bg=CARD_BG, fg=ACCENT, relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_edit()).pack(side="right")
                tk.Button(row, text="🗑",
                          bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_delete()).pack(side="right")

        def add_keybind_dialog(parent, sky_list, prefill=None, on_save=None):
            dlg = tk.Toplevel(parent)
            dlg.title("Add Keybind")
            dlg.geometry("480x500")
            dlg.configure(bg=DARK_BG)
            dlg.resizable(False, False)
            dlg.grab_set()  # modal

            captured_key = [None]
            selected_sky = [None]

            # ── Title ──
            tk.Label(dlg, text="Add New Keybind",
                     bg=DARK_BG, fg=TEXT_PRI,
                     font=("Segoe UI",12,"bold")).pack(pady=(16,4))
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,10))

            body = tk.Frame(dlg, bg=DARK_BG)
            body.pack(fill="x", padx=16)

            # ── Key capture ──
            key_var = tk.StringVar(value="Click here then press a key")
            key_row = tk.Frame(body, bg=DARK_BG)
            key_row.pack(fill="x", pady=4)
            tk.Label(key_row, text="Key:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            key_btn = tk.Button(key_row, textvariable=key_var,
                                bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                                font=("Segoe UI",10,"bold"), padx=10, pady=6,
                                activebackground=CARD_HOVER)
            key_btn.pack(side="left", fill="x", expand=True)

            def capture_key():
                # Move focus away from search entry to prevent typing into it
                key_btn.focus_set()
                key_var.set("Press any key now…")
                key_btn.config(bg=ACCENT, fg="#fff")
                def on_key(e):
                    sym = e.keysym
                    if sym in ("Shift_L","Shift_R","Control_L","Control_R",
                               "Alt_L","Alt_R","Super_L","Super_R","Tab",
                               "Return","Escape","BackSpace"): return
                    captured_key[0] = f"<{sym}>"
                    key_var.set(f"<{sym}>")
                    key_btn.config(bg=CARD_BG, fg=TEXT_PRI)
                    dlg.unbind("<Key>")
                dlg.bind("<Key>", on_key)
            key_btn.config(command=capture_key)

            # Clicking anywhere outside search entry removes its focus
            def defocus(e):
                if e.widget is not search_entry:
                    key_btn.focus_set()
            dlg.bind("<Button-1>", defocus)

            # ── Slot ──
            slot_row = tk.Frame(body, bg=DARK_BG)
            slot_row.pack(fill="x", pady=4)
            tk.Label(slot_row, text="Slot:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            slot_var = tk.IntVar(value=1)
            for s in range(1, 9):
                tk.Radiobutton(slot_row, text=str(s), variable=slot_var, value=s,
                               bg=DARK_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                               activebackground=DARK_BG,
                               font=("Segoe UI",9)).pack(side="left", padx=2)

            # ── Skylander search ──
            tk.Label(body, text="Skylander:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), anchor="w").pack(fill="x", pady=(8,2))
            search_var = tk.StringVar()
            search_entry = tk.Entry(body, textvariable=search_var,
                     bg=CARD_BG, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI,
                     relief="flat", font=("Segoe UI",10))
            search_entry.pack(fill="x", ipady=5, ipadx=6)

            # ── Results list (fixed height) ──
            list_outer = tk.Frame(dlg, bg=CARD_BG, height=180)
            list_outer.pack(fill="x", padx=16, pady=(4,0))
            list_outer.pack_propagate(False)

            lb_canvas = tk.Canvas(list_outer, bg=CARD_BG, highlightthickness=0)
            lb_sb = ttk.Scrollbar(list_outer, orient="vertical", command=lb_canvas.yview)
            lb_canvas.configure(yscrollcommand=lb_sb.set)
            lb_sb.pack(side="right", fill="y")
            lb_canvas.pack(side="left", fill="both", expand=True)
            lb_inner = tk.Frame(lb_canvas, bg=CARD_BG)
            lb_win = lb_canvas.create_window((0,0), window=lb_inner, anchor="nw")
            lb_inner.bind("<Configure>", lambda e: lb_canvas.configure(
                scrollregion=lb_canvas.bbox("all")))
            lb_canvas.bind("<Configure>", lambda e: lb_canvas.itemconfig(lb_win, width=e.width))
            lb_canvas.bind("<MouseWheel>", lambda e: lb_canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

            def populate(q=""):
                for w in lb_inner.winfo_children(): w.destroy()
                filtered = [s for s in sky_list
                            if not q or q.lower() in s["name"].lower()][:80]
                for sky in filtered:
                    def make_sel(s=sky):
                        def sel():
                            selected_sky[0] = s
                            search_var.set(s["name"])
                            for w2 in lb_inner.winfo_children():
                                try: w2.configure(bg=CARD_BG)
                                except Exception: pass
                                for c in w2.winfo_children():
                                    try: c.configure(bg=CARD_BG)
                                    except Exception: pass
                            ir.configure(bg=ACCENT)
                            il.configure(bg=ACCENT, fg="#fff")
                        return sel
                    ir = tk.Frame(lb_inner, bg=CARD_BG, cursor="hand2")
                    ir.pack(fill="x")
                    il = tk.Label(ir, text=sky["name"], bg=CARD_BG, fg=TEXT_PRI,
                                  font=("Segoe UI",9), anchor="w", padx=8, pady=5)
                    il.pack(fill="x")
                    clk = make_sel(sky)
                    ir.bind("<Button-1>", lambda e, f=clk: f())
                    il.bind("<Button-1>", lambda e, f=clk: f())
                    ir.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    ir.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)
                    il.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    il.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)

            populate()
            search_var.trace_add("write", lambda *_: populate(search_var.get()))

            # Apply prefill AFTER widgets exist
            if prefill:
                captured_key[0] = prefill.get("key","")
                key_var.set(prefill.get("key",""))
                slot_var.set(prefill.get("slot",1))
                search_var.set(prefill.get("name",""))
                for s in sky_list:
                    if s["path"] == prefill.get("path",""):
                        selected_sky[0] = s
                        break

            # ── Status + Save (always at bottom) ──
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
            status_lbl = tk.Label(dlg, text="", bg=DARK_BG, fg="#e67e22",
                                  font=("Segoe UI",9))
            status_lbl.pack(pady=(4,0))

            def save_keybind():
                if not captured_key[0]:
                    status_lbl.config(text="⚠ Click the key button and press a key first"); return
                if not selected_sky[0]:
                    status_lbl.config(text="⚠ Select a Skylander from the list"); return
                existing = [kb["key"] for kb in self.cfg.get("keybinds",[])]
                if captured_key[0] in existing:
                    status_lbl.config(text=f"⚠ {captured_key[0]} already bound — delete it first"); return
                self.cfg.setdefault("keybinds",[]).append({
                    "key":  captured_key[0],
                    "name": selected_sky[0]["name"],
                    "path": selected_sky[0]["path"],
                    "slot": slot_var.get(),
                })
                save_config(self.cfg)
                self._register_all_keybinds()
                dlg.destroy()
                if on_save: on_save()
                else: refresh_list()

            tk.Button(dlg, text="✔  Save Keybind",
                      bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                      font=("Segoe UI",10,"bold"), pady=8,
                      activebackground="#2980b9",
                      command=save_keybind).pack(fill="x", padx=16, pady=8)
        refresh_list()
        # ── Preset bar at the bottom ──
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
        preset_bar = tk.Frame(win, bg=DARK_BG)
        preset_bar.pack(fill="x", padx=16, pady=8)

        tk.Label(preset_bar, text="Preset:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left", padx=(0,6))

        preset_name_var = tk.StringVar(value="My Preset")
        tk.Entry(preset_bar, textvariable=preset_name_var,
                 bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", font=("Segoe UI",9), width=14
                 ).pack(side="left", ipady=4, ipadx=4)

        def save_preset():
            name = preset_name_var.get().strip()
            if not name: return
            save_keybind_preset(name, self.cfg.get("keybinds",[]))
            refresh_preset_list()

        tk.Button(preset_bar, text="💾 Save",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=8, pady=4,
                  activebackground="#2980b9",
                  command=save_preset).pack(side="left", padx=(4,0))

        # Preset dropdown
        preset_select_var = tk.StringVar(value="")
        preset_menu_btn = tk.Button(preset_bar, text="Load Preset ▾",
                                    bg=CARD_BG, fg=TEXT_PRI, relief="flat",
                                    cursor="hand2", font=("Segoe UI",9),
                                    padx=8, pady=4, activebackground=CARD_HOVER)
        preset_menu_btn.pack(side="left", padx=(8,0))

        def refresh_preset_list():
            pass  # placeholder — menu built on click

        def open_preset_menu():
            presets = list_keybind_presets()
            if not presets:
                return
            pmenu = tk.Toplevel(win)
            pmenu.overrideredirect(True)
            pmenu.configure(bg=BORDER)
            x = preset_menu_btn.winfo_rootx()
            y = preset_menu_btn.winfo_rooty() + preset_menu_btn.winfo_height()
            pmenu.geometry(f"+{x}+{y}")
            inner = tk.Frame(pmenu, bg=CARD_BG)
            inner.pack(fill="both", expand=True, padx=1, pady=1)
            tk.Label(inner, text="PRESETS", bg=CARD_BG, fg=TEXT_SEC,
                     font=("Segoe UI",8,"bold"), padx=10, pady=6).pack(fill="x")
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
            for p in presets:
                prow = tk.Frame(inner, bg=CARD_BG, cursor="hand2")
                prow.pack(fill="x")
                tk.Frame(prow, bg=ACCENT, width=3).pack(side="left", fill="y")
                name_lbl = tk.Label(prow, text=f"  {p['name']}",
                                    bg=CARD_BG, fg=TEXT_PRI,
                                    font=("Segoe UI",10), anchor="w",
                                    padx=6, pady=7, cursor="hand2")
                name_lbl.pack(side="left", fill="x", expand=True)
                kb_count = len(p.get("keybinds",[]))
                tk.Label(prow, text=f"{kb_count} keys",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=4)

                def make_load(preset=p):
                    def do():
                        self.cfg["keybinds"] = preset["keybinds"]
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        pmenu.destroy()
                        win.destroy()
                        self._show_keybind_manager()
                        self._status_var.set(f"✔ Preset '{preset['name']}' loaded!")
                    return do

                def make_del(preset=p):
                    def do():
                        delete_keybind_preset(preset["name"])
                        pmenu.destroy()
                    return do

                tk.Button(prow, text="🗑", bg=CARD_BG, fg="#e74c3c",
                          relief="flat", cursor="hand2", font=("Segoe UI",9),
                          padx=4, activebackground=CARD_HOVER,
                          command=make_del()).pack(side="right", padx=(0,2))

                for w in (prow, name_lbl):
                    w.bind("<Enter>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    w.bind("<Leave>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)))
                    w.bind("<Button-1>", lambda e, f=make_load(): f())

            pmenu.bind("<FocusOut>", lambda e: pmenu.destroy() if pmenu.winfo_exists() else None)
            pmenu.focus_set()

        preset_menu_btn.config(command=open_preset_menu)

        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def _show_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        self._set_win_icon(win)
        win.geometry("580x600")
        win.configure(bg=DARK_BG)
        win.resizable(False, False)
        win.transient(self)

        # Tab bar
        tab_bar = tk.Frame(win, bg=DARK_BG)
        tab_bar.pack(fill="x")
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")

        # Single scrollable area — content swaps inside
        scroll_frame = tk.Frame(win, bg=DARK_BG)
        scroll_frame.pack(fill="both", expand=True)
        canvas = tk.Canvas(scroll_frame, bg=DARK_BG, highlightthickness=0)
        sb = ttk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=DARK_BG)
        cwin = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cwin, width=e.width))
        def _sw(e): canvas.yview_scroll(int(-1*(e.delta/120)),"units")
        canvas.bind("<MouseWheel>", _sw)
        inner.bind("<MouseWheel>", _sw)
        win.bind("<MouseWheel>", _sw)

        # All panels live in inner, only one shown at a time
        tab_names = ["Keybinds","Controller","Appearance","Themes"]
        panels = {n: tk.Frame(inner, bg=DARK_BG) for n in tab_names}
        tab_btns = {}

        def switch_tab(name):
            for p in panels.values(): p.pack_forget()
            panels[name].pack(fill="x", padx=20, pady=16)
            canvas.yview_moveto(0)
            # Rebind mousewheel to all children of active panel
            def _bind_all(w):
                try: w.bind("<MouseWheel>", _sw)
                except: pass
                for c in w.winfo_children(): _bind_all(c)
            _bind_all(panels[name])
            for n,b in tab_btns.items():
                b.config(bg=CARD_BG if n==name else DARK_BG,
                         fg=TEXT_PRI if n==name else TEXT_SEC,
                         font=("Segoe UI",9,"bold") if n==name else ("Segoe UI",9))

        for name in tab_names:
            b = tk.Button(tab_bar, text=name, bg=DARK_BG, fg=TEXT_SEC,
                          relief="flat", cursor="hand2",
                          font=("Segoe UI",9), padx=16, pady=10,
                          activebackground=CARD_BG, activeforeground=TEXT_PRI,
                          command=lambda n=name: switch_tab(n))
            b.pack(side="left")
            tab_btns[name] = b

        # ── CONTROLLER ──
        cp = panels["Controller"]
        tk.Label(cp, text="Controller Wheel", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(0,2))
        ctrl_status = "✔ inputs library ready" if INPUTS_OK else "⚠ Run:  pip install inputs"
        ctrl_color  = "#3dba6f" if INPUTS_OK else "#e67e22"
        tk.Label(cp, text=ctrl_status, bg=DARK_BG, fg=ctrl_color,
                 font=("Segoe UI",8)).pack(anchor="w", pady=(0,8))

        # Enable checkbox — this is the master switch
        ctrl_enabled_var = tk.BooleanVar(value=self.cfg.get("ctrl_wheel_enabled", False))
        def on_ctrl_toggle():
            global _ctrl_wheel_enabled
            v = ctrl_enabled_var.get()
            self.cfg["ctrl_wheel_enabled"] = v
            _ctrl_wheel_enabled[0] = v
            save_config(self.cfg)
        tk.Checkbutton(cp, text="Enable Controller Wheel",
                       variable=ctrl_enabled_var, command=on_ctrl_toggle,
                       bg=DARK_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                       activebackground=DARK_BG, font=("Segoe UI",10,"bold"),
                       cursor="hand2").pack(anchor="w", pady=(0,8))

        tk.Frame(cp, bg=BORDER, height=1).pack(fill="x", pady=(0,10))

        # Trigger button rebind
        tk.Label(cp, text="Wheel Trigger Button", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,2))
        tk.Label(cp, text="Press any controller button to use it as the wheel trigger.",
                 bg=DARK_BG, fg=TEXT_SEC, font=("Segoe UI",8)).pack(anchor="w", pady=(0,6))
        trig_row = tk.Frame(cp, bg=DARK_BG); trig_row.pack(fill="x", pady=(0,10))
        saved_trigger = self.cfg.get("ctrl_trigger_code", "BTN_THUMBR")
        trig_lbl = tk.Label(trig_row, text=f"Current: {saved_trigger}",
                            bg=CARD_BG, fg="#5b9bd5", font=("Consolas",9,"bold"),
                            padx=10, pady=6, anchor="w")
        trig_lbl.pack(side="left", fill="x", expand=True)
        listening = [False]
        def start_listen_trigger():
            if listening[0]: return
            listening[0] = True
            trig_btn.config(text="… press RS or any button", bg="#3d1a00", fg="#ff9944")
            def listen():
                import time as _t
                deadline = _t.time() + 10
                prev_buttons = 0
                while _t.time() < deadline and listening[0]:
                    try:
                        evts = _inputs.get_gamepad()
                        for ev in evts:
                            if ev.ev_type == "Key" and ev.state in (0,1) and ev.code != "SYN_REPORT":
                                code = ev.code
                                def apply(c=code):
                                    global _BTN_RS
                                    self.cfg["ctrl_trigger_code"] = c
                                    _BTN_RS = {c}
                                    save_config(self.cfg)
                                    trig_lbl.config(text=f"Current: {c}")
                                    trig_btn.config(text="🎮 Change Trigger", bg=CARD_BG, fg=TEXT_PRI)
                                    listening[0] = False
                                self.after(0, apply); return
                    except: _t.sleep(0.1)
                if listening[0]:
                    listening[0] = False
                    self.after(0, lambda: trig_btn.config(text="🎮 Change Trigger", bg=CARD_BG, fg=TEXT_PRI))
                    listening[0] = False
            import threading as _thr
            _thr.Thread(target=listen, daemon=True).start()
        trig_btn = tk.Button(trig_row, text="🎮 Change Trigger", bg=CARD_BG, fg=TEXT_PRI,
                             relief="flat", cursor="hand2", font=("Segoe UI",9),
                             padx=10, pady=6, activebackground=CARD_HOVER,
                             command=start_listen_trigger)
        trig_btn.pack(side="left", padx=(6,0))

        tk.Frame(cp, bg=BORDER, height=1).pack(fill="x", pady=(0,10))

        # Active category picker
        tk.Label(cp, text="Active Game Category", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,4))
        tk.Label(cp, text="Only presets in this category appear on the wheel.",
                 bg=DARK_BG, fg=TEXT_SEC, font=("Segoe UI",8)).pack(anchor="w", pady=(0,6))
        cat_var = tk.StringVar(value=get_ctrl_active_category(self.cfg))
        cat_row = tk.Frame(cp, bg=DARK_BG); cat_row.pack(fill="x", pady=(0,10))
        cat_om2 = tk.OptionMenu(cat_row, cat_var, *CTRL_WHEEL_GAMES)
        cat_om2.config(bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                       font=("Segoe UI",9), activebackground=CARD_HOVER,
                       activeforeground=TEXT_PRI, highlightthickness=0, bd=0)
        cat_om2["menu"].config(bg=CARD_BG, fg=TEXT_PRI, activebackground=ACCENT,
                                activeforeground="#fff", relief="flat",
                                font=("Segoe UI",9))
        cat_om2.pack(side="left", fill="x", expand=True, ipady=2)
        def apply_category(*_):
            set_ctrl_active_category(self.cfg, cat_var.get())
            save_config(self.cfg)
            if hasattr(self, "_reload_ctrl_presets"):
                _ctrl_wheel_presets[0] = self._reload_ctrl_presets()
            self._status_var.set(f"✔ Wheel category set to {cat_var.get()}")
        cat_var.trace_add("write", apply_category)

        tk.Frame(cp, bg=BORDER, height=1).pack(fill="x", pady=(0,10))

        # Wheel size slider
        tk.Label(cp, text="Wheel Size", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,4))
        size_row = tk.Frame(cp, bg=DARK_BG); size_row.pack(fill="x", pady=(0,2))
        tk.Label(size_row, text="Small", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8)).pack(side="left")
        size_val = self.cfg.get("ctrl_wheel_size", 300)
        size_var = tk.IntVar(value=size_val)
        size_lbl = tk.Label(size_row, text=f"{size_val}px", bg=DARK_BG,
                            fg=TEXT_PRI, font=("Segoe UI",8,"bold"), width=5)
        size_lbl.pack(side="right")
        tk.Label(size_row, text="Large", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8)).pack(side="right")
        def on_size(val):
            v = int(float(val))
            self.cfg["ctrl_wheel_size"] = v
            size_lbl.config(text=f"{v}px")
            save_config(self.cfg)
        tk.Scale(cp, from_=180, to=500, resolution=10, orient="horizontal",
                 variable=size_var, bg=DARK_BG, fg=TEXT_PRI, highlightthickness=0,
                 troughcolor=CARD_BG, activebackground=ACCENT, showvalue=False,
                 command=on_size).pack(fill="x", pady=(0,10))

        # Opacity slider
        tk.Label(cp, text="Wheel Opacity", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,4))
        op_row = tk.Frame(cp, bg=DARK_BG); op_row.pack(fill="x", pady=(0,2))
        tk.Label(op_row, text="Transparent", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8)).pack(side="left")
        op_val = self.cfg.get("ctrl_overlay_alpha", 0.92)
        op_var = tk.DoubleVar(value=op_val)
        op_lbl = tk.Label(op_row, text=f"{int(op_val*100)}%", bg=DARK_BG,
                          fg=TEXT_PRI, font=("Segoe UI",8,"bold"), width=5)
        op_lbl.pack(side="right")
        tk.Label(op_row, text="Opaque", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8)).pack(side="right")
        def on_alpha(val):
            v = round(float(val), 2)
            self.cfg["ctrl_overlay_alpha"] = v
            op_lbl.config(text=f"{int(v*100)}%")
            save_config(self.cfg)
        tk.Scale(cp, from_=0.1, to=1.0, resolution=0.01, orient="horizontal",
                 variable=op_var, bg=DARK_BG, fg=TEXT_PRI, highlightthickness=0,
                 troughcolor=CARD_BG, activebackground=ACCENT, showvalue=False,
                 command=on_alpha).pack(fill="x", pady=(0,10))

        tk.Frame(cp, bg=BORDER, height=1).pack(fill="x", pady=(0,10))

        # Pair Controller button
        pair_status = tk.StringVar(value="")
        def pair_controller():
            pair_status.set("🔄 Scanning for controller…")
            pair_btn.config(state="disabled")
            def scan():
                try:
                    if INPUTS_OK:
                        try: _inputs.devices.__init__()
                        except: pass
                        import time as _t; _t.sleep(0.5)
                        gamepads = _inputs.devices.gamepads
                        if gamepads:
                            name = getattr(gamepads[0], "name", "Controller")
                            self.after(0, lambda: pair_status.set(f"✔ Paired: {name}"))
                            _dbg(f"Controller paired: {name}")
                        else:
                            self.after(0, lambda: pair_status.set("⚠ No controller found — plug in and try again"))
                    else:
                        self.after(0, lambda: pair_status.set("⚠ inputs library not installed"))
                except Exception as e:
                    self.after(0, lambda: pair_status.set(f"⚠ Error: {e}"))
                self.after(0, lambda: pair_btn.config(state="normal"))
            threading.Thread(target=scan, daemon=True).start()

        pair_btn = tk.Button(cp, text="🎮  Pair Controller",
                             bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                             font=("Segoe UI",10,"bold"), padx=12, pady=8,
                             activebackground=CARD_HOVER, command=pair_controller)
        pair_btn.pack(fill="x", pady=(0,4))
        tk.Label(cp, textvariable=pair_status, bg=DARK_BG, fg="#3dba6f",
                 font=("Segoe UI",8)).pack(anchor="w", pady=(0,8))

        tk.Button(cp, text="🎮  Configure D-pad Bindings", bg=CARD_BG, fg=TEXT_PRI,
                  relief="flat", cursor="hand2", font=("Segoe UI",10),
                  padx=12, pady=8, activebackground=CARD_HOVER,
                  command=self._show_controller_settings).pack(fill="x", pady=(0,4))
        tk.Button(cp, text="🔍  Test Controller / View Raw Events", bg=CARD_BG, fg=TEXT_PRI,
                  relief="flat", cursor="hand2", font=("Segoe UI",10),
                  padx=12, pady=8, activebackground=CARD_HOVER,
                  command=self._show_controller_test).pack(fill="x")

        # ── KEYBINDS ──
        kp = panels["Keybinds"]
        # ── Global keybinds on/off toggle ────────────────────────────────
        gk_var = tk.BooleanVar(value=self.cfg.get("global_keybinds_enabled", True))
        gk_row = tk.Frame(kp, bg=DARK_BG); gk_row.pack(fill="x", pady=(8,2))
        def toggle_global_keys():
            self.cfg["global_keybinds_enabled"] = gk_var.get()
            save_config(self.cfg)
            self._register_all_keybinds()
            gk_status.config(
                text="⌨ Enabled — works even when Cemu is focused" if gk_var.get() else "⌨ Disabled — use controller wheel only",
                fg="#3dba6f" if gk_var.get() else TEXT_SEC)
        tk.Checkbutton(gk_row, variable=gk_var, bg=DARK_BG, activebackground=DARK_BG,
                       fg=TEXT_PRI, selectcolor=CARD_BG, relief="flat",
                       command=toggle_global_keys).pack(side="left")
        tk.Label(gk_row, text="Enable global keybinds", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",9,"bold")).pack(side="left", padx=(4,0))
        gk_status = tk.Label(kp,
            text="⌨ Enabled — works even when Cemu is focused" if gk_var.get() else "⌨ Disabled — use controller wheel only",
            bg=DARK_BG, fg="#3dba6f" if gk_var.get() else TEXT_SEC,
            font=("Segoe UI",8))
        gk_status.pack(anchor="w", pady=(0,4))
        if not KEYBOARD_OK:
            tk.Label(kp, text="⚠ pip install keyboard required",
                     bg=DARK_BG, fg="#e67e22", font=("Segoe UI",8)).pack(anchor="w")
        tk.Frame(kp, bg=BORDER, height=1).pack(fill="x", pady=(8,8))
        # ─────────────────────────────────────────────────────────────────
        tk.Label(kp, text="Keyboard Keybinds", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(0,4))
        tk.Label(kp, text="Press a key anywhere in the app to instantly load a Skylander.",
                 bg=DARK_BG, fg=TEXT_SEC, font=("Segoe UI",8)).pack(anchor="w")
        tk.Frame(kp, bg=BORDER, height=1).pack(fill="x", pady=(8,10))
        tk.Button(kp, text="⌨  Manage Keybinds", bg=CARD_BG, fg=TEXT_PRI,
                  relief="flat", cursor="hand2", font=("Segoe UI",10),
                  padx=12, pady=8, activebackground=CARD_HOVER,
                  command=self._show_keybind_manager).pack(fill="x")
        tk.Frame(kp, bg=BORDER, height=1).pack(fill="x", pady=(12,8))
        tk.Label(kp, text="Keybind Presets", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w", pady=(0,6))
        pname_var = tk.StringVar(value="My Preset")
        prow = tk.Frame(kp, bg=DARK_BG); prow.pack(fill="x", pady=(0,6))
        tk.Entry(prow, textvariable=pname_var, bg=CARD_BG, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat",
                 font=("Segoe UI",9), width=16).pack(side="left", ipady=4, ipadx=4)
        plist = tk.Frame(kp, bg=DARK_BG); plist.pack(fill="x")
        def refresh_presets():
            for w in plist.winfo_children(): w.destroy()
            for p in list_keybind_presets():
                pr = tk.Frame(plist, bg=CARD_BG, pady=4, padx=8); pr.pack(fill="x", pady=2)
                tk.Frame(pr, bg=ACCENT, width=3).pack(side="left", fill="y", padx=(0,6))
                tk.Label(pr, text=p["name"], bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",9,"bold")).pack(side="left", fill="x", expand=True)
                tk.Label(pr, text=f"{len(p.get('keybinds',[]))} keys",
                         bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",8)).pack(side="left", padx=6)
                def mk_load(preset=p):
                    def do():
                        self.cfg["keybinds"]=preset["keybinds"]
                        save_config(self.cfg); self._register_all_keybinds()
                        self._status_var.set(f"✔ Preset '{preset['name']}' loaded!")
                        win.destroy(); self._show_settings()
                    return do
                def mk_del(preset=p):
                    def do(): delete_keybind_preset(preset["name"]); refresh_presets()
                    return do
                tk.Button(pr, text="Load", bg=ACCENT, fg="#fff", relief="flat",
                          cursor="hand2", font=("Segoe UI",8,"bold"), padx=8, pady=2,
                          command=mk_load()).pack(side="right", padx=(2,0))
                tk.Button(pr, text="🗑", bg=CARD_BG, fg="#e74c3c", relief="flat",
                          cursor="hand2", font=("Segoe UI",9), padx=4,
                          command=mk_del()).pack(side="right")
            if not list_keybind_presets():
                tk.Label(plist, text="No presets saved yet", bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(anchor="w")
        def save_preset():
            name=pname_var.get().strip()
            if not name: return
            save_keybind_preset(name, self.cfg.get("keybinds",[])); refresh_presets()
        tk.Button(prow, text="💾 Save Preset", bg=ACCENT, fg="#fff", relief="flat",
                  cursor="hand2", font=("Segoe UI",9,"bold"), padx=8, pady=4,
                  command=save_preset).pack(side="left", padx=(4,0))
        refresh_presets()
        tk.Frame(kp, bg=BORDER, height=1).pack(fill="x", pady=(12,6))
        tk.Label(kp, text="Active keybinds:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8,"bold")).pack(anchor="w", pady=(0,4))
        kbs = self.cfg.get("keybinds",[])
        if not kbs:
            tk.Label(kp, text="None", bg=DARK_BG, fg=TEXT_SEC, font=("Segoe UI",9)).pack(anchor="w")
        for kb in kbs[:8]:
            row = tk.Frame(kp, bg=DARK_BG); row.pack(fill="x", pady=1)
            tk.Label(row, text=kb.get("key","?"), bg=ACCENT, fg="#fff",
                     font=("Segoe UI",8,"bold"), padx=4, pady=1).pack(side="left", padx=(0,8))
            tk.Label(row, text=f"{kb.get('name','?')}  →  Slot {kb.get('slot',1)}",
                     bg=DARK_BG, fg=TEXT_PRI, font=("Segoe UI",9)).pack(side="left")

        # ── APPEARANCE ──
        ap = panels["Appearance"]
        tk.Label(ap, text="UI Theme", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(0,4))
        tk.Frame(ap, bg=BORDER, height=1).pack(fill="x", pady=(0,10))
        from tkinter import colorchooser
        def make_color_row(label, cfg_key, default):
            row = tk.Frame(ap, bg=DARK_BG); row.pack(fill="x", pady=4)
            tk.Label(row, text=label, bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=18, anchor="w").pack(side="left")
            cur = self.cfg.get(cfg_key, default)
            prev = tk.Frame(row, bg=cur, width=32, height=22); prev.pack(side="left", padx=(0,8))
            lbl2 = tk.Label(row, text=cur, bg=DARK_BG, fg=TEXT_PRI, font=("Consolas",9))
            lbl2.pack(side="left")
            def pick(k=cfg_key, p=prev, l=lbl2, d=default):
                c = colorchooser.askcolor(color=self.cfg.get(k,d), title=f"Pick {label}", parent=win)[1]
                if c: self.cfg[k]=c; p.config(bg=c); l.config(text=c); save_config(self.cfg); self._apply_scrollbar_style()
            def reset(k=cfg_key, d=default, p=prev, l=lbl2):
                self.cfg[k]=d; p.config(bg=d); l.config(text=d); save_config(self.cfg)
            tk.Button(row, text="Pick", bg=CARD_BG, fg=TEXT_PRI, relief="flat",
                      cursor="hand2", font=("Segoe UI",8), padx=8, pady=3,
                      activebackground=CARD_HOVER, command=pick).pack(side="left", padx=(8,0))
            tk.Button(row, text="↺", bg=CARD_BG, fg=TEXT_SEC, relief="flat",
                      cursor="hand2", font=("Segoe UI",9), padx=6, pady=3,
                      activebackground=CARD_HOVER, command=reset).pack(side="left", padx=(2,0))
        make_color_row("Accent color",    "theme_accent",    "#5b9bd5")
        make_color_row("Background",      "theme_bg",        "#0f1117")
        make_color_row("Card color",      "theme_card",      "#1e2330")
        make_color_row("Card hover",      "theme_hover",     "#272d3f")
        make_color_row("Text primary",    "theme_text",      "#eaf0fb")
        make_color_row("Text secondary",  "theme_text2",     "#7a8499")
        make_color_row("Border color",    "theme_border",    "#2a3147")
        make_color_row("Scrollbar color", "theme_scrollbar", "#1e2330")
        tk.Frame(ap, bg=BORDER, height=1).pack(fill="x", pady=(12,8))
        abr = tk.Frame(ap, bg=DARK_BG); abr.pack(anchor="w")
        tk.Button(abr, text="✔  Apply Now", bg=ACCENT, fg="#fff", relief="flat",
                  cursor="hand2", font=("Segoe UI",9,"bold"), padx=12, pady=5,
                  command=lambda: (save_config(self.cfg), win.destroy(), self._apply_theme_live())
                  ).pack(side="left", padx=(0,6))
        tk.Button(abr, text="↺  Reset All", bg=CARD_BG, fg=TEXT_SEC, relief="flat",
                  cursor="hand2", font=("Segoe UI",9), padx=10, pady=5,
                  command=lambda: (
                      self.cfg.update({"theme_accent":"#5b9bd5","theme_bg":"#0f1117","theme_card":"#1e2330",
                          "theme_hover":"#272d3f","theme_text":"#eaf0fb","theme_text2":"#7a8499",
                          "theme_border":"#2a3147","theme_scrollbar":"#1e2330"}),
                      save_config(self.cfg), win.destroy(), self._apply_theme_live()
                  )).pack(side="left")

        # ── THEMES ──
        tp = panels["Themes"]
        tk.Label(tp, text="🎨  Saved Themes", bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(0,4))
        tk.Frame(tp, bg=BORDER, height=1).pack(fill="x", pady=(0,10))
        srow = tk.Frame(tp, bg=DARK_BG); srow.pack(fill="x", pady=(0,8))
        tname_var = tk.StringVar(value="My Theme")
        tk.Entry(srow, textvariable=tname_var, bg=CARD_BG, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat",
                 font=("Segoe UI",10)).pack(side="left", fill="x", expand=True, ipady=5, ipadx=6)
        tlist = tk.Frame(tp, bg=DARK_BG); tlist.pack(fill="x")
        def refresh_themes():
            for w in tlist.winfo_children(): w.destroy()
            themes = list_themes()
            if not themes:
                tk.Label(tlist, text="No saved themes yet. Customize colors in Appearance then save here.",
                         bg=DARK_BG, fg=TEXT_SEC, font=("Segoe UI",9), justify="center").pack(pady=20)
                return
            for t in themes:
                tr = tk.Frame(tlist, bg=CARD_BG, pady=6, padx=10); tr.pack(fill="x", pady=3)
                sr = tk.Frame(tr, bg=CARD_BG); sr.pack(side="left")
                for ck in ["theme_accent","theme_bg","theme_card","theme_hover"]:
                    tk.Frame(sr, bg=t.get(ck,"#333"), width=16, height=16).pack(side="left", padx=1)
                tk.Label(tr, text=t.get("name","?"), bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10,"bold")).pack(side="left", padx=(10,0))
                def mk_lt(td=t):
                    def do():
                        load_theme_to_cfg(td, self.cfg); save_config(self.cfg)
                        win.destroy(); self._apply_theme_live()
                        self._status_var.set(f"✔ Theme '{td['name']}' applied!")
                    return do
                def mk_dt(td=t):
                    def do():
                        try: os.remove(os.path.join(THEMES_DIR, f"{td['name']}.json"))
                        except: pass
                        refresh_themes()
                    return do
                tk.Button(tr, text="Load", bg=ACCENT, fg="#fff", relief="flat",
                          cursor="hand2", font=("Segoe UI",8,"bold"), padx=10, pady=3,
                          command=mk_lt()).pack(side="right", padx=(4,0))
                tk.Button(tr, text="🗑", bg=CARD_BG, fg="#e74c3c", relief="flat",
                          cursor="hand2", font=("Segoe UI",10), padx=6,
                          command=mk_dt()).pack(side="right")
        def do_save_theme():
            n=tname_var.get().strip()
            if not n: return
            save_theme(n, self.cfg); refresh_themes()
        tk.Button(srow, text="💾 Save", bg=ACCENT, fg="#fff", relief="flat",
                  cursor="hand2", font=("Segoe UI",9,"bold"), padx=10, pady=4,
                  command=do_save_theme).pack(side="left", padx=(6,0))
        refresh_themes()

        switch_tab("Keybinds")
        win.bind("<Control-Shift-D>", lambda e: self._show_debug_log())
        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def _show_keybind_manager(self):
        """Full keybind management window inside settings."""
        all_sky = [dict(sky, game=game)
                   for game, skys in self.all_skylanders.items()
                   for sky in skys]
        all_sky.sort(key=lambda x: x["name"])

        win = tk.Toplevel(self)
        win.title("Keybind Manager")
        win.geometry("620x680")
        win.configure(bg=DARK_BG)
        win.transient(self)

        # ── Header ──
        hdr = tk.Frame(win, bg=DARK_BG, pady=10)
        hdr.pack(fill="x", padx=16)
        tk.Label(hdr, text="⌨  Keybind Manager",
                 bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Button(hdr, text="＋  Add Keybind",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=10, pady=4,
                  activebackground="#2980b9",
                  command=lambda: add_keybind_dialog(win, all_sky)
                  ).pack(side="right")

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16)

        # ── Keybind list ──
        list_frame = tk.Frame(win, bg=DARK_BG)
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)

        def refresh_list():
            for w in list_frame.winfo_children(): w.destroy()
            kbs = self.cfg.get("keybinds", [])
            if not kbs:
                tk.Label(list_frame,
                         text="No keybinds yet.\nClick  ＋ Add Keybind  to create one.",
                         bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",10), justify="center").pack(expand=True, pady=40)
                return
            # Column headers
            hrow = tk.Frame(list_frame, bg=DARK_BG)
            hrow.pack(fill="x", pady=(0,4))
            for txt, w in [("Key",100),("Skylander",220),("Slot",40),("",80)]:
                tk.Label(hrow, text=txt, bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8,"bold"), width=w//8, anchor="w").pack(side="left")
            tk.Frame(list_frame, bg=BORDER, height=1).pack(fill="x", pady=(0,4))

            for i, kb in enumerate(kbs):
                row = tk.Frame(list_frame, bg=CARD_BG, pady=6, padx=8)
                row.pack(fill="x", pady=2)
                # Key badge
                key_lbl = tk.Label(row, text=kb.get("key","?"),
                                   bg=ACCENT, fg="#fff",
                                   font=("Segoe UI",9,"bold"),
                                   padx=6, pady=2)
                key_lbl.pack(side="left", padx=(0,10))
                # Name
                tk.Label(row, text=kb.get("name","Unknown"),
                         bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10), anchor="w").pack(side="left", fill="x", expand=True)
                # Slot
                tk.Label(row, text=f"Slot {kb.get('slot',1)}",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=8)
                # Delete button
                def make_delete(idx=i):
                    def delete():
                        self.cfg["keybinds"].pop(idx)
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        refresh_list()
                    return delete

                # Edit button — opens add dialog pre-filled, deletes old only on save
                def make_edit(idx=i, kb_data=kb):
                    def edit():
                        def on_save_callback():
                            # Remove the old keybind after new one is saved
                            # Find and remove by matching original key
                            for j, kb2 in enumerate(self.cfg.get("keybinds",[])):
                                if kb2.get("key") == kb_data.get("key") and j != len(self.cfg["keybinds"])-1:
                                    self.cfg["keybinds"].pop(j)
                                    save_config(self.cfg)
                                    self._register_all_keybinds()
                                    break
                            refresh_list()
                        add_keybind_dialog(win, all_sky, prefill=kb_data, on_save=on_save_callback)
                    return edit

                tk.Button(row, text="🖊",
                          bg=CARD_BG, fg=ACCENT, relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_edit()).pack(side="right")
                tk.Button(row, text="🗑",
                          bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_delete()).pack(side="right")

        def add_keybind_dialog(parent, sky_list, prefill=None, on_save=None):
            dlg = tk.Toplevel(parent)
            dlg.title("Add Keybind")
            dlg.geometry("480x500")
            dlg.configure(bg=DARK_BG)
            dlg.resizable(False, False)
            dlg.grab_set()  # modal

            captured_key = [None]
            selected_sky = [None]

            # ── Title ──
            tk.Label(dlg, text="Add New Keybind",
                     bg=DARK_BG, fg=TEXT_PRI,
                     font=("Segoe UI",12,"bold")).pack(pady=(16,4))
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,10))

            body = tk.Frame(dlg, bg=DARK_BG)
            body.pack(fill="x", padx=16)

            # ── Key capture ──
            key_var = tk.StringVar(value="Click here then press a key")
            key_row = tk.Frame(body, bg=DARK_BG)
            key_row.pack(fill="x", pady=4)
            tk.Label(key_row, text="Key:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            key_btn = tk.Button(key_row, textvariable=key_var,
                                bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                                font=("Segoe UI",10,"bold"), padx=10, pady=6,
                                activebackground=CARD_HOVER)
            key_btn.pack(side="left", fill="x", expand=True)

            def capture_key():
                # Move focus away from search entry to prevent typing into it
                key_btn.focus_set()
                key_var.set("Press any key now…")
                key_btn.config(bg=ACCENT, fg="#fff")
                def on_key(e):
                    sym = e.keysym
                    if sym in ("Shift_L","Shift_R","Control_L","Control_R",
                               "Alt_L","Alt_R","Super_L","Super_R","Tab",
                               "Return","Escape","BackSpace"): return
                    captured_key[0] = f"<{sym}>"
                    key_var.set(f"<{sym}>")
                    key_btn.config(bg=CARD_BG, fg=TEXT_PRI)
                    dlg.unbind("<Key>")
                dlg.bind("<Key>", on_key)
            key_btn.config(command=capture_key)

            # Clicking anywhere outside search entry removes its focus
            def defocus(e):
                if e.widget is not search_entry:
                    key_btn.focus_set()
            dlg.bind("<Button-1>", defocus)

            # ── Slot ──
            slot_row = tk.Frame(body, bg=DARK_BG)
            slot_row.pack(fill="x", pady=4)
            tk.Label(slot_row, text="Slot:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            slot_var = tk.IntVar(value=1)
            for s in range(1, 9):
                tk.Radiobutton(slot_row, text=str(s), variable=slot_var, value=s,
                               bg=DARK_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                               activebackground=DARK_BG,
                               font=("Segoe UI",9)).pack(side="left", padx=2)

            # ── Skylander search ──
            tk.Label(body, text="Skylander:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), anchor="w").pack(fill="x", pady=(8,2))
            search_var = tk.StringVar()
            search_entry = tk.Entry(body, textvariable=search_var,
                     bg=CARD_BG, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI,
                     relief="flat", font=("Segoe UI",10))
            search_entry.pack(fill="x", ipady=5, ipadx=6)

            # ── Results list (fixed height) ──
            list_outer = tk.Frame(dlg, bg=CARD_BG, height=180)
            list_outer.pack(fill="x", padx=16, pady=(4,0))
            list_outer.pack_propagate(False)

            lb_canvas = tk.Canvas(list_outer, bg=CARD_BG, highlightthickness=0)
            lb_sb = ttk.Scrollbar(list_outer, orient="vertical", command=lb_canvas.yview)
            lb_canvas.configure(yscrollcommand=lb_sb.set)
            lb_sb.pack(side="right", fill="y")
            lb_canvas.pack(side="left", fill="both", expand=True)
            lb_inner = tk.Frame(lb_canvas, bg=CARD_BG)
            lb_win = lb_canvas.create_window((0,0), window=lb_inner, anchor="nw")
            lb_inner.bind("<Configure>", lambda e: lb_canvas.configure(
                scrollregion=lb_canvas.bbox("all")))
            lb_canvas.bind("<Configure>", lambda e: lb_canvas.itemconfig(lb_win, width=e.width))
            lb_canvas.bind("<MouseWheel>", lambda e: lb_canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

            def populate(q=""):
                for w in lb_inner.winfo_children(): w.destroy()
                filtered = [s for s in sky_list
                            if not q or q.lower() in s["name"].lower()][:80]
                for sky in filtered:
                    def make_sel(s=sky):
                        def sel():
                            selected_sky[0] = s
                            search_var.set(s["name"])
                            for w2 in lb_inner.winfo_children():
                                try: w2.configure(bg=CARD_BG)
                                except Exception: pass
                                for c in w2.winfo_children():
                                    try: c.configure(bg=CARD_BG)
                                    except Exception: pass
                            ir.configure(bg=ACCENT)
                            il.configure(bg=ACCENT, fg="#fff")
                        return sel
                    ir = tk.Frame(lb_inner, bg=CARD_BG, cursor="hand2")
                    ir.pack(fill="x")
                    il = tk.Label(ir, text=sky["name"], bg=CARD_BG, fg=TEXT_PRI,
                                  font=("Segoe UI",9), anchor="w", padx=8, pady=5)
                    il.pack(fill="x")
                    clk = make_sel(sky)
                    ir.bind("<Button-1>", lambda e, f=clk: f())
                    il.bind("<Button-1>", lambda e, f=clk: f())
                    ir.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    ir.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)
                    il.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    il.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)

            populate()
            search_var.trace_add("write", lambda *_: populate(search_var.get()))

            # Apply prefill AFTER widgets exist
            if prefill:
                captured_key[0] = prefill.get("key","")
                key_var.set(prefill.get("key",""))
                slot_var.set(prefill.get("slot",1))
                search_var.set(prefill.get("name",""))
                for s in sky_list:
                    if s["path"] == prefill.get("path",""):
                        selected_sky[0] = s
                        break

            # ── Status + Save (always at bottom) ──
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
            status_lbl = tk.Label(dlg, text="", bg=DARK_BG, fg="#e67e22",
                                  font=("Segoe UI",9))
            status_lbl.pack(pady=(4,0))

            def save_keybind():
                if not captured_key[0]:
                    status_lbl.config(text="⚠ Click the key button and press a key first"); return
                if not selected_sky[0]:
                    status_lbl.config(text="⚠ Select a Skylander from the list"); return
                existing = [kb["key"] for kb in self.cfg.get("keybinds",[])]
                if captured_key[0] in existing:
                    status_lbl.config(text=f"⚠ {captured_key[0]} already bound — delete it first"); return
                self.cfg.setdefault("keybinds",[]).append({
                    "key":  captured_key[0],
                    "name": selected_sky[0]["name"],
                    "path": selected_sky[0]["path"],
                    "slot": slot_var.get(),
                })
                save_config(self.cfg)
                self._register_all_keybinds()
                dlg.destroy()
                if on_save: on_save()
                else: refresh_list()

            tk.Button(dlg, text="✔  Save Keybind",
                      bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                      font=("Segoe UI",10,"bold"), pady=8,
                      activebackground="#2980b9",
                      command=save_keybind).pack(fill="x", padx=16, pady=8)
        refresh_list()
        # ── Preset bar at the bottom ──
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
        preset_bar = tk.Frame(win, bg=DARK_BG)
        preset_bar.pack(fill="x", padx=16, pady=8)

        tk.Label(preset_bar, text="Preset:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left", padx=(0,6))

        preset_name_var = tk.StringVar(value="My Preset")
        tk.Entry(preset_bar, textvariable=preset_name_var,
                 bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", font=("Segoe UI",9), width=14
                 ).pack(side="left", ipady=4, ipadx=4)

        def save_preset():
            name = preset_name_var.get().strip()
            if not name: return
            save_keybind_preset(name, self.cfg.get("keybinds",[]))
            refresh_preset_list()

        tk.Button(preset_bar, text="💾 Save",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=8, pady=4,
                  activebackground="#2980b9",
                  command=save_preset).pack(side="left", padx=(4,0))

        # Preset dropdown
        preset_select_var = tk.StringVar(value="")
        preset_menu_btn = tk.Button(preset_bar, text="Load Preset ▾",
                                    bg=CARD_BG, fg=TEXT_PRI, relief="flat",
                                    cursor="hand2", font=("Segoe UI",9),
                                    padx=8, pady=4, activebackground=CARD_HOVER)
        preset_menu_btn.pack(side="left", padx=(8,0))

        def refresh_preset_list():
            pass  # placeholder — menu built on click

        def open_preset_menu():
            presets = list_keybind_presets()
            if not presets:
                return
            pmenu = tk.Toplevel(win)
            pmenu.overrideredirect(True)
            pmenu.configure(bg=BORDER)
            x = preset_menu_btn.winfo_rootx()
            y = preset_menu_btn.winfo_rooty() + preset_menu_btn.winfo_height()
            pmenu.geometry(f"+{x}+{y}")
            inner = tk.Frame(pmenu, bg=CARD_BG)
            inner.pack(fill="both", expand=True, padx=1, pady=1)
            tk.Label(inner, text="PRESETS", bg=CARD_BG, fg=TEXT_SEC,
                     font=("Segoe UI",8,"bold"), padx=10, pady=6).pack(fill="x")
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
            for p in presets:
                prow = tk.Frame(inner, bg=CARD_BG, cursor="hand2")
                prow.pack(fill="x")
                tk.Frame(prow, bg=ACCENT, width=3).pack(side="left", fill="y")
                name_lbl = tk.Label(prow, text=f"  {p['name']}",
                                    bg=CARD_BG, fg=TEXT_PRI,
                                    font=("Segoe UI",10), anchor="w",
                                    padx=6, pady=7, cursor="hand2")
                name_lbl.pack(side="left", fill="x", expand=True)
                kb_count = len(p.get("keybinds",[]))
                tk.Label(prow, text=f"{kb_count} keys",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=4)

                def make_load(preset=p):
                    def do():
                        self.cfg["keybinds"] = preset["keybinds"]
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        pmenu.destroy()
                        win.destroy()
                        self._show_keybind_manager()
                        self._status_var.set(f"✔ Preset '{preset['name']}' loaded!")
                    return do

                def make_del(preset=p):
                    def do():
                        delete_keybind_preset(preset["name"])
                        pmenu.destroy()
                    return do

                tk.Button(prow, text="🗑", bg=CARD_BG, fg="#e74c3c",
                          relief="flat", cursor="hand2", font=("Segoe UI",9),
                          padx=4, activebackground=CARD_HOVER,
                          command=make_del()).pack(side="right", padx=(0,2))

                for w in (prow, name_lbl):
                    w.bind("<Enter>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    w.bind("<Leave>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)))
                    w.bind("<Button-1>", lambda e, f=make_load(): f())

            pmenu.bind("<FocusOut>", lambda e: pmenu.destroy() if pmenu.winfo_exists() else None)
            pmenu.focus_set()

        preset_menu_btn.config(command=open_preset_menu)

        win.protocol("WM_DELETE_WINDOW", win.destroy)



    def _show_keybind_manager(self):
        """Full keybind management window inside settings."""
        all_sky = [dict(sky, game=game)
                   for game, skys in self.all_skylanders.items()
                   for sky in skys]
        all_sky.sort(key=lambda x: x["name"])

        win = tk.Toplevel(self)
        win.title("Keybind Manager")
        win.geometry("620x680")
        win.configure(bg=DARK_BG)
        win.transient(self)

        # ── Header ──
        hdr = tk.Frame(win, bg=DARK_BG, pady=10)
        hdr.pack(fill="x", padx=16)
        tk.Label(hdr, text="⌨  Keybind Manager",
                 bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Button(hdr, text="＋  Add Keybind",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=10, pady=4,
                  activebackground="#2980b9",
                  command=lambda: add_keybind_dialog(win, all_sky)
                  ).pack(side="right")

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16)

        # ── Keybind list ──
        list_frame = tk.Frame(win, bg=DARK_BG)
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)

        def refresh_list():
            for w in list_frame.winfo_children(): w.destroy()
            kbs = self.cfg.get("keybinds", [])
            if not kbs:
                tk.Label(list_frame,
                         text="No keybinds yet.\nClick  ＋ Add Keybind  to create one.",
                         bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",10), justify="center").pack(expand=True, pady=40)
                return
            # Column headers
            hrow = tk.Frame(list_frame, bg=DARK_BG)
            hrow.pack(fill="x", pady=(0,4))
            for txt, w in [("Key",100),("Skylander",220),("Slot",40),("",80)]:
                tk.Label(hrow, text=txt, bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8,"bold"), width=w//8, anchor="w").pack(side="left")
            tk.Frame(list_frame, bg=BORDER, height=1).pack(fill="x", pady=(0,4))

            for i, kb in enumerate(kbs):
                row = tk.Frame(list_frame, bg=CARD_BG, pady=6, padx=8)
                row.pack(fill="x", pady=2)
                # Key badge
                key_lbl = tk.Label(row, text=kb.get("key","?"),
                                   bg=ACCENT, fg="#fff",
                                   font=("Segoe UI",9,"bold"),
                                   padx=6, pady=2)
                key_lbl.pack(side="left", padx=(0,10))
                # Name
                tk.Label(row, text=kb.get("name","Unknown"),
                         bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10), anchor="w").pack(side="left", fill="x", expand=True)
                # Slot
                tk.Label(row, text=f"Slot {kb.get('slot',1)}",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=8)
                # Delete button
                def make_delete(idx=i):
                    def delete():
                        self.cfg["keybinds"].pop(idx)
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        refresh_list()
                    return delete

                # Edit button — opens add dialog pre-filled, deletes old only on save
                def make_edit(idx=i, kb_data=kb):
                    def edit():
                        def on_save_callback():
                            # Remove the old keybind after new one is saved
                            # Find and remove by matching original key
                            for j, kb2 in enumerate(self.cfg.get("keybinds",[])):
                                if kb2.get("key") == kb_data.get("key") and j != len(self.cfg["keybinds"])-1:
                                    self.cfg["keybinds"].pop(j)
                                    save_config(self.cfg)
                                    self._register_all_keybinds()
                                    break
                            refresh_list()
                        add_keybind_dialog(win, all_sky, prefill=kb_data, on_save=on_save_callback)
                    return edit

                tk.Button(row, text="🖊",
                          bg=CARD_BG, fg=ACCENT, relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_edit()).pack(side="right")
                tk.Button(row, text="🗑",
                          bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_delete()).pack(side="right")

        def add_keybind_dialog(parent, sky_list, prefill=None, on_save=None):
            dlg = tk.Toplevel(parent)
            dlg.title("Add Keybind")
            dlg.geometry("480x500")
            dlg.configure(bg=DARK_BG)
            dlg.resizable(False, False)
            dlg.grab_set()  # modal

            captured_key = [None]
            selected_sky = [None]

            # ── Title ──
            tk.Label(dlg, text="Add New Keybind",
                     bg=DARK_BG, fg=TEXT_PRI,
                     font=("Segoe UI",12,"bold")).pack(pady=(16,4))
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,10))

            body = tk.Frame(dlg, bg=DARK_BG)
            body.pack(fill="x", padx=16)

            # ── Key capture ──
            key_var = tk.StringVar(value="Click here then press a key")
            key_row = tk.Frame(body, bg=DARK_BG)
            key_row.pack(fill="x", pady=4)
            tk.Label(key_row, text="Key:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            key_btn = tk.Button(key_row, textvariable=key_var,
                                bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                                font=("Segoe UI",10,"bold"), padx=10, pady=6,
                                activebackground=CARD_HOVER)
            key_btn.pack(side="left", fill="x", expand=True)

            def capture_key():
                # Move focus away from search entry to prevent typing into it
                key_btn.focus_set()
                key_var.set("Press any key now…")
                key_btn.config(bg=ACCENT, fg="#fff")
                def on_key(e):
                    sym = e.keysym
                    if sym in ("Shift_L","Shift_R","Control_L","Control_R",
                               "Alt_L","Alt_R","Super_L","Super_R","Tab",
                               "Return","Escape","BackSpace"): return
                    captured_key[0] = f"<{sym}>"
                    key_var.set(f"<{sym}>")
                    key_btn.config(bg=CARD_BG, fg=TEXT_PRI)
                    dlg.unbind("<Key>")
                dlg.bind("<Key>", on_key)
            key_btn.config(command=capture_key)

            # Clicking anywhere outside search entry removes its focus
            def defocus(e):
                if e.widget is not search_entry:
                    key_btn.focus_set()
            dlg.bind("<Button-1>", defocus)

            # ── Slot ──
            slot_row = tk.Frame(body, bg=DARK_BG)
            slot_row.pack(fill="x", pady=4)
            tk.Label(slot_row, text="Slot:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            slot_var = tk.IntVar(value=1)
            for s in range(1, 9):
                tk.Radiobutton(slot_row, text=str(s), variable=slot_var, value=s,
                               bg=DARK_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                               activebackground=DARK_BG,
                               font=("Segoe UI",9)).pack(side="left", padx=2)

            # ── Skylander search ──
            tk.Label(body, text="Skylander:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), anchor="w").pack(fill="x", pady=(8,2))
            search_var = tk.StringVar()
            search_entry = tk.Entry(body, textvariable=search_var,
                     bg=CARD_BG, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI,
                     relief="flat", font=("Segoe UI",10))
            search_entry.pack(fill="x", ipady=5, ipadx=6)

            # ── Results list (fixed height) ──
            list_outer = tk.Frame(dlg, bg=CARD_BG, height=180)
            list_outer.pack(fill="x", padx=16, pady=(4,0))
            list_outer.pack_propagate(False)

            lb_canvas = tk.Canvas(list_outer, bg=CARD_BG, highlightthickness=0)
            lb_sb = ttk.Scrollbar(list_outer, orient="vertical", command=lb_canvas.yview)
            lb_canvas.configure(yscrollcommand=lb_sb.set)
            lb_sb.pack(side="right", fill="y")
            lb_canvas.pack(side="left", fill="both", expand=True)
            lb_inner = tk.Frame(lb_canvas, bg=CARD_BG)
            lb_win = lb_canvas.create_window((0,0), window=lb_inner, anchor="nw")
            lb_inner.bind("<Configure>", lambda e: lb_canvas.configure(
                scrollregion=lb_canvas.bbox("all")))
            lb_canvas.bind("<Configure>", lambda e: lb_canvas.itemconfig(lb_win, width=e.width))
            lb_canvas.bind("<MouseWheel>", lambda e: lb_canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

            def populate(q=""):
                for w in lb_inner.winfo_children(): w.destroy()
                filtered = [s for s in sky_list
                            if not q or q.lower() in s["name"].lower()][:80]
                for sky in filtered:
                    def make_sel(s=sky):
                        def sel():
                            selected_sky[0] = s
                            search_var.set(s["name"])
                            for w2 in lb_inner.winfo_children():
                                try: w2.configure(bg=CARD_BG)
                                except Exception: pass
                                for c in w2.winfo_children():
                                    try: c.configure(bg=CARD_BG)
                                    except Exception: pass
                            ir.configure(bg=ACCENT)
                            il.configure(bg=ACCENT, fg="#fff")
                        return sel
                    ir = tk.Frame(lb_inner, bg=CARD_BG, cursor="hand2")
                    ir.pack(fill="x")
                    il = tk.Label(ir, text=sky["name"], bg=CARD_BG, fg=TEXT_PRI,
                                  font=("Segoe UI",9), anchor="w", padx=8, pady=5)
                    il.pack(fill="x")
                    clk = make_sel(sky)
                    ir.bind("<Button-1>", lambda e, f=clk: f())
                    il.bind("<Button-1>", lambda e, f=clk: f())
                    ir.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    ir.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)
                    il.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    il.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)

            populate()
            search_var.trace_add("write", lambda *_: populate(search_var.get()))

            # Apply prefill AFTER widgets exist
            if prefill:
                captured_key[0] = prefill.get("key","")
                key_var.set(prefill.get("key",""))
                slot_var.set(prefill.get("slot",1))
                search_var.set(prefill.get("name",""))
                for s in sky_list:
                    if s["path"] == prefill.get("path",""):
                        selected_sky[0] = s
                        break

            # ── Status + Save (always at bottom) ──
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
            status_lbl = tk.Label(dlg, text="", bg=DARK_BG, fg="#e67e22",
                                  font=("Segoe UI",9))
            status_lbl.pack(pady=(4,0))

            def save_keybind():
                if not captured_key[0]:
                    status_lbl.config(text="⚠ Click the key button and press a key first"); return
                if not selected_sky[0]:
                    status_lbl.config(text="⚠ Select a Skylander from the list"); return
                existing = [kb["key"] for kb in self.cfg.get("keybinds",[])]
                if captured_key[0] in existing:
                    status_lbl.config(text=f"⚠ {captured_key[0]} already bound — delete it first"); return
                self.cfg.setdefault("keybinds",[]).append({
                    "key":  captured_key[0],
                    "name": selected_sky[0]["name"],
                    "path": selected_sky[0]["path"],
                    "slot": slot_var.get(),
                })
                save_config(self.cfg)
                self._register_all_keybinds()
                dlg.destroy()
                if on_save: on_save()
                else: refresh_list()

            tk.Button(dlg, text="✔  Save Keybind",
                      bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                      font=("Segoe UI",10,"bold"), pady=8,
                      activebackground="#2980b9",
                      command=save_keybind).pack(fill="x", padx=16, pady=8)
        refresh_list()
        # ── Preset bar at the bottom ──
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
        preset_bar = tk.Frame(win, bg=DARK_BG)
        preset_bar.pack(fill="x", padx=16, pady=8)

        tk.Label(preset_bar, text="Preset:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left", padx=(0,6))

        preset_name_var = tk.StringVar(value="My Preset")
        tk.Entry(preset_bar, textvariable=preset_name_var,
                 bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", font=("Segoe UI",9), width=14
                 ).pack(side="left", ipady=4, ipadx=4)

        def save_preset():
            name = preset_name_var.get().strip()
            if not name: return
            save_keybind_preset(name, self.cfg.get("keybinds",[]))
            refresh_preset_list()

        tk.Button(preset_bar, text="💾 Save",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=8, pady=4,
                  activebackground="#2980b9",
                  command=save_preset).pack(side="left", padx=(4,0))

        # Preset dropdown
        preset_select_var = tk.StringVar(value="")
        preset_menu_btn = tk.Button(preset_bar, text="Load Preset ▾",
                                    bg=CARD_BG, fg=TEXT_PRI, relief="flat",
                                    cursor="hand2", font=("Segoe UI",9),
                                    padx=8, pady=4, activebackground=CARD_HOVER)
        preset_menu_btn.pack(side="left", padx=(8,0))

        def refresh_preset_list():
            pass  # placeholder — menu built on click

        def open_preset_menu():
            presets = list_keybind_presets()
            if not presets:
                return
            pmenu = tk.Toplevel(win)
            pmenu.overrideredirect(True)
            pmenu.configure(bg=BORDER)
            x = preset_menu_btn.winfo_rootx()
            y = preset_menu_btn.winfo_rooty() + preset_menu_btn.winfo_height()
            pmenu.geometry(f"+{x}+{y}")
            inner = tk.Frame(pmenu, bg=CARD_BG)
            inner.pack(fill="both", expand=True, padx=1, pady=1)
            tk.Label(inner, text="PRESETS", bg=CARD_BG, fg=TEXT_SEC,
                     font=("Segoe UI",8,"bold"), padx=10, pady=6).pack(fill="x")
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
            for p in presets:
                prow = tk.Frame(inner, bg=CARD_BG, cursor="hand2")
                prow.pack(fill="x")
                tk.Frame(prow, bg=ACCENT, width=3).pack(side="left", fill="y")
                name_lbl = tk.Label(prow, text=f"  {p['name']}",
                                    bg=CARD_BG, fg=TEXT_PRI,
                                    font=("Segoe UI",10), anchor="w",
                                    padx=6, pady=7, cursor="hand2")
                name_lbl.pack(side="left", fill="x", expand=True)
                kb_count = len(p.get("keybinds",[]))
                tk.Label(prow, text=f"{kb_count} keys",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=4)

                def make_load(preset=p):
                    def do():
                        self.cfg["keybinds"] = preset["keybinds"]
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        pmenu.destroy()
                        win.destroy()
                        self._show_keybind_manager()
                        self._status_var.set(f"✔ Preset '{preset['name']}' loaded!")
                    return do

                def make_del(preset=p):
                    def do():
                        delete_keybind_preset(preset["name"])
                        pmenu.destroy()
                    return do

                tk.Button(prow, text="🗑", bg=CARD_BG, fg="#e74c3c",
                          relief="flat", cursor="hand2", font=("Segoe UI",9),
                          padx=4, activebackground=CARD_HOVER,
                          command=make_del()).pack(side="right", padx=(0,2))

                for w in (prow, name_lbl):
                    w.bind("<Enter>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    w.bind("<Leave>", lambda e, r=prow, l=name_lbl: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)))
                    w.bind("<Button-1>", lambda e, f=make_load(): f())

            pmenu.bind("<FocusOut>", lambda e: pmenu.destroy() if pmenu.winfo_exists() else None)
            pmenu.focus_set()

        preset_menu_btn.config(command=open_preset_menu)

        win.protocol("WM_DELETE_WINDOW", win.destroy)


    def _show_debug_log(self):
        win=tk.Toplevel(self); win.title("Debug Log"); win.geometry("750x580")
        win.configure(bg=DARK_BG); win.transient(self)

        # VirtPort settings
        vp_frame=tk.Frame(win,bg=DARK_BG); vp_frame.pack(fill="x",padx=8,pady=(8,0))
        tk.Label(vp_frame,text="VirtPort Connection",bg=DARK_BG,fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(anchor="w")
        vp_card=tk.Frame(win,bg=CARD_BG); vp_card.pack(fill="x",padx=8,pady=(4,0))
        host_var=tk.StringVar(value=self.cfg.get("vp_host","localhost"))
        port_var=tk.StringVar(value=str(self.cfg.get("vp_port",5678)))
        for lbl,var,w in [("Host:",host_var,20),("Port:",port_var,8)]:
            r=tk.Frame(vp_card,bg=CARD_BG); r.pack(side="left",padx=(8,0),pady=6)
            tk.Label(r,text=lbl,bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",9)).pack(side="left",padx=(0,4))
            tk.Entry(r,textvariable=var,bg=DARK_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,
                     relief="flat",font=("Segoe UI",9),width=w).pack(side="left",ipady=3,ipadx=4)
        vp_status=tk.Label(vp_card,text="",bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",8))
        vp_status.pack(side="left",padx=8)
        def test_vp():
            h=host_var.get().strip()
            try: p=int(port_var.get())
            except: return
            vp_status.config(text="Testing…",fg=TEXT_SEC); win.update_idletasks()
            ok=virtport_ping(h,p)
            vp_status.config(text="✔ Connected!" if ok else "⚠ Not reachable",
                             fg="#3dba6f" if ok else "#e67e22")
        def save_vp():
            self.cfg["vp_host"]=host_var.get().strip()
            try: self.cfg["vp_port"]=int(port_var.get())
            except: pass
            save_config(self.cfg); self._check_virtport_connection()
            vp_status.config(text="✔ Saved!",fg="#3dba6f")
        btn_vp=tk.Frame(vp_card,bg=CARD_BG); btn_vp.pack(side="left",padx=4)
        tk.Button(btn_vp,text="🔌 Test",bg=CARD_BG,fg=TEXT_PRI,relief="flat",cursor="hand2",
                  font=("Segoe UI",8),padx=6,pady=3,activebackground=CARD_HOVER,
                  command=test_vp).pack(side="left",padx=(0,4))
        tk.Button(btn_vp,text="Save",bg=ACCENT,fg="#fff",relief="flat",cursor="hand2",
                  font=("Segoe UI",8,"bold"),padx=8,pady=3,command=save_vp).pack(side="left")

        tk.Frame(win,bg=BORDER,height=1).pack(fill="x",padx=8,pady=(8,0))

        toolbar=tk.Frame(win,bg=DARK_BG); toolbar.pack(fill="x",padx=8,pady=(6,0))
        tk.Label(toolbar,text="Debug Log",bg=DARK_BG,fg=TEXT_PRI,
                 font=("Segoe UI",10,"bold")).pack(side="left")
        tk.Button(toolbar,text="🗑 Clear",bg=CARD_BG,fg=TEXT_SEC,relief="flat",cursor="hand2",
                  font=("Segoe UI",9),padx=8,pady=3,
                  command=lambda:(_debug_log.clear(),txt.delete("1.0","end"))).pack(side="right")
        tk.Button(toolbar,text="📋 Copy",bg=CARD_BG,fg=TEXT_SEC,relief="flat",cursor="hand2",
                  font=("Segoe UI",9),padx=8,pady=3,
                  command=lambda:(win.clipboard_clear(),win.clipboard_append("\n".join(_debug_log)),win.update())
                  ).pack(side="right",padx=(0,6))
        txt=tk.Text(win,bg=CARD_BG,fg=TEXT_PRI,font=("Consolas",9),relief="flat",wrap="word")
        sb2=ttk.Scrollbar(win,orient="vertical",command=txt.yview)
        txt.configure(yscrollcommand=sb2.set)
        txt.tag_configure("click",foreground="#3dba6f",font=("Consolas",9,"bold"))
        sb2.pack(side="right",fill="y",padx=(0,8),pady=8)
        txt.pack(fill="both",expand=True,padx=8,pady=8)
        for line in _debug_log:
            txt.insert("end",line+"\n","click" if line.startswith("[CLICK]") else "normal")
        txt.see("end"); txt.configure(state="disabled")
        def refresh():
            if not win.winfo_exists(): return
            txt.configure(state="normal"); txt.delete("1.0","end")
            for line in _debug_log:
                txt.insert("end",line+"\n","click" if line.startswith("[CLICK]") else "normal")
            txt.see("end"); txt.configure(state="disabled"); win.after(300,refresh)
        win.after(300,refresh)


    def _show_keybind_manager(self):
        """Full keybind management window inside settings."""
        all_sky = [dict(sky, game=game)
                   for game, skys in self.all_skylanders.items()
                   for sky in skys]
        all_sky.sort(key=lambda x: x["name"])

        win = tk.Toplevel(self)
        win.title("Keybind Manager")
        win.geometry("620x560")
        win.configure(bg=DARK_BG)
        win.transient(self)

        # ── Header ──
        hdr = tk.Frame(win, bg=DARK_BG, pady=10)
        hdr.pack(fill="x", padx=16)
        tk.Label(hdr, text="⌨  Keybind Manager",
                 bg=DARK_BG, fg=TEXT_PRI,
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Button(hdr, text="＋  Add Keybind",
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  font=("Segoe UI",9,"bold"), padx=10, pady=4,
                  activebackground="#2980b9",
                  command=lambda: add_keybind_dialog(win, all_sky)
                  ).pack(side="right")

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=16)

        # ── Keybind list ──
        list_frame = tk.Frame(win, bg=DARK_BG)
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)

        def refresh_list():
            for w in list_frame.winfo_children(): w.destroy()
            kbs = self.cfg.get("keybinds", [])
            if not kbs:
                tk.Label(list_frame,
                         text="No keybinds yet.\nClick  ＋ Add Keybind  to create one.",
                         bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",10), justify="center").pack(expand=True, pady=40)
                return
            # Column headers
            hrow = tk.Frame(list_frame, bg=DARK_BG)
            hrow.pack(fill="x", pady=(0,4))
            for txt, w in [("Key",100),("Skylander",220),("Slot",40),("",80)]:
                tk.Label(hrow, text=txt, bg=DARK_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8,"bold"), width=w//8, anchor="w").pack(side="left")
            tk.Frame(list_frame, bg=BORDER, height=1).pack(fill="x", pady=(0,4))

            for i, kb in enumerate(kbs):
                row = tk.Frame(list_frame, bg=CARD_BG, pady=6, padx=8)
                row.pack(fill="x", pady=2)
                # Key badge
                key_lbl = tk.Label(row, text=kb.get("key","?"),
                                   bg=ACCENT, fg="#fff",
                                   font=("Segoe UI",9,"bold"),
                                   padx=6, pady=2)
                key_lbl.pack(side="left", padx=(0,10))
                # Name
                tk.Label(row, text=kb.get("name","Unknown"),
                         bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10), anchor="w").pack(side="left", fill="x", expand=True)
                # Slot
                tk.Label(row, text=f"Slot {kb.get('slot',1)}",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left", padx=8)
                # Delete button
                def make_delete(idx=i):
                    def delete():
                        self.cfg["keybinds"].pop(idx)
                        save_config(self.cfg)
                        self._register_all_keybinds()
                        refresh_list()
                    return delete

                # Edit button — opens add dialog pre-filled, deletes old only on save
                def make_edit(idx=i, kb_data=kb):
                    def edit():
                        def on_save_callback():
                            # Remove the old keybind after new one is saved
                            # Find and remove by matching original key
                            for j, kb2 in enumerate(self.cfg.get("keybinds",[])):
                                if kb2.get("key") == kb_data.get("key") and j != len(self.cfg["keybinds"])-1:
                                    self.cfg["keybinds"].pop(j)
                                    save_config(self.cfg)
                                    self._register_all_keybinds()
                                    break
                            refresh_list()
                        add_keybind_dialog(win, all_sky, prefill=kb_data, on_save=on_save_callback)
                    return edit

                tk.Button(row, text="🖊",
                          bg=CARD_BG, fg=ACCENT, relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_edit()).pack(side="right")
                tk.Button(row, text="🗑",
                          bg=CARD_BG, fg="#e74c3c", relief="flat", cursor="hand2",
                          font=("Segoe UI",10), padx=6,
                          activebackground=CARD_HOVER,
                          command=make_delete()).pack(side="right")

        def add_keybind_dialog(parent, sky_list, prefill=None, on_save=None):
            dlg = tk.Toplevel(parent)
            dlg.title("Add Keybind")
            dlg.geometry("480x500")
            dlg.configure(bg=DARK_BG)
            dlg.resizable(False, False)
            dlg.grab_set()  # modal

            captured_key = [None]
            selected_sky = [None]

            # ── Title ──
            tk.Label(dlg, text="Add New Keybind",
                     bg=DARK_BG, fg=TEXT_PRI,
                     font=("Segoe UI",12,"bold")).pack(pady=(16,4))
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,10))

            body = tk.Frame(dlg, bg=DARK_BG)
            body.pack(fill="x", padx=16)

            # ── Key capture ──
            key_var = tk.StringVar(value="Click here then press a key")
            key_row = tk.Frame(body, bg=DARK_BG)
            key_row.pack(fill="x", pady=4)
            tk.Label(key_row, text="Key:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            key_btn = tk.Button(key_row, textvariable=key_var,
                                bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                                font=("Segoe UI",10,"bold"), padx=10, pady=6,
                                activebackground=CARD_HOVER)
            key_btn.pack(side="left", fill="x", expand=True)

            def capture_key():
                # Move focus away from search entry to prevent typing into it
                key_btn.focus_set()
                key_var.set("Press any key now…")
                key_btn.config(bg=ACCENT, fg="#fff")
                def on_key(e):
                    sym = e.keysym
                    if sym in ("Shift_L","Shift_R","Control_L","Control_R",
                               "Alt_L","Alt_R","Super_L","Super_R","Tab",
                               "Return","Escape","BackSpace"): return
                    captured_key[0] = f"<{sym}>"
                    key_var.set(f"<{sym}>")
                    key_btn.config(bg=CARD_BG, fg=TEXT_PRI)
                    dlg.unbind("<Key>")
                dlg.bind("<Key>", on_key)
            key_btn.config(command=capture_key)

            # Clicking anywhere outside search entry removes its focus
            def defocus(e):
                if e.widget is not search_entry:
                    key_btn.focus_set()
            dlg.bind("<Button-1>", defocus)

            # ── Slot ──
            slot_row = tk.Frame(body, bg=DARK_BG)
            slot_row.pack(fill="x", pady=4)
            tk.Label(slot_row, text="Slot:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
            slot_var = tk.IntVar(value=1)
            for s in range(1, 9):
                tk.Radiobutton(slot_row, text=str(s), variable=slot_var, value=s,
                               bg=DARK_BG, fg=TEXT_PRI, selectcolor=CARD_BG,
                               activebackground=DARK_BG,
                               font=("Segoe UI",9)).pack(side="left", padx=2)

            # ── Skylander search ──
            tk.Label(body, text="Skylander:", bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI",10), anchor="w").pack(fill="x", pady=(8,2))
            search_var = tk.StringVar()
            search_entry = tk.Entry(body, textvariable=search_var,
                     bg=CARD_BG, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI,
                     relief="flat", font=("Segoe UI",10))
            search_entry.pack(fill="x", ipady=5, ipadx=6)

            # ── Results list (fixed height) ──
            list_outer = tk.Frame(dlg, bg=CARD_BG, height=180)
            list_outer.pack(fill="x", padx=16, pady=(4,0))
            list_outer.pack_propagate(False)

            lb_canvas = tk.Canvas(list_outer, bg=CARD_BG, highlightthickness=0)
            lb_sb = ttk.Scrollbar(list_outer, orient="vertical", command=lb_canvas.yview)
            lb_canvas.configure(yscrollcommand=lb_sb.set)
            lb_sb.pack(side="right", fill="y")
            lb_canvas.pack(side="left", fill="both", expand=True)
            lb_inner = tk.Frame(lb_canvas, bg=CARD_BG)
            lb_win = lb_canvas.create_window((0,0), window=lb_inner, anchor="nw")
            lb_inner.bind("<Configure>", lambda e: lb_canvas.configure(
                scrollregion=lb_canvas.bbox("all")))
            lb_canvas.bind("<Configure>", lambda e: lb_canvas.itemconfig(lb_win, width=e.width))
            lb_canvas.bind("<MouseWheel>", lambda e: lb_canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

            def populate(q=""):
                for w in lb_inner.winfo_children(): w.destroy()
                filtered = [s for s in sky_list
                            if not q or q.lower() in s["name"].lower()][:80]
                for sky in filtered:
                    def make_sel(s=sky):
                        def sel():
                            selected_sky[0] = s
                            search_var.set(s["name"])
                            for w2 in lb_inner.winfo_children():
                                try: w2.configure(bg=CARD_BG)
                                except Exception: pass
                                for c in w2.winfo_children():
                                    try: c.configure(bg=CARD_BG)
                                    except Exception: pass
                            ir.configure(bg=ACCENT)
                            il.configure(bg=ACCENT, fg="#fff")
                        return sel
                    ir = tk.Frame(lb_inner, bg=CARD_BG, cursor="hand2")
                    ir.pack(fill="x")
                    il = tk.Label(ir, text=sky["name"], bg=CARD_BG, fg=TEXT_PRI,
                                  font=("Segoe UI",9), anchor="w", padx=8, pady=5)
                    il.pack(fill="x")
                    clk = make_sel(sky)
                    ir.bind("<Button-1>", lambda e, f=clk: f())
                    il.bind("<Button-1>", lambda e, f=clk: f())
                    ir.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    ir.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)
                    il.bind("<Enter>", lambda e, r=ir, l=il: (r.config(bg=CARD_HOVER), l.config(bg=CARD_HOVER)))
                    il.bind("<Leave>", lambda e, r=ir, l=il, s=sky: (r.config(bg=CARD_BG), l.config(bg=CARD_BG)) if selected_sky[0] is not s else None)

            populate()
            search_var.trace_add("write", lambda *_: populate(search_var.get()))

            # Apply prefill AFTER widgets exist
            if prefill:
                captured_key[0] = prefill.get("key","")
                key_var.set(prefill.get("key",""))
                slot_var.set(prefill.get("slot",1))
                search_var.set(prefill.get("name",""))
                for s in sky_list:
                    if s["path"] == prefill.get("path",""):
                        selected_sky[0] = s
                        break

            # ── Status + Save (always at bottom) ──
            tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8,0))
            status_lbl = tk.Label(dlg, text="", bg=DARK_BG, fg="#e67e22",
                                  font=("Segoe UI",9))
            status_lbl.pack(pady=(4,0))

            def save_keybind():
                if not captured_key[0]:
                    status_lbl.config(text="⚠ Click the key button and press a key first"); return
                if not selected_sky[0]:
                    status_lbl.config(text="⚠ Select a Skylander from the list"); return
                existing = [kb["key"] for kb in self.cfg.get("keybinds",[])]
                if captured_key[0] in existing:
                    status_lbl.config(text=f"⚠ {captured_key[0]} already bound — delete it first"); return
                self.cfg.setdefault("keybinds",[]).append({
                    "key":  captured_key[0],
                    "name": selected_sky[0]["name"],
                    "path": selected_sky[0]["path"],
                    "slot": slot_var.get(),
                })
                save_config(self.cfg)
                self._register_all_keybinds()
                dlg.destroy()
                if on_save: on_save()
                else: refresh_list()

            tk.Button(dlg, text="✔  Save Keybind",
                      bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                      font=("Segoe UI",10,"bold"), pady=8,
                      activebackground="#2980b9",
                      command=save_keybind).pack(fill="x", padx=16, pady=8)
        refresh_list()
        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def _on_restore(self, e=None):
        """Force redraw after window is restored — debounced to prevent lag."""
        if hasattr(self, '_restore_after_id'):
            try: self.after_cancel(self._restore_after_id)
            except Exception: pass
        # Delay 150ms so rapid events (move/resize) don't all trigger redraws
        self._restore_after_id = self.after(150, self._do_restore)

    def _do_restore(self):
        if self._vlist and hasattr(self._vlist, '_schedule_draw'):
            self._vlist._schedule_draw()
        elif self._vlist and hasattr(self._vlist, '_draw'):
            self._vlist._draw()

    def _apply_theme_live(self):
        """Apply current theme colors live without restarting."""
        global DARK_BG, PANEL_BG, CARD_BG, CARD_HOVER, ACCENT, TEXT_PRI, TEXT_SEC, BORDER, SCROLLBAR
        # Update globals from config
        DARK_BG   = self.cfg.get("theme_bg",     "#0f1117")
        PANEL_BG  = self.cfg.get("theme_bg",     "#0f1117")
        CARD_BG   = self.cfg.get("theme_card",   "#1e2330")
        CARD_HOVER= self.cfg.get("theme_hover",  "#272d3f")
        ACCENT    = self.cfg.get("theme_accent", "#5b9bd5")
        TEXT_PRI  = self.cfg.get("theme_text",   "#eaf0fb")
        TEXT_SEC  = self.cfg.get("theme_text2",  "#7a8499")
        BORDER    = self.cfg.get("theme_border", "#2a3147")
        SCROLLBAR = self.cfg.get("theme_scrollbar","#1e2330")
        # Full UI rebuild — cleanest way to apply all color changes
        for w in self.winfo_children():
            w.destroy()
        self.configure(bg=DARK_BG)
        self._manual_mode = False
        self._build_ui()
        self._apply_scrollbar_style()
        if self.cfg.get("root_folder"):
            self._load_folder_startup(self.cfg["root_folder"])
        self.bind_all("<Shift-M>", self._toggle_manual_mode)
        self.bind_all("<Shift-M>", self._toggle_manual_mode)
        self._register_all_keybinds()

    def _apply_scrollbar_style(self):
        """Apply current theme scrollbar color to ttk scrollbars."""
        style = ttk.Style()
        sb_color = self.cfg.get("theme_scrollbar", SCROLLBAR)
        bg_color  = self.cfg.get("theme_bg", DARK_BG)
        hover     = self.cfg.get("theme_hover", CARD_HOVER)
        border    = self.cfg.get("theme_border", BORDER)
        txt_sec   = self.cfg.get("theme_text2", TEXT_SEC)
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar",
                background=sb_color, troughcolor=bg_color,
                bordercolor=border, arrowcolor=txt_sec,
                relief="flat", gripcount=0)
            style.map(f"{orient}.TScrollbar",
                background=[("active", hover), ("disabled", bg_color)])

    def _check_virtport_connection(self):
        def check():
            host=self.cfg.get("vp_host","localhost"); port=self.cfg.get("vp_port",5678)
            ok=virtport_ping(host,port)
            def update():
                if ok:
                    self._vp_dot.config(fg="#3dba6f")
                    self._vp_lbl.config(text="VirtPort ✔",fg="#3dba6f")
                else:
                    self._vp_dot.config(fg="#e67e22")
                    self._vp_lbl.config(text="VirtPort ⚠",fg="#e67e22")
            self.after(0,update)
        threading.Thread(target=check,daemon=True).start()
        # Recheck every 10 seconds
        self.after(10000,self._check_virtport_connection)

    # ── TABS ─────────────────────────────────

    def _build_tabs(self):
        for w in self.tab_bar.winfo_children(): w.destroy()
        self._tab_buttons={}
        for name in ["All","Favorites"]+GAME_FOLDER_HINTS:
            color=GAME_COLORS.get(name,ACCENT); display=GAME_DISPLAY_NAMES.get(name,name)
            if name=="Swap Force":
                cont=tk.Frame(self.tab_bar,bg=DARK_BG); cont.pack(side="left")
                btn=tk.Label(cont,text=display,bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9,"bold"),cursor="hand2",padx=8,pady=6); btn.pack(side="left")
                btn.bind("<Button-1>",lambda e,n=name:self._switch_tab(n))
                arrow=tk.Label(cont,text="▾",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),cursor="hand2",padx=2,pady=6); arrow.pack(side="left")
                arrow.bind("<Button-1>",lambda e,a=arrow:self._toggle_swapforce_dropdown(a))
                self._tab_buttons[name]=(btn,color); self._tab_buttons["sf_arrow"]=(arrow,color)
            elif name=="SuperChargers":
                cont=tk.Frame(self.tab_bar,bg=DARK_BG); cont.pack(side="left")
                btn=tk.Label(cont,text=display,bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9,"bold"),cursor="hand2",padx=8,pady=6); btn.pack(side="left")
                btn.bind("<Button-1>",lambda e,n=name:self._switch_tab(n))
                arrow=tk.Label(cont,text="▾",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),cursor="hand2",padx=2,pady=6); arrow.pack(side="left")
                arrow.bind("<Button-1>",lambda e,a=arrow:self._toggle_vehicles_dropdown(a))
                self._tab_buttons[name]=(btn,color); self._tab_buttons["arrow"]=(arrow,color)
            elif name=="Favorites":
                cont=tk.Frame(self.tab_bar,bg=DARK_BG); cont.pack(side="left")
                btn=tk.Label(cont,text=display,bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9,"bold"),cursor="hand2",padx=8,pady=6); btn.pack(side="left")
                btn.bind("<Button-1>",lambda e,n=name:self._switch_tab(n))
                arrow=tk.Label(cont,text="▾",bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9),cursor="hand2",padx=2,pady=6); arrow.pack(side="left")
                arrow.bind("<Button-1>",lambda e,a=arrow:self._toggle_favorites_dropdown(a))
                self._tab_buttons[name]=(btn,color); self._tab_buttons["fav_arrow"]=(arrow,color)
            else:
                btn=tk.Label(self.tab_bar,text=display,bg=DARK_BG,fg=TEXT_SEC,font=("Segoe UI",9,"bold"),cursor="hand2",padx=10,pady=6); btn.pack(side="left")
                btn.bind("<Button-1>",lambda e,n=name:self._switch_tab(n))
                self._tab_buttons[name]=(btn,color)
        self._highlight_tab(self.active_tab.get())

    def _highlight_tab(self,name):
        for n,(btn,color) in self._tab_buttons.items():
            if n in ("arrow","sf_arrow","fav_arrow"): continue
            if n==name: btn.config(fg=color,font=("Segoe UI",9,"bold"),highlightthickness=2,highlightbackground=color,highlightcolor=color,pady=4)
            else: btn.config(fg=TEXT_SEC,highlightthickness=0)

    def _switch_tab(self,name):
        self._close_dropdown(); self.active_tab.set(name); self._highlight_tab(name); self.search_var.set(""); self._refresh_active_tab()

    def _toggle_favorites_dropdown(self,anchor):
        if self._dropdown_open: self._close_dropdown()
        else: self._open_dropdown(anchor,[
            ("★  All Favorites","Favorites"),
            ("⬡  Swap Force Combos","Favorites:Combos"),
        ],"FAVORITES")

    def _toggle_swapforce_dropdown(self,anchor):
        if self._dropdown_open: self._close_dropdown()
        else: self._open_dropdown(anchor,[("🔀  All Swap Force","Swap Force"),("⚡  Swap Force Editor","SwapForce:Mix")],"SWAP FORCE")

    def _toggle_vehicles_dropdown(self,anchor):
        if self._dropdown_open: self._close_dropdown()
        else: self._open_dropdown(anchor,[
                ("🚗  All Vehicles","Vehicles"),
                ("🏎  Land Vehicles","Vehicles:Land"),
                ("✈  Sky Vehicles","Vehicles:Sky"),
                ("🚢  Sea Vehicles","Vehicles:Sea"),
                ("💀  Villain Vehicles","Vehicles:Villain"),
            ],"VEHICLES")

    def _open_dropdown(self,anchor,items,title):
        self._close_dropdown(); self._dropdown_open=True
        win=tk.Toplevel(self); win.overrideredirect(True); win.configure(bg=BORDER)
        self._dropdown_win=win
        win.attributes("-topmost",True)
        win.geometry(f"+{anchor.winfo_rootx()}+{anchor.winfo_rooty()+anchor.winfo_height()}")
        inner=tk.Frame(win,bg=CARD_BG); inner.pack(fill="both",expand=True,padx=1,pady=1)
        tk.Label(inner,text=title,bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",8,"bold"),padx=12,pady=6).pack(fill="x")
        tk.Frame(inner,bg=BORDER,height=1).pack(fill="x")
        for label,tab_key in items:
            row=tk.Frame(inner,bg=CARD_BG,cursor="hand2"); row.pack(fill="x")
            color=GAME_COLORS.get(tab_key.split(":")[0],ACCENT)
            strip=tk.Frame(row,bg=color,width=3); strip.pack(side="left",fill="y")
            it=tk.Label(row,text=f"  {label}",bg=CARD_BG,fg=TEXT_PRI,font=("Segoe UI",10),anchor="w",cursor="hand2",padx=8,pady=9); it.pack(side="left",fill="x",expand=True)
            for w2 in (row,it,strip):
                w2.bind("<Enter>",lambda e,r=row,i=it:(r.config(bg=CARD_HOVER),i.config(bg=CARD_HOVER)))
                w2.bind("<Leave>",lambda e,r=row,i=it:(r.config(bg=CARD_BG),i.config(bg=CARD_BG)))
                w2.bind("<Button-1>",lambda e,k=tab_key:self._switch_tab(k))
        self.bind("<Button-1>",self._on_outside_click); win.bind("<Button-1>",lambda e:None)

    def _close_dropdown(self):
        if self._dropdown_win:
            try: self._dropdown_win.destroy()
            except Exception: pass
            self._dropdown_win=None
        self._dropdown_open=False
        try: self.unbind("<Button-1>")
        except Exception: pass

    def _on_outside_click(self,e): self._close_dropdown()

    # ── LOADING ──────────────────────────────

    def _load_folder_startup(self,folder):
        cached=load_cache(folder)
        if cached:
            self.all_skylanders=cached
            total=sum(len(v) for v in cached.values())
            self._status_var.set(f"✔ {total} Skylanders loaded  ·  {folder}")
            self._refresh_active_tab()
        else:
            self._status_var.set("Scanning folder…"); self._do_scan(folder)

    def _pick_folder(self):
        folder=filedialog.askdirectory(title="Select your Skylanders folder")
        if folder: self.cfg["root_folder"]=folder; save_config(self.cfg); self._do_scan(folder)

    def _force_rescan(self):
        folder=self.cfg.get("root_folder")
        if not folder: return
        try: os.remove(CACHE_FILE)
        except Exception: pass
        self._do_scan(folder)

    def _do_scan(self,folder):
        self._status_var.set("Scanning…"); self.update_idletasks()
        def work():
            data=discover_skylanders(folder); save_cache(folder,data)
            self.after(0,lambda:self._apply_data(folder,data))
        threading.Thread(target=work,daemon=True).start()

    def _apply_data(self,folder,data):
        self.cfg["root_folder"]=folder; save_config(self.cfg); self.all_skylanders=data
        # Re-apply any manually located vehicles
        for entry in self.cfg.get("manual_vehicles",[]):
            if os.path.exists(entry["path"]):
                sc = self.all_skylanders.setdefault("SuperChargers",[])
                if not any(s["path"]==entry["path"] for s in sc):
                    sc.append(entry)
        total=sum(len(v) for v in data.values())
        self._status_var.set(f"✔ {total} Skylanders  ·  {folder}"); self._refresh_active_tab()

    # ── RENDERING ────────────────────────────

    def _refresh_active_tab(self):
        # Restore tab bar if hidden by randomizer
        if not self.tab_bar.winfo_ismapped():
            self.tab_bar.pack(fill="x", padx=16, pady=(0,4), before=self._content_container)
        tab=self.active_tab.get(); query=self.search_var.get().lower().strip()
        if tab=="Vehicles:Villain": self._render_villain_vehicles(); return
        if tab.startswith("Vehicles"): self._render_vehicles(tab,query); return
        if tab=="SwapForce:Mix": self._render_swapforce_mixer(); return
        if tab=="Favorites:Combos": self._render_favorites_combos(); return
        favs=set(self.cfg.get("favorites",[]))
        el_filter = self._el_filter.get() if hasattr(self, "_el_filter") else ""
        def el_match(sky):
            if not el_filter: return True
            return detect_element(sky["name"], sky.get("path","")) == el_filter
        if tab=="Favorites":
            items=[dict(sky,game=game) for game,skys in self.all_skylanders.items() for sky in skys if sky["path"] in favs and (not query or query in sky["name"].lower()) and el_match(sky)]
            # SF combos shown separately via dropdown — not mixed into main list
        elif tab=="All":
            items=[dict(sky,game=game) for game,skys in self.all_skylanders.items() for sky in skys if (not query or query in sky["name"].lower()) and el_match(sky)]
        else:
            items=[dict(sky,game=tab) for sky in self.all_skylanders.get(tab,[]) if (not query or query in sky["name"].lower()) and el_match(sky)]
        self._render_vlist(items,favs)

    def _get_tab_frame(self, tab):
        """Get or create a persistent cached frame for this tab."""
        if tab not in self._tab_frames:
            f = tk.Frame(self._content_container, bg=PANEL_BG)
            self._tab_frames[tab] = f
        return self._tab_frames[tab]

    def _show_tab_frame(self, tab):
        """Hide ALL cached frames, show only the tab's frame. Returns the frame."""
        # Hide every cached frame to ensure none bleed through
        for f in self._tab_frames.values():
            try: f.pack_forget()
            except: pass
        # Also hide the default self.content if it's separate
        try:
            if hasattr(self, '_default_content') and self._default_content:
                self._default_content.pack_forget()
        except: pass
        frame = self._get_tab_frame(tab)
        frame.pack(fill="both", expand=True)
        self._active_frame = frame
        self.content = frame
        return frame

    def _render_vlist(self,items,favs):
        tab = self.active_tab.get()
        frame = self._show_tab_frame(tab)

        # Reuse VirtualList if it exists and items haven't changed type
        existing_vlist = getattr(frame, "_vlist", None)
        if existing_vlist and existing_vlist.winfo_exists() and not isinstance(existing_vlist, VehicleList):
            existing_vlist.update_items(items)
            self._vlist = existing_vlist
            return

        # Full rebuild for this frame
        for w in frame.winfo_children(): w.destroy()
        frame._vlist = None
        self._vlist = None

        if not items:
            self._show_empty_state(tab)
            return

        vl = VirtualList(frame, items, favs,
                         on_select=self._on_select,
                         on_fav_toggle=self._toggle_favorite,
                         game_colors=GAME_COLORS, app_ref=self)
        vl.pack(fill="both", expand=True)
        frame._vlist = vl
        self._vlist = vl

    def _render_vehicles(self,tab,query=""):
        frame = self._show_tab_frame(tab)
        for w in frame.winfo_children(): w.destroy()
        self.content = frame
        self._vlist=None
        vtypes=[tab.split(":")[1]] if ":" in tab else ["Land","Sky","Sea"]
        # Build flexible name lookup — normalize hyphens/spaces/case
        def norm(s): return s.lower().replace("-","").replace(" ","").replace("_","")
        sc_files_raw = self.all_skylanders.get("SuperChargers",[])
        sc_files = {norm(sky["name"]): sky for sky in sc_files_raw}
        # Add aliases for known naming variants
        aliases = {
            "scalebiter": "scale biter",
            "darkcryptcrusher": "dark crypt crusher",
            "darkhostreak": "dark hot streak",
            "burncycle": "burn cycle",
        }
        for alias, real in aliases.items():
            if alias not in sc_files:
                # Try finding by partial match
                for k, v in list(sc_files.items()):
                    if real.replace(" ","") in k or k in real.replace(" ",""):
                        sc_files[alias] = v
                        break
        favs=set(self.cfg.get("favorites",[]))
        rows=[]
        for vtype in vtypes:
            rows.append({"type":"header","vtype":vtype,"label":f"{vtype} Vehicles"})
            for vname in VEHICLES.get(vtype,[]):
                if query and query not in vname.lower(): continue
                rows.append({"type":"vehicle","vtype":vtype,"label":vname,"sky_entry":sc_files.get(norm(vname))})
        if not any(r["type"]=="vehicle" for r in rows): self._show_empty_state(tab); return
        vl=VehicleList(self.content,rows,favs,on_select=self._on_select,on_fav_toggle=self._toggle_favorite,on_locate=self._locate_vehicle)
        vl.pack(fill="both",expand=True); self._vlist=vl

    def _render_villain_vehicles(self):
        """Show villain vehicles tab — unlocked in-game via trophies, no figures."""
        frame = self._show_tab_frame("Vehicles:Villain")
        for w in frame.winfo_children(): w.destroy()
        self.content = frame
        self._vlist = None

        outer = tk.Frame(frame, bg=PANEL_BG)
        outer.pack(fill="both", expand=True)

        # Scrollable
        canvas = tk.Canvas(outer, bg=PANEL_BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.bind("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
        inner.bind("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
        inner = tk.Frame(canvas, bg=PANEL_BG)
        cwin = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cwin, width=e.width))
        canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
        inner.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        # Header
        tk.Label(inner, text="💀  Villain Vehicles",
                 bg=PANEL_BG, fg=TEXT_PRI,
                 font=("Segoe UI",14,"bold")).pack(anchor="w", padx=16, pady=(14,2))
        tk.Label(inner, text="These vehicles have no physical figures — they unlock in-game via Trophies.",
                 bg=PANEL_BG, fg=TEXT_SEC,
                 font=("Segoe UI",8)).pack(anchor="w", padx=16, pady=(0,8))
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,10))

        # Group by trophy
        from collections import OrderedDict
        groups = OrderedDict()
        for vv in VILLAIN_VEHICLES:
            groups.setdefault(vv["unlock"], []).append(vv)

        for trophy, vehicles in groups.items():
            color = TROPHY_COLORS.get(trophy, ACCENT)

            # Trophy header
            thdr = tk.Frame(inner, bg=PANEL_BG)
            thdr.pack(fill="x", padx=16, pady=(4,2))
            tk.Frame(thdr, bg=color, width=4).pack(side="left", fill="y")
            tk.Label(thdr, text=f"  {trophy}",
                     bg=PANEL_BG, fg=color,
                     font=("Segoe UI",10,"bold")).pack(side="left", padx=(4,0))

            for vv in vehicles:
                row = tk.Frame(inner, bg=CARD_BG, pady=8, padx=0)
                row.pack(fill="x", padx=16, pady=2)

                # Color strip
                tk.Frame(row, bg=color, width=4).pack(side="left", fill="y")

                content_frame = tk.Frame(row, bg=CARD_BG)
                content_frame.pack(side="left", fill="x", expand=True, padx=10)

                # Vehicle name + terrain badge
                name_row = tk.Frame(content_frame, bg=CARD_BG)
                name_row.pack(anchor="w")
                tk.Label(name_row, text=vv["name"],
                         bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",10,"bold")).pack(side="left")
                terrain_color = {"Land":"#8B6914","Sea":"#2980b9","Sky":"#85c1e9"}.get(vv["terrain"],ACCENT)
                tk.Label(name_row, text=f"  {vv['terrain']}",
                         bg=terrain_color, fg="#fff",
                         font=("Segoe UI",7,"bold"),
                         padx=4, pady=1).pack(side="left", padx=(6,0))

                # Villain driver
                tk.Label(content_frame, text=f"Driver: {vv['villain']}",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(anchor="w")

                # Unlock method
                unlock_row = tk.Frame(content_frame, bg=CARD_BG)
                unlock_row.pack(anchor="w", pady=(2,0))
                tk.Label(unlock_row, text="Unlocked by: ",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",8)).pack(side="left")
                tk.Label(unlock_row, text=vv["unlock"],
                         bg=CARD_BG, fg=color,
                         font=("Segoe UI",8,"bold")).pack(side="left")

                # No load button — these can't be loaded (no .sky file)
                tk.Label(row, text="No Figure",
                         bg=CARD_BG, fg=TEXT_SEC,
                         font=("Segoe UI",7), padx=8).pack(side="right")

    def _render_swapforce_mixer(self):
        frame = self._show_tab_frame("SwapForce:Mix")
        for w in frame.winfo_children(): w.destroy()
        self.content = frame
        self._vlist=None
        sf_files=self.all_skylanders.get("Swap Force",[])
        if not sf_files:
            tk.Label(self.content,text="No Swap Force .sky files found.",bg=PANEL_BG,fg=TEXT_SEC,font=("Segoe UI",11),justify="center").pack(expand=True); return

        tops,bottoms=[],[]
        for sky in sf_files:
            name=sky["name"]
            display=re.sub("\\s*\\((Top|Bottom)\\)\\s*","",name,flags=re.IGNORECASE).strip()
            if "(top)" in name.lower(): tops.append({"display":display,"path":sky["path"]})
            elif "(bottom)" in name.lower(): bottoms.append({"display":display,"path":sky["path"]})
        tops=sorted(tops,key=lambda x:x["display"]); bottoms=sorted(bottoms,key=lambda x:x["display"])
        self._sf_tops=tops; self._sf_bottoms=bottoms
        self._sf_top_sel={"display":tops[0]["display"],"path":tops[0]["path"]} if tops else {}
        self._sf_bot_sel={"display":bottoms[0]["display"],"path":bottoms[0]["path"]} if bottoms else {}

        _sf_canvas=tk.Canvas(self.content,bg=PANEL_BG,highlightthickness=0)
        _sf_sb=ttk.Scrollbar(self.content,orient="vertical",command=_sf_canvas.yview)
        _sf_canvas.configure(yscrollcommand=_sf_sb.set)
        _sf_sb.pack(side="right",fill="y")
        _sf_canvas.pack(side="left",fill="both",expand=True)
        outer=tk.Frame(_sf_canvas,bg=PANEL_BG)
        _sf_win=_sf_canvas.create_window((0,0),window=outer,anchor="nw")
        outer.bind("<Configure>",lambda e:_sf_canvas.configure(scrollregion=_sf_canvas.bbox("all")))
        _sf_canvas.bind("<Configure>",lambda e:_sf_canvas.itemconfig(_sf_win,width=e.width))
        def _sf_scroll(e): _sf_canvas.yview_scroll(int(-1*(e.delta/120)),"units")
        _sf_canvas.bind("<MouseWheel>",_sf_scroll)
        outer.bind("<MouseWheel>",_sf_scroll)
        outer.configure(padx=30,pady=20)
        tk.Label(outer,text="Swap Force Editor",bg=PANEL_BG,fg=GAME_COLORS["Swap Force"],font=("Segoe UI",16,"bold")).pack(anchor="w",pady=(10,8))
        tk.Frame(outer,bg=BORDER,height=1).pack(fill="x",pady=(0,16))

        def make_dark_dropdown(parent,label_text,items,sel_ref_key,color):
            row=tk.Frame(parent,bg=PANEL_BG); row.pack(fill="x",pady=6)
            tk.Frame(row,bg=color,width=4).pack(side="left",fill="y")
            card=tk.Frame(row,bg=CARD_BG,pady=8,padx=10); card.pack(side="left",fill="x",expand=True)
            tk.Label(card,text=label_text,bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",9,"bold")).pack(anchor="w")
            sel_row=tk.Frame(card,bg=CARD_BG,cursor="hand2"); sel_row.pack(fill="x",pady=(4,0))
            init=self._sf_top_sel.get("display","") if sel_ref_key=="top" else self._sf_bot_sel.get("display","")
            sel_lbl=tk.Label(sel_row,text=init,bg=CARD_BG,fg=TEXT_PRI,font=("Segoe UI",11),anchor="w",cursor="hand2"); sel_lbl.pack(side="left",fill="x",expand=True)
            tk.Label(sel_row,text="▾",bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",11),cursor="hand2").pack(side="right")

            def open_panel(e=None):
                popup=tk.Toplevel(self); popup.overrideredirect(True); popup.attributes("-topmost",True); popup.configure(bg=BORDER)
                x=card.winfo_rootx(); y=card.winfo_rooty()+card.winfo_height(); w=card.winfo_width()
                popup.geometry(f"{w}x320+{x}+{y}")
                inner=tk.Frame(popup,bg=CARD_BG); inner.pack(fill="both",expand=True,padx=1,pady=1)
                search_var=tk.StringVar()
                sf2=tk.Frame(inner,bg=CARD_BG); sf2.pack(fill="x",padx=6,pady=6)
                tk.Label(sf2,text="🔍",bg=CARD_BG,fg=TEXT_SEC,font=("Segoe UI",10)).pack(side="left",padx=(0,4))
                se=tk.Entry(sf2,textvariable=search_var,bg=DARK_BG,fg=TEXT_PRI,insertbackground=TEXT_PRI,relief="flat",font=("Segoe UI",10)); se.pack(side="left",fill="x",expand=True,ipady=4); se.focus_set()
                tk.Frame(inner,bg=BORDER,height=1).pack(fill="x")
                list_frame=tk.Frame(inner,bg=CARD_BG); list_frame.pack(fill="both",expand=True)
                canvas=tk.Canvas(list_frame,bg=CARD_BG,highlightthickness=0)
                sb2=ttk.Scrollbar(list_frame,orient="vertical",command=canvas.yview); canvas.configure(yscrollcommand=sb2.set)
                canvas.bind("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
                sb2.pack(side="right",fill="y"); canvas.pack(side="left",fill="both",expand=True)
                list_inner=tk.Frame(canvas,bg=CARD_BG)
                list_win=canvas.create_window((0,0),window=list_inner,anchor="nw")
                list_inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
                canvas.bind("<Configure>",lambda e:canvas.itemconfig(list_win,width=e.width))
                def _popup_scroll(e): canvas.yview_scroll(int(-1*(e.delta/120)),"units")
                canvas.bind("<MouseWheel>",_popup_scroll)
                list_inner.bind("<MouseWheel>",_popup_scroll)

                def populate(q=""):
                    for w2 in list_inner.winfo_children(): w2.destroy()
                    for it in [x for x in items if not q or q.lower() in x["display"].lower()]:
                        def make_click(item=it):
                            def click(_=None):
                                if sel_ref_key=="top": self._sf_top_sel=item
                                else: self._sf_bot_sel=item
                                sel_lbl.config(text=item["display"]); update_preview(); popup.destroy()
                            return click
                        ir=tk.Frame(list_inner,bg=CARD_BG,cursor="hand2"); ir.pack(fill="x")
                        if sel_ref_key=="bot":
                            move_type=SWAP_BOTTOM_MOVEMENT.get(it["display"])
                            move_img=_movement_images.get(move_type) if move_type else None
                            if move_img:
                                icon_lbl=tk.Label(ir,image=move_img,bg=CARD_BG,cursor="hand2",padx=6,pady=7)
                                icon_lbl.image=move_img
                                icon_lbl.pack(side="left")
                            else:
                                tk.Label(ir,text=" ",bg=CARD_BG,width=3,cursor="hand2").pack(side="left")
                        il=tk.Label(ir,text=it["display"],bg=CARD_BG,fg=TEXT_PRI,font=("Segoe UI",10),anchor="w",padx=10,pady=7,cursor="hand2"); il.pack(side="left",fill="x",expand=True)
                        clk=make_click(it)
                        ir.bind("<Button-1>",clk); il.bind("<Button-1>",clk)
                        ir.bind("<Enter>",lambda e,r=ir,l=il:(r.config(bg=CARD_HOVER),l.config(bg=CARD_HOVER)))
                        ir.bind("<Leave>",lambda e,r=ir,l=il:(r.config(bg=CARD_BG),l.config(bg=CARD_BG)))
                        il.bind("<Enter>",lambda e,r=ir,l=il:(r.config(bg=CARD_HOVER),l.config(bg=CARD_HOVER)))
                        il.bind("<Leave>",lambda e,r=ir,l=il:(r.config(bg=CARD_BG),l.config(bg=CARD_BG)))
                        ir.bind("<MouseWheel>",_popup_scroll)
                        il.bind("<MouseWheel>",_popup_scroll)

                populate()
                search_var.trace_add("write",lambda *_:populate(search_var.get()))
                popup.bind("<FocusOut>",lambda e: popup.destroy() if popup.winfo_exists() else None)
                se.bind("<Escape>",lambda e:popup.destroy())

            for w2 in (sel_row,sel_lbl): w2.bind("<Button-1>",open_panel)
            return sel_lbl

        gc=GAME_COLORS["Swap Force"]
        self._sf_top_lbl=make_dark_dropdown(outer,"🔝  Top Half",tops,"top",gc)
        self._sf_bot_lbl=make_dark_dropdown(outer,"🔽  Bottom Half",bottoms,"bot",gc)
        tk.Frame(outer,bg=BORDER,height=1).pack(fill="x",pady=(16,0))

        self._sf_preview=tk.Label(outer,text="",bg=PANEL_BG,fg=TEXT_SEC,font=("Segoe UI",9),pady=8); self._sf_preview.pack(anchor="w")

        def update_preview():
            t=self._sf_top_sel.get("display",""); b=self._sf_bot_sel.get("display","")
            move=SWAP_BOTTOM_MOVEMENT.get(b,"")
            move_str=f"  [{move}]" if move else ""
            self._sf_preview.config(text=f"  {t}  (top)   +   {b}  (bottom){move_str}")
        update_preview()

        btn_row=tk.Frame(outer,bg=PANEL_BG); btn_row.pack(anchor="w",pady=(4,10))
        tk.Button(btn_row,text="⬡  Put on Portal",bg=GAME_COLORS["Swap Force"],fg="#fff",relief="flat",cursor="hand2",font=("Segoe UI",11,"bold"),padx=20,pady=8,activebackground="#2ecc71",activeforeground="#fff",command=self._swapforce_load).pack(side="left")

        def fav_combo():
            top_e = self._sf_top_sel if hasattr(self,"_sf_top_sel") else {}
            bot_e = self._sf_bot_sel if hasattr(self,"_sf_bot_sel") else {}
            if not top_e.get("path") or not bot_e.get("path"):
                self._sf_status.config(text="⚠ Select both halves first",fg="#e67e22"); return
            nickname, top_name, bot_name = self._make_combo_name(
                top_e.get("display",""), bot_e.get("display",""))
            # Save to sf_combos in config
            combos = self.cfg.setdefault("sf_combos",[])
            # Check not already saved
            for c in combos:
                if c["top_path"]==top_e["path"] and c["bot_path"]==bot_e["path"]:
                    self._sf_status.config(text=f"Already saved: {nickname}",fg=TEXT_SEC); return
            combos.append({
                "nickname":  nickname,
                "top_name":  top_name,
                "bot_name":  bot_name,
                "top_path":  top_e["path"],
                "bot_path":  bot_e["path"],
                "top_display": top_e.get("display",""),
                "bot_display": bot_e.get("display",""),
            })
            save_config(self.cfg)
            self._sf_status.config(text=f"★ {nickname} saved to combos!",fg="#f5a623")

        tk.Button(btn_row,text="★ Save Combo",bg=PANEL_BG,fg="#f5a623",relief="flat",
                  cursor="hand2",font=("Segoe UI",10),padx=12,pady=8,
                  activebackground=CARD_BG,
                  command=fav_combo).pack(side="left",padx=(8,0))

        def delete_combo():
            top_e=self._sf_top_sel if hasattr(self,"_sf_top_sel") else {}
            bot_e=self._sf_bot_sel if hasattr(self,"_sf_bot_sel") else {}
            combos=self.cfg.get("sf_combos",[])
            before=len(combos)
            self.cfg["sf_combos"]=[c for c in combos
                if not (c["top_path"]==top_e.get("path","") and
                        c["bot_path"]==bot_e.get("path",""))]
            if len(self.cfg["sf_combos"])<before:
                save_config(self.cfg)
                self._sf_status.config(text="✕ Combo removed",fg="#e74c3c")
            else:
                self._sf_status.config(text="No matching combo found",fg=TEXT_SEC)
        tk.Button(btn_row,text="✕ Delete Combo",bg=PANEL_BG,fg="#e74c3c",relief="flat",
                  cursor="hand2",font=("Segoe UI",10),padx=12,pady=8,
                  activebackground=CARD_BG,
                  command=delete_combo).pack(side="left",padx=(4,0))
        self._sf_status=tk.Label(btn_row,text="",bg=PANEL_BG,fg="#3dba6f",font=("Segoe UI",9,"bold"),padx=12); self._sf_status.pack(side="left")

    def _make_combo_name(self, top_display, bot_display):
        """Generate the combined nickname e.g. Blast Zone + Wash Buckler → Blast Buckler"""
        import re as _re2
        t = _re2.sub(r"\s*\(Top\)\s*","",top_display,flags=_re2.IGNORECASE).strip()
        b = _re2.sub(r"\s*\(Bottom\)\s*","",bot_display,flags=_re2.IGNORECASE).strip()
        # Nickname: first word of top + last word of bottom
        t_first = t.split()[0] if t.split() else t
        b_last  = b.split()[-1] if b.split() else b
        return f"{t_first} {b_last}", t, b

    def _swapforce_load(self):
        top_entry=self._sf_top_sel if hasattr(self,"_sf_top_sel") else {}
        bot_entry=self._sf_bot_sel if hasattr(self,"_sf_bot_sel") else {}
        if not top_entry.get("path") or not bot_entry.get("path"):
            self._sf_status.config(text="⚠ Select both top and bottom first",fg="#e67e22"); return
        self._sf_status.config(text="⏳ Loading…",fg=TEXT_SEC)
        host=self.cfg.get("vp_host","localhost"); port=self.cfg.get("vp_port",5678)
        nickname,_,_ = self._make_combo_name(top_entry.get("display",""),bot_entry.get("display",""))
        top_path = top_entry["path"]
        bot_path = bot_entry["path"]
        def run():
            import concurrent.futures as _cf
            # Clear both slots first in parallel
            with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                ex.submit(virtport_clear,1,host,port)
                ex.submit(virtport_clear,2,host,port)
            # Load both slots in parallel for speed
            import concurrent.futures as _cf
            with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                f1=ex.submit(virtport_load,top_path,1,host,port)
                f2=ex.submit(virtport_load,bot_path,2,host,port)
                ok1,err1=f1.result(); ok2,err2=f2.result()
            def done():
                if ok1 and ok2:
                    self._sf_combo_active = True
                    self._sf_status.config(text=f"✔ {nickname} loaded!",fg="#3dba6f")
                else:
                    self._sf_combo_active = False
                    self._sf_status.config(text=f"⚠ Error: {err1 or err2}",fg="#e67e22")
            self.after(0,done)
        threading.Thread(target=run,daemon=True).start()

    def _render_favorites_combos(self):
        """Dedicated full-page view for saved Swap Force combos — Favorites subtab."""
        self._vlist = None
        frame = self._show_tab_frame("Favorites:Combos")
        for w in frame.winfo_children(): w.destroy()
        self.content = frame
        combos = self.cfg.get("sf_combos",[])
        hdr = tk.Frame(self.content, bg=PANEL_BG)
        hdr.pack(fill="x", padx=16, pady=(10,4))
        tk.Label(hdr, text="⬡  Swap Force Combos", bg=PANEL_BG,
                 fg=GAME_COLORS.get("Swap Force","#3dba6f"),
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Label(hdr, text=f"({len(combos)} saved)", bg=PANEL_BG,
                 fg=TEXT_SEC, font=("Segoe UI",9)).pack(side="left", padx=8)
        tk.Frame(self.content, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0,6))
        if not combos:
            tk.Label(self.content,
                     text="No combos saved yet.\nUse ★ Save Combo in the Swap Force Editor tab.",
                     bg=PANEL_BG, fg=TEXT_SEC, font=("Segoe UI",11),
                     justify="center").pack(expand=True)
            return
        lf = tk.Frame(self.content, bg=PANEL_BG); lf.pack(fill="both", expand=True)
        cv = tk.Canvas(lf, bg=PANEL_BG, highlightthickness=0)
        sb = ttk.Scrollbar(lf, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
        inn = tk.Frame(cv, bg=PANEL_BG); cw2 = cv.create_window((0,0), window=inn, anchor="nw")
        inn.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(cw2, width=e.width))
        def _whl(e): cv.yview_scroll(int(-1*(e.delta/120)),"units")
        cv.bind("<MouseWheel>",_whl); inn.bind("<MouseWheel>",_whl)
        def render_all():
            for w in inn.winfo_children(): w.destroy()
            for c in self.cfg.get("sf_combos",[]):
                row = tk.Frame(inn, bg=CARD_BG, cursor="hand2")
                row.pack(fill="x", padx=0, pady=1)
                tk.Frame(row, bg="#4488ff", width=4).pack(side="left", fill="y")
                info = tk.Frame(row, bg=CARD_BG)
                info.pack(side="left", fill="x", expand=True, padx=10, pady=8)
                tk.Label(info, text=f"⬡  {c['nickname']}", bg=CARD_BG, fg=TEXT_PRI,
                         font=("Segoe UI",11,"bold"), anchor="w").pack(anchor="w")
                tk.Label(info, text=f"{c.get('top_name','')}  +  {c.get('bot_name','')}",
                         bg=CARD_BG, fg=TEXT_SEC, font=("Segoe UI",8), anchor="w").pack(anchor="w")
                def del_c(combo=c):
                    self.cfg["sf_combos"]=[x for x in self.cfg.get("sf_combos",[])
                        if x.get("top_path","")!=combo.get("top_path","")
                        or x.get("bot_path","")!=combo.get("bot_path","")]
                    save_config(self.cfg); render_all()
                del_btn = tk.Label(row, text="✕", bg="#3a0a0a", fg="#e74c3c",
                                   font=("Segoe UI",12), padx=12, cursor="hand2")
                del_btn.pack(side="right", pady=4)
                del_btn.bind("<Button-1>", lambda e,f=del_c: f())
                del_btn.bind("<Enter>", lambda e,b=del_btn: b.config(bg="#5a1a1a"))
                del_btn.bind("<Leave>", lambda e,b=del_btn: b.config(bg="#3a0a0a"))
                def load_c(combo=c):
                    self._on_select({"name":combo["nickname"],"path":combo["top_path"],
                                     "bot_path":combo.get("bot_path",""),
                                     "is_sf_combo":True,"game":"Swap Force"})
                for w in (row, info) + tuple(info.winfo_children()):
                    w.bind("<Button-1>", lambda e,f=load_c: f())
                    w.bind("<MouseWheel>", _whl)
                    w.bind("<Enter>", lambda e,r=row,i=info: [
                        r.config(bg=CARD_HOVER),i.config(bg=CARD_HOVER)]+
                        [x.config(bg=CARD_HOVER) for x in i.winfo_children()])
                    w.bind("<Leave>", lambda e,r=row,i=info: [
                        r.config(bg=CARD_BG),i.config(bg=CARD_BG)]+
                        [x.config(bg=CARD_BG) for x in i.winfo_children()])
        render_all()

    def _show_empty_state(self,tab=None):
        # content is already set to the active frame by _show_tab_frame
        for w in self.content.winfo_children(): w.destroy()
        if tab=="Favorites":
            msg="No favorited Skylanders yet.\nClick ☆ on any Skylander to add one."
        elif not self.cfg.get("root_folder"):
            msg="Click  📁 Folder  to point to your Skylanders directory."
        else:
            msg="No Skylanders found here."
        tk.Label(self.content,text=msg,bg=PANEL_BG,fg=TEXT_SEC,font=("Segoe UI",11),justify="center").pack(expand=True)


    def _focus_cemu_portal(self):
        """Bring Cemu's Emulated USB Devices window to the front."""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            found = []
            def enum_cb(hwnd, lparam):
                buf = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, buf, 256)
                title = buf.value.lower()
                if "emulated usb" in title or "skylander" in title:
                    found.append(hwnd)
                return True
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
            if found:
                user32.ShowWindow(found[0], 9)
                user32.SetForegroundWindow(found[0])
                self._status_var.set("✔ Cemu portal window opened")
            else:
                self._status_var.set("⚠ Cemu portal window not found — open it in Cemu → Tools")
        except Exception as e:
            self._status_var.set("⚠ Could not find Cemu window")


    def _on_select(self,sky):
        if not sky: return
        host = self.cfg.get("vp_host","localhost")
        port = self.cfg.get("vp_port",5678)
        name = sky["name"]
        path = sky.get("path","")
        game = sky.get("game","")
        was_combo = getattr(self,"_sf_combo_active",False)

        # ── SF combo: load top→slot1, bottom→slot2 ──────────────────────────
        if sky.get("is_sf_combo"):
            top_path = path
            bot_path = sky.get("bot_path","")
            self._status_var.set(f"⏳ Loading {name}…")
            self.clip_lbl.config(text="⏳")
            def run_combo():
                import concurrent.futures as _cf
                # Clear both slots first in parallel
                with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                    ex.submit(virtport_clear,1,host,port)
                    ex.submit(virtport_clear,2,host,port)
                # Load top first, then bottom (sequential prevents race condition)
                ok1,_ = virtport_load(top_path, 1, host, port)
                ok2,_ = virtport_load(bot_path, 2, host, port) if bot_path else (False,"")
                def done():
                    if ok1 and ok2:
                        self._sf_combo_active = True
                        self._status_var.set(f"✔ {name} loaded!")
                        self.clip_lbl.config(text="✔ Loaded!")
                        self._toast(f"✔  {name}")
                    else:
                        self._status_var.set(f"⚠ {name} — failed")
                        self.clip_lbl.config(text="⚠ Failed")
                    self.after(3000, lambda: self.clip_lbl.config(text=""))
                self.after(0, done)
            threading.Thread(target=run_combo, daemon=True).start()
            return

        # ── Determine correct slot for this Skylander ────────────────────────
        is_sf_bottom = "(bottom)" in name.lower() or "(bottom)" in path.lower().replace("\\","/")
        slot = get_portal_slot(
            name=name, path=path, game=game,
            is_sf_bottom=is_sf_bottom,
            user_slot=self._active_slot
        )

        # ── Determine what slots need clearing ───────────────────────────────
        clear_slots = should_clear_slots(slot, was_combo)

        self._status_var.set(f"⏳ Loading {name}…")
        self.clip_lbl.config(text="⏳")
        self._sf_combo_active = False

        def run():
            # Clear slots in parallel, wait for completion before loading
            if clear_slots:
                import concurrent.futures as _cf
                with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                    futs = [ex.submit(virtport_clear, s, host, port) for s in clear_slots]
                    _cf.wait(futs)
                ok, err = virtport_load(path, slot=slot, host=host, port=port)
            else:
                ok, err = virtport_load(path, slot=slot, host=host, port=port)
            # If this is an SF top, mark combo active (bottom still on slot 2)
            if is_sf_bottom:
                pass  # loading a bottom alone — don't mark as combo
            def done():
                if ok:
                    self._status_var.set(f"✔ {name} → slot {slot}")
                    self.clip_lbl.config(text="✔ Loaded!")
                    self._toast(f"✔  {name}")
                else:
                    self._status_var.set(f"⚠ Failed: {err}")
                    self.clip_lbl.config(text="⚠ Failed")
                self.after(3000, lambda: self.clip_lbl.config(text=""))
            self.after(0, done)
        threading.Thread(target=run, daemon=True).start()

    def _toast(self,msg):
        t=tk.Toplevel(self); t.overrideredirect(True); t.attributes("-topmost",True); t.configure(bg="#1a2540")
        x=self.winfo_x()+self.winfo_width()//2-210; y=self.winfo_y()+self.winfo_height()-80
        t.geometry(f"420x42+{x}+{y}")
        tk.Label(t,text=msg,bg="#1a2540",fg="#3dba6f",font=("Segoe UI",10,"bold"),pady=10).pack(fill="both",expand=True)
        t.after(2000,t.destroy)

    def _locate_vehicle(self,row_idx,vname):
        path=filedialog.askopenfilename(title=f"Locate {vname}.sky",filetypes=[("Skylander files","*.sky"),("All files","*.*")],initialdir=self.cfg.get("root_folder") or os.path.expanduser("~"))
        if not path: return
        sky_entry={"name":os.path.splitext(os.path.basename(path))[0],"path":path}
        if isinstance(self._vlist,VehicleList): self._vlist.update_row_found(row_idx,sky_entry)
        # Add to in-memory list
        self.all_skylanders.setdefault("SuperChargers",[]).append(sky_entry)
        # Save to config so it persists across restarts
        manual = self.cfg.setdefault("manual_vehicles",[])
        # Avoid duplicates
        if not any(m["path"]==path for m in manual):
            manual.append({"name":sky_entry["name"],"path":path})
        save_config(self.cfg)
        save_cache(self.cfg["root_folder"],self.all_skylanders)

    def _toggle_favorite(self,path):
        favs=self.cfg.setdefault("favorites",[])
        if path in favs: favs.remove(path)
        else: favs.append(path)
        save_config(self.cfg)
        if self._vlist: self._vlist.refresh_favorites(set(favs))
        elif self.active_tab.get()=="Favorites": self._refresh_active_tab()

if __name__=="__main__":
    app = SkylandersPortalApp()
    def on_close():
        if KEYBOARD_OK:
            try: _keyboard.unhook_all()
            except Exception: pass
        app.destroy()
    app.protocol("WM_DELETE_WINDOW", on_close)
    app.mainloop()
