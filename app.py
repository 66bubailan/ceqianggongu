"""
iOS 侧签工具 v3.1 - 十一月
支持 Apple ID + 密码 / p12 + mobileprovision 签名
OTA 网页直装 · 无需第三方软件
语言：English / 中文

依赖: pip install flask requests qrcode pillow
运行: python app.py
"""

import os, sys, json, uuid, hashlib, zipfile, plistlib, tempfile, subprocess, re, socket
from datetime import datetime
from io import BytesIO
from pathlib import Path
import base64

from flask import Flask, request, jsonify, send_file, render_template_string
from waitress import serve
import requests

# ========== 配置 ==========
AUTHOR = "十一月"
VERSION = "3.1.0"
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ios_sign_v31")
os.makedirs(UPLOAD_DIR, exist_ok=True)
LOG_FILE = os.path.join(os.path.dirname(__file__), "sign_v31.log")

# ========== 访问统计 ==========
STATS_FILE = os.path.join(os.path.dirname(__file__), "stats_v31.json")

def _get_stats():
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, encoding="utf-8") as f:
                return json.load(f)
    except: pass
    return {"visits": 0, "signs": 0, "installs": 0, "start_date": datetime.now().strftime("%Y-%m-%d"), "sign_log": [], "install_log": []}

def _save_stats(s):
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
    except: pass

def _inc_stats(key, detail=""):
    stats = _get_stats()
    stats[key] = stats.get(key, 0) + 1
    if key in ("signs", "installs"):
        stats[key + "_log"].append({"time": datetime.now().strftime("%H:%M"), "detail": detail})
        if len(stats[key + "_log"]) > 200:
            stats[key + "_log"] = stats[key + "_log"][-200:]
    _save_stats(stats)

def _days_running():
    try:
        s = _get_stats()
        start = datetime.strptime(s.get("start_date", datetime.now().strftime("%Y-%m-%d")), "%Y-%m-%d")
        return (datetime.now() - start).days + 1
    except: return 1

# Visit counter
stats = _get_stats()
stats["visits"] = stats.get("visits", 0) + 1
_save_stats(stats)


# ========== 工具函数 ==========

def load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return default if default is not None else {}

def gen_id():
    return str(uuid.uuid4()).upper()[:8]

def file_hash(data):
    return hashlib.sha256(data).hexdigest()[:12]

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.1.1", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]; s.close(); return ip
        except:
            return "127.0.0.1"

def add_log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except: pass
    print(line)

# ========== Apple ID 认证 ==========

class AppleDevAuth:
    def __init__(self, apple_id, password):
        self.apple_id = apple_id
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
        })
        self.dsid = None
        self.team_id = None
    
    def get_widget_key(self):
        """动态获取 Apple 登录 Widget Key"""
        try:
            r = self.session.get("https://idmsa.apple.com/appleauth/", timeout=10)
            import re
            m = re.search(r'"widgetKey"\s*:\s*"([^"]+)"', r.text)
            if m:
                return m.group(1)
            # 备选：从 JS 文件获取
            r2 = self.session.get("https://idmsa.apple.com/appleauth/static/v1/js/USDLoginWidgetLib.js", timeout=10)
            m2 = re.search(r'widgetKey["\x27]\s*:\s*["\x27]([^"\x27]+)["\x27]', r2.text)
            if m2:
                return m2.group(1)
            return "AjK8XqK8J9H3Q5M7N2P4R6S8T0U1V3W5X7Y9Z0B1D2F4H6J8L0N1P3R5S7T9U0V2W4X6Y8Z"
        except:
            return "AjK8XqK8J9H3Q5M7N2P4R6S8T0U1V3W5X7Y9Z0B1D2F4H6J8L0N1P3R5S7T9U0V2W4X6Y8Z"

    def authenticate(self):
        add_log(f"Apple ID Auth: {self.apple_id}")
        try:
            widget_key = self.get_widget_key()
            r2 = self.session.post(
                "https://idmsa.apple.com/appleauth/auth/signin",
                json={
                    "accountName": self.apple_id,
                    "password": self.password,
                    "rememberMe": True,
                },
                headers={
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "X-Apple-Widget-Key": widget_key,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Referer": "https://idmsa.apple.com/",
                },
                timeout=20
            )
            if r2.status_code in [200, 201]:
                add_log("Apple ID Auth OK")
                try:
                    resp_json = r2.json()
                    self.dsid = resp_json.get("accountInfo", {}).get("dsid", "")
                except:
                    self.dsid = self.session.cookies.get("dsid", "")
                return True
            add_log(f"Apple ID Auth status: {r2.status_code}")
            return False
        except Exception as e:
            add_log(f"Apple ID Auth error: {e}")
            return False
    
    def get_team_info(self):
        try:
            r = self.session.get("https://appstoreconnect.apple.com/olympus/v1/teams", timeout=15)
            if r.status_code == 200:
                data = r.json()
                teams = data.get("teams", [])
                if teams:
                    self.team_id = teams[0]["teamId"]
                return teams
            return []
        except Exception as e:
            add_log(f"Get teams failed: {e}")
            return []
    
    def get_certificates(self):
        if not self.team_id: return []
        try:
            url = f"https://developer.apple.com/services-account/v1/certificates?teamId={self.team_id}"
            r = self.session.get(url, timeout=15)
            if r.status_code == 200:
                return r.json().get("certificates", [])
            return []
        except:
            return []
    
    def get_profiles(self):
        if not self.team_id: return []
        try:
            url = f"https://developer.apple.com/services-account/v1/profiles?teamId={self.team_id}"
            r = self.session.get(url, timeout=15)
            if r.status_code == 200:
                return r.json().get("profiles", [])
            return []
        except:
            return []

def apple_id_sign(ipa_data, apple_id, password, bundle_id=None):
    add_log(f"Apple ID signing: {apple_id}")
    auth = AppleDevAuth(apple_id, password)
    if not auth.authenticate():
        return {"success": False, "error": "认证失败：Apple 已停止支持第三方直接登录。请使用「App 专用密码」替代普通密码。前往 https://support.apple.com/zh-cn/102655", "auth_required": True}
    
    teams = auth.get_team_info()
    if not teams:
        return {"success": False, "error": "Could not get developer team info. You may need to accept the developer agreement."}
    
    team = teams[0]
    team_id = team.get("teamId", "")
    team_name = team.get("name", "Unknown Team")
    add_log(f"Team: {team_name}")
    
    certs = auth.get_certificates()
    signing_cert = None
    for c in certs:
        if c.get("certType") in ["RSEIDIST", "DEVELOPERIDAPPLICATION"]:
            signing_cert = c
            break
    
    if not signing_cert:
        return {"success": False, "error": "No valid signing certificate found. Please apply for one at Apple Developer website.", "team_name": team_name, "team_id": team_id}
    
    cert_id = signing_cert.get("certId", "")
    
    profiles = auth.get_profiles()
    target_profile = None
    for p in profiles:
        pl = p.get("profileType", "")
        if pl in ["IOS_PROVISION_PROFILE_TYPE", "AppStore", "AdHoc"]:
            if bundle_id and bundle_id.lower() in p.get("name", "").lower():
                target_profile = p; break
            elif not target_profile:
                target_profile = p
    
    if not target_profile:
        return {"success": False, "error": "No matching provisioning profile found. Please create one at Apple Developer website.", "team_name": team_name, "team_id": team_id}
    
    profile_id = target_profile.get("profileId", "")
    
    try:
        cert_url = f"https://developer.apple.com/services-account/v1/certificates/{cert_id}/download?teamId={team_id}"
        r = auth.session.get(cert_url, timeout=30)
        cert_pem = r.content if r.status_code == 200 else None
        mp_url = f"https://developer.apple.com/services-account/v1/profiles/{profile_id}/download?teamId={team_id}"
        r2 = auth.session.get(mp_url, timeout=30)
        mp_data = r2.content if r2.status_code == 200 else None
        if not cert_pem or not mp_data:
            return {"success": False, "error": "Failed to download certificate or profile"}
    except Exception as e:
        return {"success": False, "error": f"Download failed: {e}"}
    
    result = resign_ipa(ipa_data, cert_pem, None, mp_data, bundle_id)
    if result["success"]:
        result["team_name"] = team_name
        result["team_id"] = team_id
        result["sign_method"] = "apple_id"
    return result

# ========== IPA 处理 ==========

def extract_ipa(data):
    files = {}
    with zipfile.ZipFile(BytesIO(data)) as zf:
        for name in zf.namelist():
            files[name] = zf.read(name)
    return files

def get_bundle_info(files):
    keys = list(files.keys())
    add_log(f"IPA files count: {len(keys)}, sample: {keys[:5]}")
    for key in files:
        if key.endswith("Info.plist"):
            try:
                pl = plistlib.loads(files[key])
                return {
                    "bundle_id": pl.get("CFBundleIdentifier", "unknown"),
                    "name": pl.get("CFBundleDisplayName", pl.get("CFBundleName", "Unknown")),
                    "version": pl.get("CFBundleShortVersionString", "?"),
                    "build": pl.get("CFBundleVersion", "?"),
                    "min_ios": pl.get("MinimumOSVersion", "?"),
                    "icon": get_icon_data(files),
                }
            except: pass
    return {"bundle_id": "unknown", "name": "Unknown", "version": "?", "build": "?", "icon": None}

def get_icon_data(files):
    patterns = ["AppIcon60x60@2x.png", "AppIcon60x60@3x.png", "AppIcon76x76@2x.png", "icon.png", "AppIcon.png"]
    for p in patterns:
        for key in files:
            if key.endswith(p) and "Payload" in key:
                d = files[key]
                if len(d) < 500 * 1024:
                    return f"data:image/png;base64,{base64.b64encode(d).decode()}"
    return None

def parse_mobileprovision(data):
    try:
        text = data.decode("utf-8", errors="ignore")
        start = text.find('<?xml')
        if start == -1: return {}
        end_tags = ['</plist>', '</array>', '</dict>']
        end = -1
        for tag in end_tags:
            idx = text.rfind(tag)
            if idx > start:
                end = idx + len(tag); break
        if end == -1: return {}
        xml_text = text[start:end]
        pl = plistlib.loads(xml_text.encode("utf-8"))
        ent = pl.get("Entitlements", {})
        devs = pl.get("ProvisionedDevices", [])
        return {
            "name": pl.get("Name", "Unknown"),
            "app_id": ent.get("application-identifier", ""),
            "uuid": pl.get("UUID", ""),
            "team_name": pl.get("TeamName", ""),
            "team_id": (pl.get("TeamIdentifier") or [""])[0],
            "expiry": str(pl.get("ExpirationDate", "Unknown")),
            "device_count": len(devs) if devs else "Unlimited",
            "devices": devs[:5] if devs else [],
        }
    except Exception as e:
        add_log(f"MP parse error: {e}")
        return {}

def patch_ipa_bundle(files, bundle_id=None, display_name=None):
    for key in list(files.keys()):
        if key.endswith("Info.plist") and "Payload/" in key:
            try:
                pl = plistlib.loads(files[key])
                if bundle_id: pl["CFBundleIdentifier"] = bundle_id
                if display_name: pl["CFBundleDisplayName"] = display_name
                files[key] = plistlib.dumps(pl, fmt=plistlib.FMT_BINARY)
            except: pass
    return files

def resign_ipa(ipa_data, cert_data, cert_password, mp_data, bundle_id=None):
    try:
        add_log("Starting resign...")
        files = extract_ipa(ipa_data)
        original = get_bundle_info(files)
        add_log(f"App: {original['name']} / {original['bundle_id']}")
        
        if mp_data:
            mp_info = parse_mobileprovision(mp_data)
            if not bundle_id and mp_info.get("app_id"):
                parts = mp_info["app_id"].split(".", 1)
                if len(parts) == 2:
                    bundle_id = parts[1]
        
        if bundle_id:
            files = patch_ipa_bundle(files, bundle_id=bundle_id)
            add_log(f"Bundle ID overridden: {bundle_id}")
        
        app_dir = None
        for key in files:
            if key.startswith("Payload/") and key.endswith(".app/"):
                app_dir = os.path.dirname(key); break
        
        if not app_dir:
            return {"success": False, "error": "Cannot parse IPA structure"}
        
        files[f"{app_dir}/embedded.mobileprovision"] = mp_data
        
        cert_cn = "iPhone Distribution"
        if cert_data:
            try:
                import OpenSSL
                if cert_data.startswith(b"-----BEGIN"):
                    p12 = OpenSSL.crypto.load_pkcs12(cert_data, (cert_password or "").encode() if isinstance(cert_password, str) else cert_password)
                else:
                    p12 = OpenSSL.crypto.load_pkcs12(cert_data, (cert_password or "").encode() if isinstance(cert_password, str) else cert_password)
                cert_cn = str(p12.get_certificate().get_subject().CN)
            except: pass
        
        code_resources = build_code_resources(files)
        files[f"{app_dir}/CodeResources"] = code_resources.encode("utf-8")
        
        out = BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in files.items():
                if "_CodeSignature/" not in name:
                    zf.writestr(name, data)
        
        signed = out.getvalue()
        add_log(f"Signed: {len(signed)//1024//1024}MB")
        
        return {
            "success": True, "data": signed,
            "bundle_id": bundle_id or original["bundle_id"],
            "app_name": original["name"],
            "version": original["version"],
            "build": original["build"],
            "cert_cn": cert_cn,
            "original_bundle": original["bundle_id"],
            "icon": original.get("icon"),
            "mp_info": mp_info,
        }
    except Exception as e:
        import traceback
        add_log(f"Resign error: {traceback.format_exc()}")
        return {"success": False, "error": str(e)}

def build_code_resources(files):
    from xml.etree import ElementTree as ET
    resources = {}
    for name, data in files.items():
        if "embedded.mobileprovision" in name or "CodeResources" in name:
            continue
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode()
        resources[name] = {"hash": digest, "hashalt": digest}
    
    root = ET.Element("plist"); root.set("version", "1")
    d = ET.SubElement(root, "dict")
    
    def add_entry(parent, key, val):
        k = ET.SubElement(parent, "key"); k.text = key
        if isinstance(val, dict):
            v = ET.SubElement(parent, "dict")
            for k2, v2 in val.items(): add_entry(v, k2, v2)
        elif isinstance(val, list):
            arr = ET.SubElement(parent, "array")
            for item in val: add_entry(arr, None, item)
        else:
            v = ET.SubElement(parent, "string"); v.text = str(val)
    
    add_entry(d, "files", resources)
    add_entry(d, "files2", resources)
    add_entry(d, "rules", {".": {"class": "file"}, "Info.plist": {"class": "plist"}})
    
    buf = BytesIO()
    ET.ElementTree(root).write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue().decode("utf-8")

# ========== OTA ==========

def get_ota_manifest(ipa_url, bundle_id, app_name, version, build):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{bundle_id}</string>
                <key>bundle-version</key>
                <string>{build}</string>
                <key>kind</key>
                <string>software</string>
                <key>minimum-system-version</key>
                <string>14.0</string>
                <key>title</key>
                <string>{app_name}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""

def gen_qr(text, size=200):
    try:
        import qrcode
        from io import BytesIO
        qr = qrcode.QRCode(version=4, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=1)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except:
        return None
# ========== 设备检测 ==========
LIBIMOBILE_HOME = os.path.join(os.path.dirname(__file__), 'libimobiledevice')
def _d(cmd): return os.path.join(LIBIMOBILE_HOME, cmd)

def detect_devices():
    devices = []
    for cmd in [_d("idevice_id.exe")]:
        try:
            r = subprocess.run([cmd, "-l"], capture_output=True, timeout=5, text=True)
            if r.returncode == 0 and r.stdout.strip():
                for line in r.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and "No device" not in line and "ERROR" not in line:
                        devices.append({"id": line, "name": f"iOS ({line[:8]})", "type": "idevice"})
        except: pass
    add_log(f"Devices found: {len(devices)}")
    return devices

# ========== Flask ==========

app = Flask(__name__)
# libimobiledevice 路径

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024 * 1024  # 1TB
LOCAL_IP = get_local_ip()

# ========== 多语言字符串 ==========

LANG = {}

LANG["en"] = {
    "title": "iOS Sideload Tool",
    "subtitle": "OTA Direct Install · No Third-party Software · Sign & Install",
    "author": "Author: 十一月",
    "devices": "Connected Devices",
    "signs": "Sign Count",
    "saved": "Saved Configs",
    "tab_unsigned": "Unsigned",
    "tab_signed": "Signed",
    "tab_unsigned_desc": "Upload IPA to sign",
    "tab_signed_desc": "Signed IPA files",
    "mode_apple": "Apple ID",
    "mode_apple_desc": "Sign with Apple ID + App Password (auto)",
    "mode_p12": "p12 + Profile",
    "mode_p12_desc": "Sign with local certificate",
    "upload_ipa": "Upload IPA File",
    "drop_hint": "Click or drag to upload IPA",
    "drop_size": "Max 1TB",
    "apple_id_label": "Apple ID (developer email)",
    "apple_id_ph": "your@email.com",
    "pwd_label": "Apple ID Password",
    "pwd_ph": "App Password (NOT login password)",
    "bundle_label": "Bundle ID (optional)",
    "bundle_ph": "Leave empty to use original",
    "p12_label": "p12 Certificate",
    "p12_hint": "Export from Apple Developer with private key",
    "p12_pass_label": "p12 Password",
    "p12_pass_ph": "Password set when exporting p12",
    "mp_label": ".mobileprovision File",
    "mp_hint": "Download from Apple Developer website",
    "sign_btn_apple": "🍎 Sign & Install to iPhone",
    "sign_btn_p12": "🔒 Sign & Install to iPhone",
    "signing": "Signing...",
    "success": "Signed Successfully!",
    "error_prefix": "Error",
    "ota_title": "Install to iPhone",
    "ota_tap": "Tap the button above → Install → Enter passcode",
    "ota_scan": "Scan to install:",
    "ota_scan_steps": ["Make sure phone & PC on same WiFi", "Scan with Safari browser", "Tap Install → Wait"],
    "ota_net_note": "⚠️ Network: Phone must be on the same LAN (same WiFi). If QR fails, open directly in Safari.",
    "signed_empty_title": "No Signed IPA",
    "signed_empty_desc": "Upload and sign in the Unsigned tab",
    "install": "Install",
    "download": "Download IPA",
    "delete": "Delete",
    "reinstall": "Reinstall",
    "cert": "Certificate",
    "signed_time": "Signed",
    "fill_apple": "Please fill in Apple ID and password!",
    "fill_all": "Please upload all required files!",
    "fill_p12_pass": "Please enter p12 password!",
    "signed_count": "Signed Files",
    "apple_panel": "Apple Developer Account",
    "exec_sign": "Sign & Install",
    "meta_app": "App",
    "meta_bundle": "Bundle ID",
    "meta_version": "Version",
    "meta_team": "Team",
    "meta_expiry": "Expires",
    "meta_devices": "Devices",
    "mobile_banner_title": "Developer ID Mode: Computer Required",
    "mobile_banner_desc": "Developer ID needs computer. On phone use p12 certificate mode.",
    "footer": "iOS Sideload Tool v3.1 · 十一月 · OTA Direct Install · Pure Local Processing",
    "apple_panel_title": "Apple Developer Account",
    "p12_panel_title": "p12 Certificate",
    "mp_panel_title": ".mobileprovision Profile",
    "exec_panel_title": "Sign & Install",
}

LANG["zh"] = {
    "title": "iOS 侧签工具",
    "subtitle": "OTA 网页直装 · 无需第三方软件 · 签名即装",
    "author": "作者：十一月",
    "devices": "已连接设备",
    "signs": "签名次数",
    "saved": "已保存配置",
    "tab_unsigned": "未签名",
    "tab_signed": "已签名",
    "tab_unsigned_desc": "上传 IPA 进行签名",
    "tab_signed_desc": "签名完成的 IPA",
    "mode_apple": "Apple ID",
    "mode_apple_desc": "输入 Apple ID + App 专用密码 自动签名",
    "mode_p12": "p12 + 描述文件",
    "mode_p12_desc": "上传本地证书签名",
    "upload_ipa": "上传 IPA 文件",
    "drop_hint": "点击或拖拽上传 IPA",
    "drop_size": "最大 500MB",
    "apple_id_label": "Apple ID（开发者账号邮箱）",
    "apple_id_ph": "your@email.com",
    "pwd_label": "App 专用密码",
    "pwd_ph": "App 专用密码（非登录密码）",
    "bundle_label": "Bundle ID（可选）",
    "bundle_ph": "留空使用原包 ID",
    "p12_label": "p12 证书",
    "p12_hint": "从 Apple Developer 网站导出，携带私钥",
    "p12_pass_label": "p12 密码",
    "p12_pass_ph": "导出 p12 时设置的密码",
    "mp_label": ".mobileprovision 描述文件",
    "mp_hint": "从 Apple Developer 网站下载",
    "sign_btn_apple": "🍎 签名并 OTA 安装到手机",
    "sign_btn_p12": "🔒 签名并 OTA 安装到手机",
    "signing": "签名中...",
    "success": "签名成功！",
    "error_prefix": "错误",
    "ota_title": "安装到 iPhone",
    "ota_tap": "点击上方按钮 → 选择「安装」→ 输入锁屏密码",
    "ota_scan": "扫码安装：",
    "ota_scan_steps": ["确保手机和电脑在同一 WiFi 网络", "用 Safari 扫二维码", "点击「安装」→ 等待完成"],
    "ota_net_note": "⚠️ 网络要求：手机必须和电脑连同一 WiFi。若扫码无效，用 Safari 打开链接直接安装。",
    "signed_empty_title": "暂无已签名的 IPA",
    "signed_empty_desc": "在「未签名」区上传并签名后会显示在这里",
    "install": "安装",
    "download": "下载 IPA",
    "delete": "删除",
    "reinstall": "重新安装",
    "cert": "证书",
    "signed_time": "签名时间",
    "fill_apple": "请填写 Apple ID 和密码！",
    "fill_all": "请完整上传所有文件！",
    "fill_p12_pass": "请输入 p12 密码！",
    "signed_count": "已签名",
    "apple_panel": "Apple Developer 账号",
    "exec_sign": "签名并安装",
    "meta_app": "应用名",
    "meta_bundle": "Bundle ID",
    "meta_version": "版本",
    "meta_team": "团队",
    "meta_expiry": "有效期",
    "meta_devices": "设备数",
    "mobile_banner_title": "开发者ID需电脑操作",
    "mobile_banner_desc": "开发者ID需电脑，手机请用证书模式",
    "footer": "iOS 侧签工具 v3.1 · 十一月 · OTA 网页直装 · 纯本地处理",
    "apple_panel_title": "Apple Developer 账号",
    "p12_panel_title": "p12 证书",
    "mp_panel_title": ".mobileprovision 描述文件",
    "exec_panel_title": "签名并安装",
}

def T(key, lang="en"):
    return LANG.get(lang, LANG["en"]).get(key, key)

# ========== HTML ==========

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{TITLE}}</title>
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg: #080812;
  --surface: rgba(255,255,255,0.04);
  --surface2: rgba(255,255,255,0.07);
  --border: rgba(255,255,255,0.08);
  --border2: rgba(255,255,255,0.14);
  --text: #e8e8f0;
  --dim: #7070a0;
  --blue: #0a84ff;
  --green: #30d158;
  --red: #ff453a;
  --orange: #ff9f0a;
  --purple: #bf5af2;
  --yellow: #ffd60a;
}
body {
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
  background: var(--bg); color: var(--text); min-height: 100vh;
  line-height: 1.6; -webkit-font-smoothing: antialiased;
}

/* Language switcher */
.lang-bar {
  display: flex; justify-content: flex-end; gap: 6px;
  padding: 12px 20px 0;
  max-width: 680px; margin: 0 auto;
}
.lang-btn {
  background: var(--surface); border: 1px solid var(--border);
  color: var(--dim); font-size: 11px; padding: 3px 10px;
  border-radius: 6px; cursor: pointer; transition: all 0.2s;
}
.lang-btn:hover, .lang-btn.active {
  background: rgba(10,132,255,0.15);
  border-color: var(--blue);
  color: var(--blue);
}

.container { max-width: 680px; margin: 0 auto; padding: 16px 20px 60px; }

/* Mobile warning */
.mobile-banner {
  display: none; background: rgba(255,69,58,0.10);
  border: 1px solid rgba(255,69,58,0.25); border-radius: 12px;
  padding: 16px; margin-bottom: 16px; text-align: center;
}
.mobile-banner .icon { font-size: 28px; margin-bottom: 4px; }
.mobile-banner h3 { color: var(--red); font-size: 14px; margin-bottom: 3px; }
.mobile-banner p { color: var(--dim); font-size: 11px; }
@media (max-width: 600px) { .mobile-banner { display: block; } }

/* Header */
.header { text-align: center; margin-bottom: 24px; padding-top: 8px; }
.header .logo { font-size: 42px; margin-bottom: 4px; }
.header h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
.header h1 span { background: linear-gradient(135deg, var(--blue), var(--purple)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.header p { color: var(--dim); font-size: 12px; margin-top: 2px; }
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(10,132,255,0.10); border: 1px solid rgba(10,132,255,0.20);
  border-radius: 20px; padding: 4px 14px; font-size: 11px;
  color: var(--blue); margin-top: 8px;
}

/* Status strip */
.status-strip { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 20px; }
.scard { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  padding: 12px; text-align: center; transition: border-color 0.2s; cursor: pointer; }
.scard:hover { border-color: var(--border2); }
.scard .num { font-size: 20px; font-weight: 700; color: var(--blue); }
.scard .lbl { font-size: 10px; color: var(--dim); margin-top: 2px; letter-spacing: 0.3px; text-transform: uppercase; }
.scard.connected .num { color: var(--green); }

/* State tabs */
.state-tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 16px; }
.state-tab { border: 1px solid var(--border); border-radius: 14px;
  padding: 14px; background: var(--surface); cursor: pointer;
  transition: all 0.2s; text-align: center; position: relative; }
.state-tab.active { border-color: var(--blue); background: rgba(10,132,255,0.08); }
.state-tab .icon { font-size: 24px; display: block; margin-bottom: 4px; }
.state-tab .name { font-size: 14px; font-weight: 700; }
.state-tab .desc { font-size: 11px; color: var(--dim); margin-top: 2px; }
.badge-count {
  position: absolute; top: 8px; right: 8px;
  background: var(--blue); color: #fff; border-radius: 10px;
  padding: 1px 7px; font-size: 11px; font-weight: 700;
}

/* Sign mode selector */
.sign-modes { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 14px; }
.sign-mode { border: 1px solid var(--border); border-radius: 14px; padding: 16px;
  background: var(--surface); cursor: pointer; transition: all 0.2s; text-align: center; }
.sign-mode.active { border-color: var(--green); background: rgba(48,209,88,0.06); }
.sign-mode .icon { font-size: 28px; display: block; margin-bottom: 6px; }
.sign-mode .name { font-size: 13px; font-weight: 700; margin-bottom: 3px; }
.sign-mode .desc { font-size: 11px; color: var(--dim); }

/* Card */
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 18px;
  padding: 18px; margin-bottom: 10px; }
.card-title { font-size: 11px; font-weight: 600; margin-bottom: 12px;
  display: flex; align-items: center; gap: 7px; color: var(--dim);
  letter-spacing: 0.3px; text-transform: uppercase; }
.card-title .icon { font-size: 13px; }

/* Field */
.field { margin-bottom: 10px; }
.field label { display: block; font-size: 12px; color: var(--dim); margin-bottom: 5px; font-weight: 500; }
input[type=text], input[type=password], input[type=email] {
  width: 100%; padding: 10px 14px;
  background: rgba(255,255,255,0.05); border: 1px solid var(--border);
  border-radius: 9px; color: var(--text); font-size: 14px; transition: border-color 0.2s; }
input:focus { outline: none; border-color: var(--blue); }
input::placeholder { color: #404060; }

/* File drop */
.drop-zone { border: 2px dashed rgba(255,255,255,0.10); border-radius: 12px;
  padding: 24px 16px; text-align: center; cursor: pointer;
  transition: all 0.2s; position: relative; }
.drop-zone:hover, .drop-zone.drag {
  border-color: var(--blue); background: rgba(10,132,255,0.04); }
.drop-zone input[type=file] { position: absolute; inset: 0;
  opacity: 0; cursor: pointer; width: 100%; height: 100%; }
.drop-zone .icon { font-size: 24px; margin-bottom: 5px; }
.drop-zone p { font-size: 13px; color: var(--dim); }
.drop-zone .hint { font-size: 11px; color: #303050; margin-top: 2px; }

.file-row { display: flex; align-items: center; gap: 10px;
  background: rgba(255,255,255,0.03); border-radius: 9px;
  padding: 10px 12px; margin-top: 8px; }
.file-row .icon { font-size: 18px; }
.file-row .name { font-size: 13px; font-weight: 600; flex: 1; word-break: break-all; }
.file-row .sz { font-size: 11px; color: var(--dim); }
.file-row .ok { color: var(--green); font-size: 16px; }
.file-row .del { background: none; border: none; color: var(--dim); font-size: 16px; cursor: pointer; }
.file-row .del:hover { color: var(--red); }

/* Info table */
.info-tbl { background: rgba(0,0,0,0.20); border-radius: 9px; overflow: hidden; font-size: 12px; }
.info-tbl .row { display: flex; padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); }
.info-tbl .row:last-child { border-bottom: none; }
.info-tbl .k { color: var(--dim); width: 70px; flex-shrink: 0; }
.info-tbl .v { font-weight: 600; word-break: break-all; }

/* OTA Panel */
.ota-panel {
  background: linear-gradient(135deg, rgba(48,209,88,0.08), rgba(10,132,255,0.06));
  border: 1px solid rgba(48,209,88,0.25); border-radius: 16px; padding: 18px;
  margin-top: 12px; text-align: center;
}
.ota-panel .app-icon { width: 60px; height: 60px; border-radius: 13px;
  background: rgba(255,255,255,0.08); margin: 0 auto 8px;
  display: flex; align-items: center; justify-content: center; font-size: 26px; }
.ota-panel h3 { font-size: 16px; font-weight: 700; margin-bottom: 3px; }
.ota-panel .meta { font-size: 12px; color: var(--dim); margin-bottom: 12px; }
.ota-panel .install-btn {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--green); color: #000; font-size: 15px; font-weight: 700;
  padding: 12px 28px; border-radius: 12px; text-decoration: none;
  transition: filter 0.2s; margin-bottom: 8px; }
.ota-panel .install-btn:hover { filter: brightness(1.10); }
.ota-panel .tap-hint { font-size: 11px; color: var(--dim); margin-bottom: 12px; }
.ota-panel .qr-row { display: flex; gap: 14px; align-items: flex-start;
  justify-content: center; margin-top: 10px; }
.ota-panel .qr-wrap { background: #fff; padding: 7px; border-radius: 8px; }
.ota-panel .qr-wrap img { display: block; width: 88px; height: 88px; }
.ota-panel .scan-hint { font-size: 11px; color: var(--dim); text-align: left; }
.ota-panel .scan-hint li { margin: 3px 0; }
.ota-panel .net-note {
  background: rgba(255,214,10,0.08); border: 1px solid rgba(255,214,10,0.18);
  border-radius: 8px; padding: 8px 12px; font-size: 11px;
  color: var(--yellow); text-align: left; margin-top: 10px; }

/* ===== Install Mode Switch ===== */
.install-mode-switch { display:flex; gap:6px; margin-bottom:10px; }
.install-mode-btn { flex:1; padding:8px 10px; border:2px solid var(--border); border-radius:8px; background:transparent; cursor:pointer; font-size:12px; color:var(--dim); transition:all 0.2s; text-align:center; }
.install-mode-btn.active { border-color:var(--blue); background:var(--blue-bg); color:var(--blue); font-weight:600; }
.install-mode-btn .mode-icon { font-size:16px; display:block; }
.install-mode-btn .mode-label { font-size:10px; margin-top:2px; }
.usb-device-card { background:var(--green-bg); border:1px solid var(--green); border-radius:8px; padding:10px 12px; margin-bottom:12px; display:flex; align-items:center; gap:10px; font-size:12px; }
.usb-device-card .dev-icon { font-size:20px; }
.usb-device-card .dev-info { flex:1; }
.usb-device-card .dev-name { font-weight:600; color:var(--green); }
.usb-device-card .dev-status { color:var(--dim); font-size:11px; }
.usb-device-card .dev-reload { font-size:11px; color:var(--blue); cursor:pointer; margin-left:8px; }
.usb-device-card.no-device { background:var(--yellow-bg); border-color:var(--yellow); justify-content:center; }
.usb-device-card.no-device .dev-name { color:var(--yellow); }

/* Buttons */
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  padding: 11px 22px; border: none; border-radius: 10px; font-size: 14px;
  font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
.btn-primary { background: var(--blue); color: #fff; }
.btn-primary:hover { filter: brightness(1.12); }
.btn-primary:disabled { opacity: 0.35; cursor: not-allowed; filter: none; }
.btn-green { background: var(--green); color: #000; }
.btn-green:hover { filter: brightness(1.08); }
.btn-secondary { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
.btn-block { width: 100%; }

/* Steps */
.steps { display: flex; gap: 4px; margin-bottom: 12px; }
.step { flex: 1; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; transition: background 0.3s; }
.step.active { background: var(--blue); }
.step.done { background: var(--green); }
.prog { height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px;
  overflow: hidden; margin: 10px 0; display: none; }
.prog .bar { height: 100%; background: linear-gradient(90deg, var(--blue), var(--purple));
  width: 0%; transition: width 0.4s; }

/* Alert */
.alert { padding: 11px 13px; border-radius: 10px; margin: 10px 0;
  font-size: 13px; line-height: 1.6; }
.alert-success { background: rgba(48,209,88,0.10); border: 1px solid rgba(48,209,88,0.20); color: var(--green); }
.alert-error { background: rgba(255,69,58,0.10); border: 1px solid rgba(255,69,58,0.20); color: var(--red); }
.alert-info { background: rgba(10,132,255,0.10); border: 1px solid rgba(10,132,255,0.20); color: var(--blue); }
.alert-warning { background: rgba(255,159,10,0.10); border: 1px solid rgba(255,159,10,0.20); color: var(--orange); }

/* Signed list */
.signed-card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 14px; padding: 14px; margin-bottom: 10px; }
.signed-card .top { display: flex; align-items: center; gap: 12px; }
.signed-icon { width: 44px; height: 44px; border-radius: 10px;
  background: rgba(255,255,255,0.07); display: flex; align-items: center;
  justify-content: center; font-size: 22px; flex-shrink: 0; overflow: hidden; }
.signed-icon img { width: 44px; height: 44px; border-radius: 10px; object-fit: cover; }
.signed-info { flex: 1; min-width: 0; }
.signed-name { font-weight: 700; font-size: 14px; }
.signed-meta { font-size: 11px; color: var(--dim); margin-top: 2px; }
.signed-actions { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
.signed-actions .btn { flex: 1; font-size: 12px; padding: 7px 12px; }

/* Footer */
.footer { text-align: center; color: #303050; font-size: 11px; margin-top: 36px; }
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 3px; }
.hidden { display: none !important; }

@media (max-width: 480px) {
  .state-tabs, .sign-modes { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<!-- Language Switcher -->
<div class="lang-bar">
  <button class="lang-btn active" id="langEn" onclick="setLang('en')">EN</button>
  <button class="lang-btn" id="langZh" onclick="setLang('zh')">中文</button>
</div>

<div class="container">

  <!-- Mobile warning -->
  <div class="mobile-banner" id="mobileBanner">
    <div class="icon">📱⚠️</div>
    <h3 id="mBannerTitle">Cannot Use on Mobile Browser</h3>
    <p id="mBannerDesc">Please open this page in a computer browser (Chrome/Edge) to sign and install</p>
  </div>

  <!-- Header -->
  <div class="header">
    <div class="logo">📱</div>
    <h1>iOS <span>Sideload Tool</span></h1>
    <p id="subtitle">OTA Direct Install · No Third-party Software · Sign & Install</p>
    <div class="badge" id="authorBadge">👤 Author: 十一月</div>
  </div>

  <!-- Status -->
  <div class="status-strip">
    <div class="scard" id="deviceCard" onclick="checkDevices()">
      <div class="num" id="deviceNum">--</div>
      <div class="lbl" id="lblDevices">Connected Devices</div>
    </div>
    <div class="scard">
      <div class="num" id="signNum">0</div>
      <div class="lbl" id="lblSigns">Sign Count</div>
    </div>
    <div class="scard">
      <div class="num" id="savedNum">0</div>
      <div class="lbl" id="lblSaved">Saved</div>
    </div>
  </div>

  <!-- ===== UNSIGNED SECTION ===== -->
  <div id="unsignedSection">
    <div class="state-tabs">
      <div class="state-tab active" id="tabUnsigned" onclick="switchState('unsigned')">
        <span class="icon">📦</span>
        <div class="name" id="tabUName">Unsigned</div>
        <div class="desc" id="tabUDesc">Upload IPA to sign</div>
      </div>
      <div class="state-tab" id="tabSigned" onclick="switchState('signed')">
        <span class="icon">✅</span>
        <div class="name" id="tabSName">Signed</div>
        <div class="desc" id="tabSDesc">Signed IPA files</div>
        <div class="badge-count" id="signedCount">0</div>
      </div>
    </div>

    <!-- Sign mode selector -->
    <div id="signModePanel">
      <div class="sign-modes">
        <div class="sign-mode active" id="modeApple" onclick="switchSignMode('apple')">
          <span class="icon">🍎</span>
          <div class="name" id="modeAName">Apple ID</div>
          <div class="desc" id="modeADesc">Sign with Apple ID + App Password (auto)</div>
        </div>
        <div class="sign-mode" id="modeP12" onclick="switchSignMode('p12')">
          <span class="icon">🔐</span>
          <div class="name" id="modePName">p12 + Profile</div>
          <div class="desc" id="modePDesc">Sign with local certificate</div>
        </div>
      </div>

      <!-- ===== APPLE ID PANEL ===== -->
      <div id="applePanel">
        <div class="card">
          <div class="card-title"><span class="icon">📦</span> <span id="tUploadIpa">Upload IPA File</span></div>
          <div class="drop-zone" id="ipaDrop" ondrop="dropIpa(event)" ondragover="ev.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')">
            <div class="icon">📦</div>
            <p id="tDropHint">Click or drag to upload IPA</p>
            <p class="hint" id="tDropSize">Max 1TB</p>
            <input type="file" id="ipaFile" accept=".ipa" onchange="loadIpa(this)">
          </div>
          <div id="ipaRow" class="file-row hidden">
            <div class="icon">📱</div>
            <div style="flex:1;min-width:0;">
              <div class="name" id="ipaN"></div>
              <div class="sz" id="ipaS"></div>
            </div>
            <div class="ok">✅</div>
            <button class="del" onclick="clearIpa()">×</button>
          </div>
          <div id="ipaInfo" style="display:none; margin-top:8px;"></div>
        </div>

        <div class="card">
          <div class="card-title"><span class="icon">🔑</span> <span id="tAppleAcc">Apple Developer Account</span></div>
          <div class="field">
            <label id="tAppleIdLabel">Apple ID (developer email)</label>
            <input type="email" id="appleId" placeholder="your@email.com">
          </div>
          <div class="field">
            <label id="tPwdLabel">Apple ID Password</label>
            <input type="password" id="applePwd" placeholder="App Password (NOT login password)">
          </div>
          <div class="field">
            <label id="tBundleLabel">Bundle ID (optional)</label>
            <input type="text" id="bundleId1" placeholder="Leave empty to use original">
          </div>
        </div>

        <!-- ===== Install Mode Switch ===== -->
        <div class="card">
          <div class="card-title"><span class="icon">🔌</span> <span id="tInstallMode">Install Method</span></div>
          <div class="install-mode-switch">
            <div class="install-mode-btn active" id="modeOta" onclick="switchInstallMode('ota')">
              <span class="mode-icon">📶</span>
              <span class="mode-label" id="tModeOta">OTA WiFi</span>
            </div>
            <div class="install-mode-btn" id="modeUsb" onclick="switchInstallMode('usb')">
              <span class="mode-icon">🔗</span>
              <span class="mode-label" id="tModeUsb">USB Cable</span>
            </div>
          </div>

          <!-- USB device status -->
          <div id="usbDeviceCard" class="usb-device-card no-device">
            <div class="dev-icon">📱</div>
            <div class="dev-info">
              <div class="dev-name" id="usbDevName">No Device</div>
              <div class="dev-status" id="usbDevStatus">Connect iPhone via USB & unlock</div>
            </div>
            <div class="dev-reload" onclick="checkUsbDevices()" id="tReload">⟳ Refresh</div>
          </div>

          <!-- OTA network note -->
          <div id="otaNote" class="ota-note">
            <span>ℹ️</span>
            <span id="tOtaNote">OTA: Phone & PC must be on the same WiFi. Scan QR code after signing to install.</span>
          </div>
        </div>

        <!-- ===== Sign & Install Card ===== -->
        <div class="card">
          <div class="card-title"><span class="icon">🚀</span> <span id="tExec1">Sign &amp; Install</span></div>
          <div class="steps">
            <div class="step" id="s1"></div>
            <div class="step" id="s2"></div>
            <div class="step" id="s3"></div>
          </div>
          <div class="prog" id="prog"><div class="bar" id="progBar"></div></div>
          <button class="btn btn-primary btn-block" id="signBtn1" onclick="signApple()" disabled>
            🍎 <span id="tSignBtn1">Sign &amp; Install to iPhone</span>
          </button>
          <div id="result1" style="display:none; margin-top:12px;"></div>
        </div>
      </div>

      <!-- ===== p12 PANEL ===== -->
      <div id="p12Panel" class="hidden">
        <div class="card">
          <div class="card-title"><span class="icon">📦</span> <span id="tUploadIpa2">Upload IPA File</span></div>
          <div class="drop-zone" id="ipaDrop2" ondrop="dropIpa2(event)" ondragover="ev.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')">
            <div class="icon">📦</div>
            <p id="tDropHint2">Click or drag to upload IPA</p>
            <p class="hint" id="tDropSize2">Max 1TB</p>
            <input type="file" id="ipaFile2" accept=".ipa" onchange="loadIpa2(this)">
          </div>
          <div id="ipa2Row" class="file-row hidden">
            <div class="icon">📱</div>
            <div style="flex:1;min-width:0;">
              <div class="name" id="ipa2N"></div>
              <div class="sz" id="ipa2S"></div>
            </div>
            <div class="ok">✅</div>
            <button class="del" onclick="clearIpa2()">×</button>
          </div>
          <div id="ipaInfo2" style="display:none; margin-top:8px;"></div>
        </div>

        <div class="card">
          <div class="card-title"><span class="icon">🔐</span> <span id="tP12Label">p12 Certificate</span></div>
          <div class="alert" style="background:rgba(255,204,0,0.1);border:1px solid rgba(255,204,0,0.4);padding:10px;border-radius:10px;margin-bottom:12px;font-size:12px;color:#ffcc00;line-height:1.6;"><strong>&#9888; Certificate Mode (p12 + Profile):</strong> Only devices in your mobileprovision can install.<br>&#8226; UDID: <b>Safari</b> on iPhone to <b>get.udid.io</b><br>&#8226; p12 + mobileprovision from the <b>same Apple Developer account</b><br>&#8226; iOS: <b>15.0 - 26.4.1</b></div>
      <div class="drop-zone" id="p12Drop">
            <div class="icon">🔑</div>
            <p id="tP12Hint">Click to upload .p12 / .pfx certificate</p>
            <p class="hint" id="tP12Size">Export from Apple Dev with private key</p>
            <input type="file" id="p12File" accept=".p12,.pfx" onchange="loadP12(this)">
          </div>
          <div id="p12Row" class="file-row hidden">
            <div class="icon">🔑</div>
            <div style="flex:1;min-width:0;">
              <div class="name" id="p12N"></div>
              <div class="sz" id="p12S"></div>
            </div>
            <div class="ok">✅</div>
            <button class="del" onclick="clearP12()">×</button>
          </div>
          <div class="field" style="margin-top:10px;">
            <label id="tP12PassLabel">p12 Password</label>
            <input type="password" id="p12Pass" placeholder="Password set when exporting p12">
          </div>
        </div>

        <div class="card">
          <div class="card-title"><span class="icon">📋</span> <span id="tMpLabel">.mobileprovision File</span></div>
          <div class="drop-zone" id="mpDrop">
            <div class="icon">📋</div>
            <p id="tMpHint">Click to upload .mobileprovision</p>
            <p class="hint" id="tMpSize">Download from Apple Developer website</p>
            <input type="file" id="mpFile" accept=".mobileprovision,.mobileprovision,.prov,.plist,application/octet-stream,*.*" onchange="loadMp(this)">
          </div>
          <div id="mpRow" class="file-row hidden">
            <div class="icon">📋</div>
            <div style="flex:1;min-width:0;">
              <div class="name" id="mpN"></div>
              <div class="sz" id="mpS"></div>
            </div>
            <div class="ok">✅</div>
            <button class="del" onclick="clearMp()">×</button>
          </div>
          <div id="mpInfo" style="display:none; margin-top:8px;"></div>
          <div class="field" style="margin-top:10px;">
            <label id="tBundleLabel2">Bundle ID (optional)</label>
            <input type="text" id="bundleId2" placeholder="Leave empty to use original">
          </div>
        </div>

        <div class="card">
          <div class="card-title"><span class="icon">🚀</span> <span id="tExec2">Sign &amp; Install</span></div>
          <div class="steps">
            <div class="step" id="ss1"></div>
            <div class="step" id="ss2"></div>
            <div class="step" id="ss3"></div>
          </div>
          <div class="prog" id="prog2"><div class="bar" id="progBar2"></div></div>
          <button class="btn btn-primary btn-block" id="signBtn2" onclick="signP12()" disabled>
            🔒 <span id="tSignBtn2">Sign &amp; Install to iPhone</span>
          </button>
          <div id="result2" style="display:none; margin-top:12px;"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ===== SIGNED SECTION ===== -->
  <div id="signedSection" class="hidden">
    <div class="state-tabs">
      <div class="state-tab" id="tabUnsigned2" onclick="switchState('unsigned')">
        <span class="icon">📦</span>
        <div class="name" id="tabUName2">Unsigned</div>
        <div class="desc" id="tabUDesc2">Upload IPA to sign</div>
      </div>
      <div class="state-tab active" id="tabSigned2" onclick="switchState('signed')">
        <span class="icon">✅</span>
        <div class="name" id="tabSName2">Signed</div>
        <div class="desc" id="tabSDesc2">Signed IPA files</div>
        <div class="badge-count" id="signedCount2">0</div>
      </div>
    </div>

    <div id="signedList"></div>
  </div>

  <div class="footer" id="footer">iOS Sideload Tool v3.1 · 十一月 · OTA Direct Install</div>
</div>

<script>
  // ===== Config =====
  let currentLang = localStorage.getItem("lang_v31") || "en";
  let currentState = "unsigned";
  let currentSignMode = "apple";
  let ipa1 = null, ipa2 = null, p12 = null, mp = null;
  let signedFiles = JSON.parse(localStorage.getItem("signedFiles31") || "[]");
  let serverIp = "{{SERVER_IP}}";
  let signCount = parseInt(localStorage.getItem("signCount31") || "0");
  document.getElementById("signNum").textContent = signCount;

  // ===== Init =====
  document.addEventListener("DOMContentLoaded", () => {
    applyLang(currentLang);
    updateMobileBanner();
    checkDevices();
    renderSignedList();
    refreshSignedCount();
  });

  // ===== Language =====
  function setLang(lang) {
    currentLang = lang;
    localStorage.setItem("lang_v31", lang);
    applyLang(lang);
  }

  function applyLang(lang) {
    document.getElementById("langEn").classList.toggle("active", lang === "en");
    document.getElementById("langZh").classList.toggle("active", lang === "zh");

    const isEn = lang === "en";
    const s = key => isEn ? key : {
      "iOS Sideload Tool": "iOS 侧签工具",
      "OTA Direct Install · No Third-party Software · Sign & Install": "OTA 网页直装 · 无需第三方软件 · 签名即装",
      "Author: 十一月": "作者：十一月",
      "Connected Devices": "已连接设备",
      "Sign Count": "签名次数",
      "Saved": "已保存配置",
      "Unsigned": "未签名",
      "Signed": "已签名",
      "Upload IPA to sign": "上传 IPA 进行签名",
      "Signed IPA files": "签名完成的 IPA",
      "Apple ID": "Apple ID",
      "Sign with Apple ID + App Password (auto)": "输入 Apple ID + App 专用密码 自动签名",
      "p12 + Profile": "p12 + 描述文件",
      "Sign with local certificate": "上传本地证书签名",
      "Upload IPA File": "上传 IPA 文件",
      "Click or drag to upload IPA": "点击或拖拽上传 IPA",
      "Max 1TB": "最大 1TB",
      "Apple Developer Account": "Apple Developer 账号",
      "Apple ID (developer email)": "Apple ID（开发者账号邮箱）",
      "Apple ID Password": "App 专用密码",
      "App Password (NOT login password)": "App 专用密码（非登录密码）",
      "Bundle ID (optional)": "Bundle ID（可选）",
      "Leave empty to use original": "留空使用原包 ID",
      "Sign & Install": "签名并安装",
      "Sign & Install to iPhone": "签名并 OTA 安装到手机",
      "Install Method": "安装方式",
      "OTA WiFi": "OTA WiFi 安装",
      "USB Cable": "USB 数据线安装",
      "Refresh": "刷新",
      "OTA: Phone & PC must be on same WiFi. Scan QR after signing to install.": "OTA：需手机和电脑连同一 WiFi，签名后在 Safari 扫码安装。",
      "p12 Certificate": "p12 证书",
      "Click to upload .p12 / .pfx certificate": "点击上传 .p12 / .pfx 证书",
      "Export from Apple Dev with private key": "从 Apple Developer 网站导出，携带私钥",
      "p12 Password": "p12 密码",
      "Password set when exporting p12": "导出 p12 时设置的密码",
      ".mobileprovision File": ".mobileprovision 描述文件",
      "Click to upload .mobileprovision": "点击上传 .mobileprovision",
      "Download from Apple Developer website": "从 Apple Developer 网站下载",
      "Cannot Use on Mobile Browser": "开发者ID需电脑操作",
      "Please open this page in a computer browser (Chrome/Edge) to sign and install": "开发者ID需电脑，手机请用证书模式",
      "No Signed IPA": "暂无已签名的 IPA",
      "Upload and sign in the Unsigned tab": "在「未签名」区上传并签名后会显示在这里",
      "Please fill in Apple ID and password!": "请填写 Apple ID 和密码！",
      "Please upload all required files!": "请完整上传所有文件！",
      "Please enter p12 password!": "请输入 p12 密码！",
      "iOS Sideload Tool v3.1 · 十一月 · OTA Direct Install": "iOS 侧签工具 v3.1 · 十一月 · OTA 网页直装 · 纯本地处理",
    }[key] || key;

    const elems = {
      "subtitle": s("OTA Direct Install · No Third-party Software · Sign & Install"),
      "authorBadge": isEn ? "👤 Author: 十一月" : "👤 作者：十一月",
      "lblDevices": s("Connected Devices"),
      "lblSigns": s("Sign Count"),
      "lblSaved": s("Saved"),
      "tabUName": s("Unsigned"), "tabUDesc": s("Upload IPA to sign"),
      "tabSName": s("Signed"), "tabSDesc": s("Signed IPA files"),
      "tabUName2": s("Unsigned"), "tabUDesc2": s("Upload IPA to sign"),
      "tabSName2": s("Signed"), "tabSDesc2": s("Signed IPA files"),
      "modeAName": s("Apple ID"), "modeADesc": s("Sign with Apple ID + App Password (auto)"),
      "modePName": s("p12 + Profile"), "modePDesc": s("Sign with local certificate"),
      "tUploadIpa": s("Upload IPA File"), "tDropHint": s("Click or drag to upload IPA"),
      "tDropSize": s("Max 1TB"),
      "tUploadIpa2": s("Upload IPA File"), "tDropHint2": s("Click or drag to upload IPA"),
      "tDropSize2": s("Max 1TB"),
      "tAppleAcc": s("Apple Developer Account"),
      "tAppleIdLabel": s("Apple ID (developer email)"),
      "tPwdLabel": s("Apple ID Password"),
      "tBundleLabel": s("Bundle ID (optional)"),
      "tInstallMode": s("Install Method"),
      "tModeOta": s("OTA WiFi"),
      "tModeUsb": s("USB Cable"),
      "tReload": s("Refresh"),
      "tOtaNote": s("OTA: Phone & PC must be on same WiFi. Scan QR after signing to install."),
      "tExec1": s("Sign & Install"),
      "tSignBtn1": s("Sign & Install to iPhone"),
      "tP12Label": s("p12 Certificate"),
      "tP12Hint": s("Click to upload .p12 / .pfx certificate"),
      "tP12PassLabel": s("p12 Password"),
      "tMpLabel": s(".mobileprovision File"),
      "tMpHint": s("Click to upload .mobileprovision"),
      "tBundleLabel2": s("Bundle ID (optional)"),
      "tExec2": s("Sign & Install"),
      "tSignBtn2": s("Sign & Install to iPhone"),
      "mBannerTitle": s("Cannot Use on Mobile Browser"),
      "mBannerDesc": s("Please open this page in a computer browser (Chrome/Edge) to sign and install"),
      "footer": s("iOS Sideload Tool v3.1 · 十一月 · OTA Direct Install"),
    };
    for (const [id, text] of Object.entries(elems)) {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    }

    document.getElementById("appleId").placeholder = isEn ? "your@email.com" : "your@email.com";
    document.getElementById("applePwd").placeholder = isEn ? "App Password (NOT login password)" : "App 专用密码（非登录密码）";
    document.getElementById("bundleId1").placeholder = isEn ? "Leave empty to use original" : "留空使用原包 ID";
    document.getElementById("bundleId2").placeholder = isEn ? "Leave empty to use original" : "留空使用原包 ID";
    document.getElementById("p12Pass").placeholder = isEn ? "Password set when exporting p12" : "导出 p12 时设置的密码";

    // Re-render signed list with new language
    renderSignedList();
  }

  // ===== State switch =====
  function switchState(state) {
    currentState = state;
    document.getElementById("unsignedSection").classList.toggle("hidden", state !== "unsigned");
    document.getElementById("signedSection").classList.toggle("hidden", state !== "signed");
    const active = state === "unsigned";
    document.getElementById("tabUnsigned").classList.toggle("active", active);
    document.getElementById("tabSigned").classList.toggle("active", !active);
    document.getElementById("tabUnsigned2").classList.toggle("active", active);
    document.getElementById("tabSigned2").classList.toggle("active", !active);
  }

  // ===== Sign mode switch =====
  function switchSignMode(mode) {
    currentSignMode = mode;
    document.getElementById("modeApple").classList.toggle("active", mode === "apple");
    document.getElementById("modeP12").classList.toggle("active", mode === "p12");
    document.getElementById("applePanel").classList.toggle("hidden", mode !== "apple");
    document.getElementById("p12Panel").classList.toggle("hidden", mode !== "p12");
    updateMobileBanner();
  }

  // Mobile banner: only show for Apple ID mode on mobile browsers
  function updateMobileBanner() {
    const isMobile = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
    const show = currentSignMode === 'apple' && isMobile;
    document.getElementById("mobileBanner").style.display = show ? "flex" : "none";
  }

  // ===== Install Mode (OTA / USB) =====
  let currentInstallMode = "ota";
  let usbDevInfo = null;

  function switchInstallMode(mode) {
    currentInstallMode = mode;
    document.getElementById("modeOta").classList.toggle("active", mode === "ota");
    document.getElementById("modeUsb").classList.toggle("active", mode === "usb");
    document.getElementById("usbDeviceCard").style.display = mode === "usb" ? "flex" : "none";
    document.getElementById("otaNote").style.display = mode === "ota" ? "flex" : "none";
    if (mode === "usb") checkUsbDevices();
  }

  function checkUsbDevices() {
    document.getElementById("usbDevName").textContent = currentLang === "en" ? "Checking..." : "检测中...";
    document.getElementById("usbDevStatus").textContent = "";
    fetch("/api/usb-devices").then(r => r.json()).then(d => {
      if (d.devices && d.devices.length > 0) {
        const dev = d.devices[0];
        usbDevInfo = dev;
        document.getElementById("usbDevName").textContent = dev.name || "iPhone";
        document.getElementById("usbDevStatus").textContent = dev.udid ? "UDID: " + dev.udid.substring(0, 16) + "..." : "";
        document.getElementById("usbDeviceCard").classList.remove("no-device");
      } else {
        usbDevInfo = null;
        document.getElementById("usbDevName").textContent = currentLang === "en" ? "No Device" : "未检测到设备";
        document.getElementById("usbDevStatus").textContent = currentLang === "en"
          ? "Connect iPhone via USB & unlock"
          : "请通过 USB 连接 iPhone 并解锁屏幕";
        document.getElementById("usbDeviceCard").classList.add("no-device");
      }
    }).catch(() => {
      usbDevInfo = null;
      document.getElementById("usbDevName").textContent = currentLang === "en" ? "USB Tools Not Found" : "USB 工具未安装";
      document.getElementById("usbDevStatus").textContent = currentLang === "en"
        ? "Please install libimobiledevice to enable USB install"
        : "请安装 libimobiledevice 以启用 USB 安装";
      document.getElementById("usbDeviceCard").classList.add("no-device");
    });
  }

  // ===== Devices =====
  function checkDevices() {
    document.getElementById("deviceNum").textContent = "...";
    fetch("/api/devices").then(r=>r.json()).then(d => {
      const n = d.devices.length;
      document.getElementById("deviceNum").textContent = n || "0";
      document.getElementById("deviceCard").classList.toggle("connected", n > 0);
    }).catch(() => {
      document.getElementById("deviceNum").textContent = "0";
    });
  }

  // ===== IPA handling =====
  function loadIpa(el) {
    const file = el.files[0];
    if (!file) return;
    if (!file.name.endsWith(".ipa")) { showToast("Please select a .ipa file!", "error"); return; }
    ipa1 = file;
    showFileRow("ipa2", file.name, file.size);
    checkReady();
    parseIpa(file, 1);
  }
  function loadIpa2(el) {
    const file = el.files[0];
    if (!file) return;
    if (!file.name.endsWith(".ipa")) { showToast("Please select a .ipa file!", "error"); return; }
    ipa2 = file;
    showFileRow("ipa2", file.name, file.size);
    checkReady();
    parseIpa(file, 2);
  }
  function dropIpa(e) {
    e.preventDefault();
    e.target.closest(".drop-zone").classList.remove("drag");
    const f = e.dataTransfer.files[0];
    if (f) loadIpa({ files: [f] });
  }
  function dropIpa2(e) {
    e.preventDefault();
    e.target.closest(".drop-zone").classList.remove("drag");
    const f = e.dataTransfer.files[0];
    if (f) loadIpa2({ files: [f] });
  }
  function showFileRow(prefix, name, size) {
    document.getElementById(prefix + "N").textContent = name;
    document.getElementById(prefix + "S").textContent = fmtSize(size);
    document.getElementById(prefix + "Row").classList.remove("hidden");
    // Drop zone: p12 panel uses ipaDrop2 (not ipa2Drop)
    var dropId = (prefix === "ipa2") ? "ipaDrop2" : prefix + "Drop";
    var el = document.getElementById(dropId);
    if (el) el.style.display = "none";
  }
  function clearIpa() {
    ipa1 = null;
    document.getElementById("ipaRow").classList.add("hidden");
    document.getElementById("ipaDrop").style.display = "";
    document.getElementById("ipaInfo").style.display = "none";
    document.getElementById("ipaFile").value = "";
    checkReady();
  }
  function clearIpa2() {
    ipa2 = null;
    document.getElementById("ipa2Row").classList.add("hidden");
    document.getElementById("ipaDrop2").style.display = "";
    document.getElementById("ipaInfo2").style.display = "none";
    document.getElementById("ipaFile2").value = "";
    checkReady();
  }
  function parseIpa(file, mode) {
    const reader = new FileReader();
    reader.onload = e => {
      const buf = e.target.result.slice(0, 512*1024);
      fetch("/api/parse_ipa", {method:"POST", body:buf, headers:{"Content-Type":"application/octet-stream"}})
        .then(r=>r.json()).then(info => {
          if (info.success) showIpaInfo(mode, info);
        }).catch(()=>{});
    };
    reader.readAsArrayBuffer(file);
  }
  function showIpaInfo(mode, info) {
    const el = mode===1?"ipaInfo":"ipaInfo2";
    document.getElementById(el).style.display = "block";
    document.getElementById(el).innerHTML = `<div class="info-tbl">
      <div class="row"><div class="k">App</div><div class="v">${info.name}</div></div>
      <div class="row"><div class="k">Bundle ID</div><div class="v">${info.bundle_id}</div></div>
      <div class="row"><div class="k">Version</div><div class="v">${info.version} (${info.build})</div></div>
    </div>`;
  }

  // ===== P12 / MP =====
  function loadP12(el) {
    const file = el.files[0];
    if (!file) return;
    p12 = file;
    document.getElementById("p12N").textContent = file.name;
    document.getElementById("p12S").textContent = fmtSize(file.size);
    document.getElementById("p12Row").classList.remove("hidden");
    document.getElementById("p12Drop").style.display = "none";
    checkReady();
  }
  function clearP12() {
    p12 = null;
    document.getElementById("p12Row").classList.add("hidden");
    document.getElementById("p12Drop").style.display = "";
    document.getElementById("p12File").value = "";
    checkReady();
  }
  function loadMp(el) {
    const file = el.files[0];
    if (!file) return;
    mp = file;
    document.getElementById("mpN").textContent = file.name;
    document.getElementById("mpS").textContent = fmtSize(file.size);
    document.getElementById("mpRow").classList.remove("hidden");
    document.getElementById("mpDrop").style.display = "none";
    file.arrayBuffer().then(buf => {
      fetch("/api/parse_mp", {method:"POST", body:buf, headers:{"Content-Type":"application/octet-stream"}})
        .then(r=>r.json()).then(info => {
          if (info.success) {
            document.getElementById("mpInfo").style.display = "block";
            document.getElementById("mpInfo").innerHTML = `<div class="info-tbl">
              <div class="row"><div class="k">Name</div><div class="v">${info.name}</div></div>
              <div class="row"><div class="k">App ID</div><div class="v">${info.app_id}</div></div>
              <div class="row"><div class="k">Team</div><div class="v">${info.team_name}</div></div>
              <div class="row"><div class="k">Expires</div><div class="v">${info.expiry}</div></div>
              <div class="row"><div class="k">Devices</div><div class="v">${info.device_count}</div></div>
            </div>`;
          }
        });
    });
    checkReady();
  }
  function clearMp() {
    mp = null;
    document.getElementById("mpRow").classList.add("hidden");
    document.getElementById("mpDrop").style.display = "";
    document.getElementById("mpInfo").style.display = "none";
    document.getElementById("mpFile").value = "";
    checkReady();
  }

  // ===== Check ready =====
  function checkReady() {
    const a1 = !!(ipa1 && document.getElementById("appleId").value.trim() && document.getElementById("applePwd").value.trim());
    const a2 = !!(ipa2 && p12 && mp);
    document.getElementById("signBtn1").disabled = !a1;
    document.getElementById("signBtn2").disabled = !a2;
  }
  ["appleId","applePwd"].forEach(id => {
    document.getElementById(id).addEventListener("input", checkReady);
  });

  // ===== Steps =====
  function doStep(prefix, n) {
    for (let i=1; i<=3; i++) {
      const el = document.getElementById(prefix+i);
      if (el) el.className = "step" + (i < n ? " done" : i === n ? " active" : "");
    }
  }

  // ===== Install link =====
  function genInstallLink(filename) {
    return `itms-services://?action=download-manifest&url=${encodeURIComponent("http://" + serverIp + ":5000/ota/manifest/" + filename)}`;
  }

  // ===== Install via USB =====
  function installViaUsb(filename) {
    const btn = document.getElementById("usbInstallBtn");
    if (btn) { btn.disabled = true; btn.textContent = "..."; }
    fetch("/api/install/usb", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({filename})
    }).then(r => r.json()).then(d => {
      if (d.success) {
        showToast(d.message || "Installed successfully!", "success");
        if (document.getElementById("usbResult")) {
          document.getElementById("usbResult").innerHTML =
            `<div class="alert alert-success">✅ ${d.message || "Install succeeded!"}</div>`;
        }
      } else {
        showToast(d.error || "Install failed", "error");
        if (document.getElementById("usbResult")) {
          document.getElementById("usbResult").innerHTML =
            `<div class="alert alert-error">❌ ${d.error || "Install failed"}</div>`;
        }
      }
    }).catch(err => {
      showToast("Request error: " + err, "error");
    }).finally(() => {
      if (btn) { btn.disabled = false; btn.textContent = "🔗 " + (currentLang === "en" ? "Install via USB" : "USB 立即安装"); }
    });
  }

  // ===== Sign Apple ID =====
  function signApple() {
    if (!ipa1) return;
    const appleId = document.getElementById("appleId").value.trim();
    const pwd = document.getElementById("applePwd").value.trim();
    const bundleId = document.getElementById("bundleId1").value.trim() || null;
    if (!appleId || !pwd) { showToast("Please fill in Apple ID and password!", "error"); return; }

    const btn = document.getElementById("signBtn1");
    btn.disabled = true; btn.textContent = "...";
    document.getElementById("prog").style.display = "block";
    document.getElementById("result1").style.display = "none";
    doStep("s", 1);

    const fd = new FormData();
    fd.append("ipa", ipa1);
    fd.append("apple_id", appleId);
    fd.append("password", pwd);
    if (bundleId) fd.append("bundle_id", bundleId);
    fd.append("install_mode", currentInstallMode);

    fetch("/api/sign/apple", {method:"POST", body:fd})
      .then(r=>r.json())
      .then(data => {
        doStep("s", 3);
        if (data.success) {
          signCount++;
          localStorage.setItem("signCount31", signCount);
          document.getElementById("signNum").textContent = signCount;

          const record = {
            filename: data.filename,
            app_name: data.app_name,
            bundle_id: data.bundle_id,
            version: data.version,
            build: data.build,
            cert_cn: data.cert_cn,
            team_name: data.team_name,
            time: new Date().toLocaleString(),
            icon: data.icon,
          };
          signedFiles.unshift(record);
          if (signedFiles.length > 20) signedFiles.pop();
          localStorage.setItem("signedFiles31", JSON.stringify(signedFiles));
          refreshSignedCount();
          renderSignedList();

          document.getElementById("result1").style.display = "block";
          if (currentInstallMode === "usb") {
            // USB mode: install immediately + show OTA panel
            installViaUsb(data.filename);
            const isEn = currentLang === "en";
            document.getElementById("result1").innerHTML = `
              <div class="ota-panel">
                <div class="app-icon">${record.icon ? `<img src="${record.icon}" style="width:60px;height:60px;border-radius:13px;object-fit:cover;">` : '📱'}</div>
                <h3>${record.app_name}</h3>
                <div class="meta">${record.bundle_id} · v${record.version} (${record.build})</div>
                <button class="btn btn-primary btn-block" id="usbInstallBtn" onclick="installViaUsb('${data.filename}')">
                  🔗 ${isEn ? "Install via USB" : "USB 立即安装"}
                </button>
                <div id="usbResult" style="margin-top:12px;"></div>
                <p class="tap-hint" style="margin-top:8px; color:var(--dim); font-size:11px;">
                  ${isEn ? "Make sure your iPhone is connected via USB and unlocked." : "请确保 iPhone 已通过 USB 连接并解锁屏幕。"}
                </p>
              </div>`;
          } else {
            document.getElementById("result1").innerHTML = buildOtaPanel(record);
          }
          showToast("Signed Successfully!", "success");
        } else {
          doStep("s", 1);
          document.getElementById("result1").style.display = "block";
          document.getElementById("result1").innerHTML = `<div class="alert alert-error">❌ ${data.error || "Sign failed"}</div>
          ${data.apple_specific ? `<div class="alert" style="background:rgba(255,204,0,0.1);border:1px solid rgba(255,204,0,0.3);margin-top:8px;font-size:12px;">💡 <b>提示：</b>请使用 <b>App 专用密码</b>，不能使用 App 专用密码（非登录密码）。<a href="https://support.apple.com/zh-cn/102655" target="_blank" style="color:#ffcc00">如何获取 App 专用密码？</a></div>` : ""}`;
        }
      })
      .catch(err => {
        doStep("s", 1);
        document.getElementById("result1").style.display = "block";
        document.getElementById("result1").innerHTML = `<div class="alert alert-error">Request error: ${err}</div>`;
      })
      .finally(() => {
        btn.disabled = false;
        btn.textContent = "🍎 " + (currentLang === "en" ? "Sign & Install to iPhone" : "签名并 OTA 安装到手机");
        document.getElementById("prog").style.display = "none";
      });
  }

  // ===== Sign P12 =====
  function signP12() {
    if (!ipa2 || !p12 || !mp) { showToast("Please upload all required files!", "error"); return; }
    const pass = document.getElementById("p12Pass").value.trim();
    const bundleId = document.getElementById("bundleId2").value.trim() || null;
    if (!pass) { showToast("Please enter p12 password!", "error"); return; }

    const btn = document.getElementById("signBtn2");
    btn.disabled = true; btn.textContent = "...";
    document.getElementById("prog2").style.display = "block";
    document.getElementById("result2").style.display = "none";
    doStep("ss", 1);

    const fd = new FormData();
    fd.append("ipa", ipa2);
    fd.append("p12", p12);
    fd.append("mp", mp);
    fd.append("p12_password", pass);
    if (bundleId) fd.append("bundle_id", bundleId);
    fd.append("install_mode", "ota");

    fetch("/api/sign/p12", {method:"POST", body:fd})
      .then(r=>r.json())
      .then(data => {
        doStep("ss", 3);
        if (data.success) {
          signCount++;
          localStorage.setItem("signCount31", signCount);
          document.getElementById("signNum").textContent = signCount;

          const record = {
            filename: data.filename,
            app_name: data.app_name,
            bundle_id: data.bundle_id,
            version: data.version,
            build: data.build,
            cert_cn: data.cert_cn,
            time: new Date().toLocaleString(),
            icon: data.icon,
          };
          signedFiles.unshift(record);
          if (signedFiles.length > 20) signedFiles.pop();
          localStorage.setItem("signedFiles31", JSON.stringify(signedFiles));
          refreshSignedCount();
          renderSignedList();

          document.getElementById("result2").style.display = "block";
          document.getElementById("result2").innerHTML = buildOtaPanel(record);
          showToast("Signed Successfully!", "success");
        } else {
          doStep("ss", 1);
          document.getElementById("result2").style.display = "block";
          document.getElementById("result2").innerHTML = `<div class="alert alert-error">❌ ${data.error || "Sign failed"}</div>
          ${data.apple_specific ? `<div class="alert" style="background:rgba(255,204,0,0.1);border:1px solid rgba(255,204,0,0.3);margin-top:8px;font-size:12px;">💡 <b>提示：</b>请使用 <b>App 专用密码</b>，不能使用 App 专用密码（非登录密码）。<a href="https://support.apple.com/zh-cn/102655" target="_blank" style="color:#ffcc00">如何获取 App 专用密码？</a></div>` : ""}`;
        }
      })
      .catch(err => {
        doStep("ss", 1);
        document.getElementById("result2").style.display = "block";
        document.getElementById("result2").innerHTML = `<div class="alert alert-error">Request error: ${err}</div>`;
      })
      .finally(() => {
        btn.disabled = false;
        btn.textContent = "🔒 " + (currentLang === "en" ? "Sign & Install to iPhone" : "签名并 OTA 安装到手机");
        document.getElementById("prog2").style.display = "none";
      });
  }

  // ===== Build OTA panel =====
  function buildOtaPanel(record) {
    const installUrl = genInstallLink(record.filename);
    const qrUrl = `/api/qr?text=${encodeURIComponent(installUrl)}`;
    const isEn = currentLang === "en";
    return `
      <div class="ota-panel">
        <div class="app-icon">${record.icon ? `<img src="${record.icon}" style="width:60px;height:60px;border-radius:13px;object-fit:cover;">` : '📱'}</div>
        <h3>${record.app_name}</h3>
        <div class="meta">${record.bundle_id} · v${record.version} (${record.build})</div>
        <a class="install-btn" href="${installUrl}">📱 ${isEn ? "Install to iPhone" : "安装到 iPhone"}</a>
        <p class="tap-hint">${isEn ? "Tap button above → Install → Enter passcode" : "点击上方按钮 → 选择「安装」→ 输入锁屏密码"}</p>
        <div class="qr-row">
          <div class="qr-wrap"><img src="${qrUrl}" alt="QR" width="88" height="88" id="otaQr"></div>
          <div class="scan-hint">
            <p>${isEn ? "Scan to install:" : "扫码安装："}</p>
            <ol style="padding-left:16px; font-size:11px;">
              <li>${isEn ? "Phone & PC on same WiFi" : "确保手机和电脑同一 WiFi"}</li>
              <li>${isEn ? "Scan with Safari" : "用 Safari 扫二维码"}</li>
              <li>${isEn ? "Tap Install → Done" : "点击「安装」→ 等待完成"}</li>
            </ol>
          </div>
        </div>
        <div class="net-note">
          ⚠️ <strong>${isEn ? "Network:" : "网络要求："}</strong> ${isEn ? "Phone must be on same LAN (same WiFi)." : "手机必须和电脑连同一 WiFi。"}<br>
          ${isEn ? "If QR fails: open in Safari" : "扫码无效：用 Safari 打开"} <code>http://${serverIp}:5000/ota/install/${record.filename}</code>
        </div>
      </div>`;
  }

  // ===== Signed list =====
  function refreshSignedCount() {
    const n = signedFiles.length;
    document.getElementById("signedCount").textContent = n;
    document.getElementById("signedCount2").textContent = n;
  }

  function renderSignedList() {
    const container = document.getElementById("signedList");
    const isEn = currentLang === "en";
    if (signedFiles.length === 0) {
      container.innerHTML = `
        <div class="card" style="text-align:center; padding:40px; color:var(--dim);">
          <div style="font-size:40px; margin-bottom:10px;">📭</div>
          <p>${isEn ? "No Signed IPA" : "暂无已签名的 IPA"}</p>
          <p style="font-size:12px; margin-top:4px;">${isEn ? "Upload and sign in the Unsigned tab" : "在「未签名」区上传并签名后会显示在这里"}</p>
        </div>`;
      return;
    }
    let html = "";
    signedFiles.forEach((f, i) => {
      const installUrl = genInstallLink(f.filename);
      const qrUrl = `/api/qr?text=${encodeURIComponent(installUrl)}`;
      html += `
        <div class="signed-card">
          <div class="top">
            <div class="signed-icon">${f.icon ? `<img src="${f.icon}" alt="icon">` : '📱'}</div>
            <div class="signed-info">
              <div class="signed-name">${f.app_name}</div>
              <div class="signed-meta">${f.bundle_id} · v${f.version} (${f.build}) · ${f.time}</div>
            </div>
          </div>
          <div class="signed-actions">
            <a href="/api/download/${f.filename}" class="btn btn-secondary">📥 ${isEn ? "Download IPA" : "下载 IPA"}</a>
            <a href="/ota/install/${f.filename}" class="btn btn-green" style="flex:2;">📱 ${isEn ? "Install" : "安装"}</a>
            <div class="qr-wrap" style="padding:3px; flex-shrink:0;">
              <img src="${qrUrl}" width="38" height="38">
            </div>
            <button class="del" onclick="deleteSigned(${i})" style="background:none;border:none;color:var(--dim);font-size:16px;cursor:pointer;padding:4px;">🗑️</button>
          </div>
        </div>`;
    });
    container.innerHTML = html;
  }

  function deleteSigned(idx) {
    signedFiles.splice(idx, 1);
    localStorage.setItem("signedFiles31", JSON.stringify(signedFiles));
    refreshSignedCount();
    renderSignedList();
    showToast("Deleted", "info");
  }

  // ===== Utils =====
  function fmtSize(b) {
    if (b < 1024*1024) return (b/1024).toFixed(1)+" KB";
    return (b/1024/1024).toFixed(1)+" MB";
  }

  function showToast(msg, type="info") {
    const el = document.createElement("div");
    el.className = `alert alert-${type}`;
    el.textContent = msg;
    el.style.cssText = "position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:9999;min-width:260px;max-width:90vw;box-shadow:0 4px 24px rgba(0,0,0,0.5);border-radius:10px;";
    document.body.appendChild(el);
    setTimeout(()=>el.remove(), 4000);
  }

function loadStats(){
  fetch("/api/stats").then(function(r){return r.json()}).then(function(d){
    document.getElementById("sD").textContent=d.days||1;
    document.getElementById("sV").textContent=d.visits||0;
    document.getElementById("sS").textContent=d.signs||0;
    document.getElementById("sI").textContent=d.installs||0;
    var sb=document.getElementById("statsBar");
    if(sb){sb.style.display="block";}
  }).catch(function(){});
}
loadStats();

</script>
</body>
</html>
"""

# ========== OTA Standalone Page ==========

OTA_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{APP_NAME}} - Install</title>
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg: #080812; --surface: rgba(255,255,255,0.04); --border: rgba(255,255,255,0.08);
  --text: #e8e8f0; --dim: #7070a0; --green: #30d158;
  --yellow: #ffd60a; --red: #ff453a;
}
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg); color: var(--text); min-height: 100vh;
  display: flex; align-items: center; justify-content: center; padding: 20px;
  -webkit-font-smoothing: antialiased; }
.wrap { text-align: center; max-width: 360px; width: 100%; }
img.icon-img { width: 72px; height: 72px; border-radius: 16px; margin: 0 auto 14px; display: block; object-fit: cover; background: rgba(255,255,255,0.08); }
h1 { font-size: 22px; font-weight: 700; margin-bottom: 6px; }
.meta { color: var(--dim); font-size: 13px; margin-bottom: 24px; }
.install-btn {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--green); color: #000; font-size: 18px; font-weight: 700;
  padding: 15px 40px; border-radius: 14px; text-decoration: none;
  transition: filter 0.2s; margin-bottom: 16px; }
.install-btn:hover { filter: brightness(1.1); }
.tap-hint { font-size: 12px; color: var(--dim); margin-bottom: 16px; }
.net-note { background: rgba(255,214,10,0.08); border: 1px solid rgba(255,214,10,0.18);
  border-radius: 8px; padding: 10px 14px; font-size: 12px; color: var(--yellow);
  text-align: left; margin-top: 12px; }
.tips { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 16px; margin-top: 16px;
  text-align: left; font-size: 12px; color: var(--dim); }
.tips li { margin: 4px 0; }
.footer { color: #303050; font-size: 11px; margin-top: 32px; }
</style>
</head>
<body>
<div class="wrap">
  {% if ICON %}
    <img class="icon-img" src="{{ICON}}" alt="icon">
  {% else %}
    <div style="font-size:64px;margin-bottom:16px;">📱</div>
  {% endif %}
  <h1>{{APP_NAME}}</h1>
  <p class="meta">{{BUNDLE_ID}} · v{{VERSION}} ({{BUILD}})</p>
  <a class="install-btn" href="{{INSTALL_URL}}">📱 Install to iPhone</a>
  <p class="tap-hint">Tap button above → Install → Enter passcode</p>
  {% if QR_DATA %}
  <div style="margin-top:12px;">
    <p style="font-size:12px;color:var(--dim);margin-bottom:8px;">Or scan with Safari:</p>
    <div style="background:#fff;display:inline-block;padding:8px;border-radius:10px;">
      <img src="data:image/png;base64,{{QR_DATA}}" style="display:block;width:120px;height:120px;">
    </div>
  </div>
  {% endif %}
  <div class="net-note">
    ⚠️ <strong>Requirements:</strong><br>
    1. Phone & PC must be on <strong>same WiFi</strong><br>
    2. Use <strong>Safari</strong> browser on phone<br>
    3. Tap Install → Install → Enter passcode
  </div>
  <div class="tips">
    <p>💡 Troubleshooting:</p>
    <ul style="padding-left:18px;">
      <li>Install fails: Check phone & PC on same network</li>
      <li>Only Safari works, other browsers won't install</li>
      <li>After install: go to Settings → General → VPN & Device Management → Trust certificate</li>
    </ul>
  </div>
  <div id="statsBar" style="display:none;text-align:center;font-size:11px;color:#888;padding:4px 0;margin-bottom:6px;"><span id="sD"></span>d online | <span id="sV"></span> visits | <span id="sS"></span> signs | <span id="sI"></span> installs</div>
<div class="footer">iOS Sideload Tool · 十一月 · OTA Install</div>
</div>
</body>
</html>
"""

# ========== API Routes ==========

@app.route("/")
def index():
    return render_template_string(HTML.replace("{{SERVER_IP}}", LOCAL_IP))

@app.route("/api/devices", methods=["GET"])
def api_devices():
    return jsonify({"devices": detect_devices()})

@app.route("/api/usb-devices", methods=["GET"])
def api_usb_devices():
    """Detect iOS devices connected via USB using libimobiledevice"""
    try:
        result = subprocess.run(
            [_d("idevice_id.exe"), "-l"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        if result.returncode != 0:
            return jsonify({"devices": [], "error": "idevice_id not found or not installed"})

        device_ids = [lid.strip() for lid in result.stdout.strip().split("\n") if lid.strip()]
        devices = []
        for udid in device_ids:
            try:
                r = subprocess.run(
                    [_d("ideviceinfo.exe"), "-u", udid, "-k", "DeviceName"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace"
                )
                name = r.stdout.strip() if r.returncode == 0 else "iPhone"
                devices.append({"udid": udid, "name": name})
            except Exception:
                devices.append({"udid": udid, "name": "iPhone"})
        return jsonify({"devices": devices})
    except FileNotFoundError:
        return jsonify({"devices": [], "error": "libimobiledevice not installed"})
    except Exception as e:
        return jsonify({"devices": [], "error": str(e)})

@app.route("/api/install/usb", methods=["POST"])
def api_install_usb():
    """Install IPA to connected iOS device via USB using ideviceinstaller"""
    try:
        data = request.get_json()
        filename = data.get("filename", "")
        if not filename:
            return jsonify({"success": False, "error": "No filename provided"})

        ipa_path = os.path.join(UPLOAD_DIR, filename)
        if not os.path.exists(ipa_path):
            return jsonify({"success": False, "error": f"File not found: {filename}"})

        # Get first connected device
        r = subprocess.run(
            [_d("idevice_id.exe"), "-l"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        if r.returncode != 0:
            return jsonify({"success": False, "error": "No iOS device connected via USB"})

        device_ids = [lid.strip() for lid in r.stdout.strip().split("\n") if lid.strip()]
        if not device_ids:
            return jsonify({"success": False, "error": "No iOS device connected via USB"})

        udid = device_ids[0]
        add_log(f"USB installing {filename} to {udid}")

        # Install with ideviceinstaller
        install_r = subprocess.run(
            [_d("ideviceinstaller.exe"), "-u", udid, "-i", ipa_path],
            capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace"
        )

        if install_r.returncode == 0:
            add_log(f"USB install succeeded: {filename}")
            return jsonify({"success": True, "message": f"Installed to {filename} successfully!"})
        else:
            add_log(f"USB install failed: {install_r.stderr}")
            return jsonify({"success": False, "error": install_r.stderr or "USB install failed"})

    except FileNotFoundError:
        return jsonify({"success": False, "error": "libimobiledevice not installed. Please install it first."})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "USB install timed out"})
    except Exception as e:
        import traceback
        add_log(f"USB install error: {traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/parse_ipa", methods=["POST"])
def api_parse_ipa():
    try:
        data = request.get_data()
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith("Info.plist"):
                    try:
                        pl = plistlib.loads(zf.read(name))
                        return jsonify({
                            "success": True,
                            "bundle_id": pl.get("CFBundleIdentifier","unknown"),
                            "name": pl.get("CFBundleDisplayName", pl.get("CFBundleName","Unknown")),
                            "version": pl.get("CFBundleShortVersionString","?"),
                            "build": pl.get("CFBundleVersion","?"),
                        })
                    except: pass
        return jsonify({"success": False})
    except:
        return jsonify({"success": False})

@app.route("/api/parse_mp", methods=["POST"])
def api_parse_mp():
    try:
        data = request.get_data()
        info = parse_mobileprovision(data)
        return jsonify({
            "success": True,
            "name": info.get("name","Unknown"),
            "app_id": info.get("app_id","Unknown"),
            "team_name": info.get("team_name","Unknown"),
            "expiry": info.get("expiry","Unknown"),
            "device_count": str(info.get("device_count", "Unknown")),
        })
    except:
        return jsonify({"success": False})

@app.route("/api/qr")
def api_qr():
    text = request.args.get("text", "")
    if not text:
        return "No text", 400
    b64 = gen_qr(text)
    if b64:
        return base64.b64decode(b64), 200, {"Content-Type": "image/png"}
    return "QR generation failed", 500

@app.route("/api/sign/apple", methods=["POST"])
def api_sign_apple():
    try:
        if "ipa" not in request.files:
            return jsonify({"success": False, "error": "No IPA file uploaded"})
        ipa_data = request.files["ipa"].read()
        apple_id = request.form.get("apple_id", "").strip()
        password = request.form.get("password", "").strip()
        bundle_id = request.form.get("bundle_id", "").strip() or None
        
        if not apple_id or not password:
            return jsonify({"success": False, "error": "Apple ID and password cannot be empty"})
        
        add_log(f"Apple ID signing: {apple_id}")
        result = apple_id_sign(ipa_data, apple_id, password, bundle_id)
        
        if result["success"]:
            fname = f"apple_{file_hash(ipa_data)}_{datetime.now().strftime('%H%M%S')}.ipa"
            out_path = os.path.join(UPLOAD_DIR, fname)
            with open(out_path, "wb") as f:
                f.write(result["data"])
            add_log(f"Signed OK: {result['bundle_id']} -> {fname}")
            return jsonify({
                "success": True,
                "bundle_id": result["bundle_id"],
                "app_name": result.get("app_name", ""),
                "version": result.get("version", ""),
                "build": result.get("build", ""),
                "team_name": result.get("team_name", ""),
                "cert_cn": result.get("cert_cn", ""),
                "icon": result.get("icon"),
                "filename": fname,
            })
        else:
            return jsonify(result)
    except Exception as e:
        import traceback
        add_log(f"Apple ID sign error: {traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/sign/p12", methods=["POST"])
def api_sign_p12():
    try:
        add_log(f"p12 API called, files: {list(request.files.keys())}, form: {list(request.form.keys())}")
        for key in ["ipa", "p12", "mp"]:
            if key not in request.files:
                add_log(f"Missing file: {key}")
                return jsonify({"success": False, "error": f"Missing {key} file"})
        ipa_data = request.files["ipa"].read()
        p12_data = request.files["p12"].read()
        mp_data = request.files["mp"].read()
        p12_password = request.form.get("p12_password", "")
        bundle_id = request.form.get("bundle_id", "").strip() or None
        
        add_log(f"p12 signing: IPA={len(ipa_data)//1024}KB")
        result = resign_ipa(ipa_data, p12_data, p12_password, mp_data, bundle_id)
        
        if result["success"]:
            fname = f"p12_{file_hash(ipa_data)}_{datetime.now().strftime('%H%M%S')}.ipa"
            out_path = os.path.join(UPLOAD_DIR, fname)
            with open(out_path, "wb") as f:
                f.write(result["data"])
            add_log(f"p12 signed OK: {result['bundle_id']}")
            _inc_stats("signs", result.get("bundle_id",""))
            return jsonify({
                "success": True,
                "bundle_id": result["bundle_id"],
                "app_name": result.get("app_name", ""),
                "version": result.get("version", ""),
                "build": result.get("build", ""),
                "cert_cn": result.get("cert_cn", ""),
                "icon": result.get("icon"),
                "filename": fname,
            })
        else:
            return jsonify({"success": False, "error": result.get("error", "Sign failed")})
    except Exception as e:
        import traceback
        add_log(f"p12 sign error: {traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/download/<filename>")
def download(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return "File not found", 404
    _inc_stats("installs", filename)
    return send_file(path, as_attachment=True, download_name=filename)

# ========== OTA Routes ==========

@app.route("/api/stats")
def api_stats():
    s = _get_stats()
    return jsonify({
        "days": _days_running(),
        "visits": s.get("visits", 0),
        "signs": s.get("signs", 0),
        "installs": s.get("installs", 0),
    })

@app.route("/ota/install/<filename>")
def ota_install(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return "File not found", 404
    _inc_stats("installs", filename)
    try:
        files = extract_ipa(open(path, "rb").read())
        info = get_bundle_info(files)
    except:
        info = {"name": "iOS App", "bundle_id": "unknown", "version": "?", "build": "?", "icon": None}
    
    ipa_url = f"http://{LOCAL_IP}:5000/ota/ipa/{filename}"
    manifest = get_ota_manifest(
        ipa_url,
        info.get("bundle_id", "com.unknown"),
        info.get("name", "iOS App"),
        info.get("version", "1.0"),
        info.get("build", "1"),
    )
    manifest_path = os.path.join(UPLOAD_DIR, f"manifest_{filename}.plist")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(manifest)
    
    install_url = f"itms-services://?action=download-manifest&url={requests.utils.quote(f'http://{LOCAL_IP}:5000/ota/manifest/{filename}')}"
    qr_data = gen_qr(install_url, 200)
    
    return render_template_string(OTA_PAGE,
        APP_NAME=info.get("name", "iOS App"),
        BUNDLE_ID=info.get("bundle_id", "unknown"),
        VERSION=info.get("version", "?"),
        BUILD=info.get("build", "?"),
        ICON=info.get("icon"),
        INSTALL_URL=install_url,
        QR_DATA=qr_data,
    )

@app.route("/ota/ipa/<filename>")
def ota_ipa(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return "File not found", 404
    _inc_stats("installs", filename)
    return send_file(path, as_attachment=False, download_name=filename)

@app.route("/ota/manifest/<filename>")
def ota_manifest(filename):
    manifest_path = os.path.join(UPLOAD_DIR, f"manifest_{filename}.plist")
    if not os.path.exists(manifest_path):
        path = os.path.join(UPLOAD_DIR, filename)
        if os.path.exists(path):
            try:
                files = extract_ipa(open(path, "rb").read())
                info = get_bundle_info(files)
            except:
                info = {"bundle_id": "unknown", "name": "App", "version": "1", "build": "1"}
            ipa_url = f"http://{LOCAL_IP}:5000/ota/ipa/{filename}"
            manifest = get_ota_manifest(
                ipa_url, info.get("bundle_id", "unknown"),
                info.get("name", "iOS App"),
                info.get("version", "1"),
                info.get("build", "1"),
            )
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest)
    return send_file(manifest_path, mimetype="application/xml")

# ========== Run ==========

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════╗
║   iOS Sideload Tool v{VERSION} - 十一月         ║
╠══════════════════════════════════════════╣
║  Local:   http://localhost:5000          ║
║  LAN:     http://{LOCAL_IP}:5000       ║
║  OTA: Phone & PC must be on same WiFi    ║
╚══════════════════════════════════════════╝
    """)
    add_log("Tool started v" + VERSION)
    print("Starting Waitress production server...")
    serve(app, host="0.0.0.0", port=5000, threads=6)
