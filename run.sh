#!/usr/bin/env bash
set -u
mkdir -p /workspace/rev && cd /workspace/rev || exit 1

URL='https://yq-cu22.baidupcs.com/file/308fd2d4bte6b56550449587f030876a?bkt=en-2e2b5030dd6ff037a851cd7abeb7f342edd09f75170f9ce68e079a902eb5a8a50ade65cd46863f59&fid=3006089423-250528-4236395513108&time=1793371108&sign=FDTAXUbGERLQlBHSKfWqi-DCb740ccc5511e5e8fedcff06b081203-O8lvDRxsZJve6yT1GEvQ1R2Zu7w%3D&to=522&size=25118720&sta_dx=25118720&sta_cs=14&sta_ft=exe&sta_ct=0&sta_mt=0&fm2=MH%2CBaoding%2CAnywhere%2C%2C%E6%B9%96%E5%8C%97%2Ccnc&ctime=1793288879&mtime=1793370236&dt3=14&resv0=-1&resv1=0&resv2=rlim&resv3=2&resv4=25118720&vuk=3006089423&iv=0&vl=5&htype=&randtype=&tkbind_id=0&newver=1&newfm=1&secfm=1&flow_ver=3&pkey=en-c7be22d72599f5625271245b786abede0eef25d2942db7bdecf4b6bb292736c76464d854f7cf3d05&sl=78053454&expires=8h&rt=pr&r=755859470&vbdid=3113258122&fin=%E7%88%B1%E4%BD%A0%E4%B8%93%E4%B8%9A%E8%BD%AF%E4%BB%B6_v6.4..exe&rtype=1&dp-logid=108583218759673391&dp-callid=0.1&hps=1&tsl=120&csl=120&fsl=-1&csign=kj%2F8V%2FPZ3TayTN2iSmTLhiQ3gWk%3D&so=0&ut=6&uter=1&serv=0&uc=2083196089&ti=e38f2d2f207d2315a76689cf8175cc5921c1942c6f1f086b305a5e1275657320&hflag=32&from_type=3&adg=c_831b08a8133543318db1fdde15177182&reqlabel=250528_d_5775e83256fa38143a7953fa64cd21d0_-1_91d090d41380779e37f6f81d50975f3e&fpath=%E6%88%91%E7%9A%84%E8%B5%84%E6%BA%90&by=themis&ccn=CN'

echo "================ ENV ================"
head -2 /etc/os-release 2>/dev/null
echo "cpu=$(nproc) mem=$(free -g 2>/dev/null | awk '/Mem:/{print $2}')G disk=$(df -h /workspace 2>/dev/null | awk 'NR==2{print $4}')"
python3 -V 2>&1

echo "================ DOWNLOAD ================"
if [ ! -s sample.exe ]; then
  curl -L --retry 2 --connect-timeout 20 -m 900 -A 'netdisk' -o sample.exe "$URL" -w 'http=%{http_code} size=%{size_download} speed=%{speed_download}B/s\n'
fi
ls -l sample.exe 2>/dev/null
sha256sum sample.exe 2>/dev/null
md5sum sample.exe 2>/dev/null

echo "================ DEPS ================"
python3 -c 'import pefile' 2>/dev/null || pip3 install -q pefile -i https://pypi.tuna.tsinghua.edu.cn/simple 2>&1 | tail -2
python3 -c 'import pefile; print("pefile ok")' 2>&1 | tail -1

echo "================ ANALYZE ================"
python3 - <<'PYEOF' 2>&1
import math, re, hashlib, datetime, sys
from collections import Counter
try:
    import pefile
except Exception as e:
    print("no pefile:", e); sys.exit(0)
p = 'sample.exe'
try:
    d = open(p, 'rb').read()
except Exception as e:
    print("read fail:", e); sys.exit(0)
print("size =", len(d))
print("sha256 =", hashlib.sha256(d).hexdigest())
print("md5    =", hashlib.md5(d).hexdigest())
try:
    pe = pefile.PE(p, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
    ])
except Exception as e:
    print("pefile fail:", e); sys.exit(0)

print("\n--- HEADER ---")
print("machine  :", hex(pe.FILE_HEADER.Machine), {0x14c:'x86',0x8664:'x64'}.get(pe.FILE_HEADER.Machine,'?'))
try:
    print("timestamp:", datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat())
except Exception:
    print("timestamp:", pe.FILE_HEADER.TimeDateStamp)
print("subsystem:", pe.OPTIONAL_HEADER.Subsystem, {2:'GUI',3:'Console'}.get(pe.OPTIONAL_HEADER.Subsystem,''))
print("entryRVA :", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
dc = pe.OPTIONAL_HEADER.DllCharacteristics
print("dllchar  :", hex(dc), "ASLR" if dc & 0x40 else "-", "DEP" if dc & 0x100 else "-", "CFG" if dc & 0x4000 else "-")
sig = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
print("signature:", ("YES %d bytes" % sig) if sig else "NONE")

print("\n--- SECTIONS ---")
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1', 'ignore')
    data = s.get_data()
    H = 0.0
    if data:
        c = Counter(data); n = len(data)
        H = -sum((v / n) * math.log2(v / n) for v in c.values())
    print("  %-10s raw=%9d vsz=%9d ent=%.3f%s" % (nm, s.SizeOfRawData, s.Misc_VirtualSize, H, "   <== HIGH" if H > 7.2 else ""))

print("\n--- IMPORTS ---")
total = 0; imps = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dll = e.dll.decode('latin1', 'ignore')
        fns = [(i.name.decode('latin1', 'ignore') if i.name else 'ord%d' % i.ordinal) for i in e.imports]
        imps[dll] = fns; total += len(fns)
        print("  %s (%d): %s%s" % (dll, len(fns), ", ".join(fns[:26]), " ..." if len(fns) > 26 else ""))
print("TOTAL dll=%d funcs=%d%s" % (len(imps), total, "   <== VERY FEW, packed?" if total < 15 else ""))

flat = [k + "!" + v for k, vs in imps.items() for v in vs]
caps = {
 'net-http': r'InternetOpen|WinHttp|HttpSend|URLDownload|InternetRead',
 'net-sock': r'WSAStartup|socket|connect|send|recv|getaddrinfo',
 'registry': r'RegSetValue|RegCreateKey|RegOpenKey|RegQueryValue',
 'inject-exec': r'CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|CreateProcess|ShellExecute|WinExec',
 'service': r'CreateService|StartService|schtasks',
 'antidebug': r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess',
 'crypto': r'CryptEncrypt|CryptDecrypt|CryptAcquireContext|BCrypt',
 'fileio': r'CreateFile|FindFirstFile|MoveFile|CopyFile|DeleteFile',
 'gui': r'CreateWindowEx|MessageBox|DialogBox|GetDlgItem',
}
print("\n--- CAPABILITY ---")
for k, pat in caps.items():
    v = [x for x in flat if re.search(pat, x)]
    print("  %s %-12s %s%s" % ("YES" if v else " - ", k, ", ".join(v[:5]), (" +%d" % (len(v) - 5)) if len(v) > 5 else ""))

print("\n--- VERSION INFO ---")
try:
    for fi in pe.FileInfo:
        for entry in fi:
            if entry.Key.decode('latin1', 'ignore') == 'StringFileInfo':
                for st in entry.StringTable:
                    for k, v in st.entries.items():
                        print("   %s = %s" % (k.decode('latin1', 'ignore'), v.decode('utf-8', 'ignore')[:110]))
except Exception:
    print("   (none)")

print("\n--- STRINGS: url/reg/license ---")
pat2 = re.compile(r'https?://|regist|serial|licen|activ|trial|crack|keygen|patch|machine.?code|hardware|\.dll$', re.I)
seen = set(); n = 0
for m in re.finditer(rb'[\x20-\x7e]{6,120}', d):
    s = m.group().decode('latin1')
    if s in seen or not pat2.search(s):
        continue
    seen.add(s); n += 1
    print("   ", s[:110])
    if n >= 60:
        break

print("\n--- STRINGS: CJK utf16 ---")
cn = []
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,80}', d):
    try:
        s = m.group().decode('utf-16le')
    except Exception:
        continue
    if re.search(r'[\u4e00-\u9fff]', s):
        cn.append(s)
        if len(cn) > 4000:
            break
for s in list(dict.fromkeys(cn))[:40]:
    print("   ", re.sub(r'[^\u4e00-\u9fffA-Za-z0-9 :：，。！？()（）\-.%]', '', s)[:90])

print("\n=== END ===")
PYEOF

echo "================ DONE ================"
ls -l /workspace/rev/
