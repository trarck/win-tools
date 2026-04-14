#!/usr/bin/env python3
"""
IPA 重签名工具
用法: python resign_ipa.py -i input.ipa -o output.ipa -p cert.p12 -pw 123456 -m app.mobileprovision [选项]
"""

import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional


# ──────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────

def run(cmd: List[str], check=True, capture=False) -> subprocess.CompletedProcess:
    kwargs = dict(check=check)
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(cmd, **kwargs)


def find_app_bundle(payload_dir: Path) -> Path:
    apps = list(payload_dir.glob("*.app"))
    if not apps:
        raise RuntimeError(f"在 Payload/ 下未找到 .app bundle: {payload_dir}")
    if len(apps) > 1:
        print(f"[warn] 发现多个 .app，使用第一个: {apps[0].name}")
    return apps[0]


# ──────────────────────────────────────────────
# Keychain 管理（临时，不影响系统 keychain）
# ──────────────────────────────────────────────

class TempKeychain:
    def __init__(self, p12: Path, password: str):
        self.p12 = p12
        self.password = password
        self.path = None
        self.kc_password = "resign_tmp_kc_pass"

    def __enter__(self):
        fd, path = tempfile.mkstemp(suffix=".keychain-db")
        os.close(fd)
        os.unlink(path)
        self.path = path

        run(["security", "create-keychain", "-p", self.kc_password, self.path])
        run(["security", "set-keychain-settings", "-lut", "7200", self.path])
        run(["security", "unlock-keychain", "-p", self.kc_password, self.path])

        # 导入 p12
        run([
            "security", "import", str(self.p12),
            "-k", self.path,
            "-P", self.password,
            "-T", "/usr/bin/codesign",
            "-T", "/usr/bin/security",
        ])

        # 设置 key partition list，避免 codesign 弹出授权对话框
        run([
            "security", "set-key-partition-list",
            "-S", "apple-tool:,apple:",
            "-s", "-k", self.kc_password, self.path,
        ])

        # 将临时 keychain 加入搜索列表
        result = run(["security", "list-keychains", "-d", "user"], capture=True)
        existing = [s.strip().strip('"') for s in result.stdout.strip().splitlines()]
        run(["security", "list-keychains", "-d", "user", "-s", self.path] + existing)

        print(f"[keychain] 临时 keychain 创建: {self.path}")
        return self

    def __exit__(self, *_):
        if self.path:
            # 从搜索列表移除
            result = run(["security", "list-keychains", "-d", "user"], capture=True, check=False)
            keychains = [s.strip().strip('"') for s in result.stdout.strip().splitlines()
                         if s.strip().strip('"') != self.path]
            run(["security", "list-keychains", "-d", "user", "-s"] + keychains, check=False)
            run(["security", "delete-keychain", self.path], check=False)
            print("[keychain] 临时 keychain 已删除")

    def find_identity(self) -> str:
        """返回 keychain 中第一个有效签名身份的 SHA1 / Common Name"""
        result = run(
            ["security", "find-identity", "-v", "-p", "codesigning", self.path],
            capture=True
        )
        lines = [l.strip() for l in result.stdout.splitlines() if ")" in l and "CSSMERR" not in l]
        if not lines:
            raise RuntimeError("在 p12 中未找到有效的代码签名身份，请检查证书和密码")
        # 取第一个，格式: 1) <SHA1> "iPhone Distribution: ..."
        identity = lines[0].split('"')[1]
        print(f"[identity] 使用签名身份: {identity}")
        return identity


# ──────────────────────────────────────────────
# mobileprovision 解析与 entitlements 提取
# ──────────────────────────────────────────────

def extract_entitlements(provision_path: Path, out_dir: Path) -> Path:
    """从 .mobileprovision 提取 Entitlements.plist"""
    # mobileprovision 是 CMS 签名的 plist，用 security cms 解码
    decoded = out_dir / "decoded_provision.plist"
    run(["security", "cms", "-D", "-i", str(provision_path), "-o", str(decoded)])

    with open(decoded, "rb") as f:
        provision = plistlib.load(f)

    entitlements = provision.get("Entitlements", {})
    ent_path = out_dir / "entitlements.plist"
    with open(ent_path, "wb") as f:
        plistlib.dump(entitlements, f)

    print(f"[provision] AppID: {entitlements.get('application-identifier', '?')}")
    return ent_path


# ──────────────────────────────────────────────
# Info.plist 修改
# ──────────────────────────────────────────────

PLIST_KEYS = {
    "bundle_id":      "CFBundleIdentifier",
    "bundle_name":    "CFBundleName",
    "display_name":   "CFBundleDisplayName",
    "short_version":  "CFBundleShortVersionString",
    "bundle_version": "CFBundleVersion",
    "doc_browser":    "UISupportsDocumentBrowser",
}


def patch_info_plist(app_bundle: Path, args: argparse.Namespace):
    plist_path = app_bundle / "Info.plist"
    if not plist_path.exists():
        raise RuntimeError(f"未找到 Info.plist: {plist_path}")

    with open(plist_path, "rb") as f:
        info = plistlib.load(f)

    changed = []
    for arg_key, plist_key in PLIST_KEYS.items():
        val = getattr(args, arg_key, None)
        if val is None:
            continue
        # UISupportsDocumentBrowser 是布尔值
        if plist_key == "UISupportsDocumentBrowser":
            typed_val = val.lower() in ("1", "true", "yes")
        else:
            typed_val = val
        old = info.get(plist_key, "<未设置>")
        info[plist_key] = typed_val
        changed.append(f"  {plist_key}: {old!r} → {typed_val!r}")

    if changed:
        print("[plist] 修改 Info.plist:")
        print("\n".join(changed))
        with open(plist_path, "wb") as f:
            plistlib.dump(info, f)
    else:
        print("[plist] 无需修改 Info.plist")


# ──────────────────────────────────────────────
# 代码签名
# ──────────────────────────────────────────────

def remove_code_signature(path: Path):
    sig_dir = path / "_CodeSignature"
    if sig_dir.exists():
        shutil.rmtree(sig_dir)


def codesign(target: Path, identity: str, ent_path: Optional[Path] = None,
             keychain: Optional[str] = None):
    cmd = [
        "codesign",
        "--force",
        "--sign", identity,
        "--timestamp=none",
    ]
    if ent_path:
        cmd += ["--entitlements", str(ent_path)]
    if keychain:
        cmd += ["--keychain", keychain]
    cmd.append(str(target))
    run(cmd)


def resign_app(app_bundle: Path, identity: str, ent_path: Path, keychain: str):
    """按从深到浅的顺序重签名，确保签名链完整"""

    # 1. 签名所有嵌入的 Frameworks
    frameworks_dir = app_bundle / "Frameworks"
    if frameworks_dir.exists():
        for item in sorted(frameworks_dir.iterdir()):
            if item.suffix in (".framework", ".dylib"):
                print(f"[sign] Framework: {item.name}")
                remove_code_signature(item)
                codesign(item, identity, keychain=keychain)

    # 2. 签名 PlugIns（App Extensions）
    plugins_dir = app_bundle / "PlugIns"
    if plugins_dir.exists():
        for ext in sorted(plugins_dir.glob("*.appex")):
            print(f"[sign] Extension: {ext.name}")
            # Extension 内的 Frameworks
            ext_fw = ext / "Frameworks"
            if ext_fw.exists():
                for fw in sorted(ext_fw.iterdir()):
                    if fw.suffix in (".framework", ".dylib"):
                        remove_code_signature(fw)
                        codesign(fw, identity, keychain=keychain)
            remove_code_signature(ext)
            codesign(ext, identity, ent_path=ent_path, keychain=keychain)

    # 3. 签名 WatchKit / Watch App
    watch_dir = app_bundle / "Watch"
    if watch_dir.exists():
        for watch_app in sorted(watch_dir.glob("*.app")):
            print(f"[sign] Watch App: {watch_app.name}")
            remove_code_signature(watch_app)
            codesign(watch_app, identity, ent_path=ent_path, keychain=keychain)

    # 4. 签名主 .app
    print(f"[sign] Main app: {app_bundle.name}")
    remove_code_signature(app_bundle)
    codesign(app_bundle, identity, ent_path=ent_path, keychain=keychain)


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IPA 重签名工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本重签名
  python resign_ipa.py -i app.ipa -o resigned.ipa -p cert.p12 -pw mypass -m app.mobileprovision

  # 同时修改 Bundle ID 和版本
  python resign_ipa.py -i app.ipa -o resigned.ipa -p cert.p12 -pw mypass -m app.mobileprovision \\
      --bundle-id com.example.newapp --short-version 2.0.0 --bundle-version 200
        """
    )

    # 必填参数
    parser.add_argument("-i",  "--input",    required=True, help="输入 IPA 路径")
    parser.add_argument("-o",  "--output",   required=True, help="输出 IPA 路径")
    parser.add_argument("-p",  "--p12",      required=True, help="P12 证书路径")
    parser.add_argument("-pw", "--password", required=True, help="P12 证书密码")
    parser.add_argument("-m",  "--provision", required=True, help="mobileprovision 文件路径")

    # 可选：plist 修改
    parser.add_argument("--bundle-id",      dest="bundle_id",      help="CFBundleIdentifier")
    parser.add_argument("--bundle-name",    dest="bundle_name",    help="CFBundleName")
    parser.add_argument("--display-name",   dest="display_name",   help="CFBundleDisplayName")
    parser.add_argument("--short-version",  dest="short_version",  help="CFBundleShortVersionString")
    parser.add_argument("--bundle-version", dest="bundle_version", help="CFBundleVersion")
    parser.add_argument("--doc-browser",    dest="doc_browser",
                        metavar="true/false",
                        help="UISupportsDocumentBrowser (true/false)")

    args = parser.parse_args()

    # 路径校验
    input_ipa   = Path(args.input).resolve()
    output_ipa  = Path(args.output).resolve()
    p12_path    = Path(args.p12).resolve()
    provision   = Path(args.provision).resolve()

    for p, name in [(input_ipa, "IPA"), (p12_path, "P12"), (provision, "mobileprovision")]:
        if not p.exists():
            print(f"[error] 文件不存在: {name} → {p}", file=sys.stderr)
            sys.exit(1)

    # 检查 macOS 工具链
    for tool in ("codesign", "security"):
        if not shutil.which(tool):
            print(f"[error] 未找到系统工具: {tool}（需要在 macOS 上运行）", file=sys.stderr)
            sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="resign_") as tmp:
        tmp_dir = Path(tmp)
        payload_dir = tmp_dir / "Payload"

        # ── Step 1: 解压 IPA ──
        print(f"\n[step 1] 解压 IPA: {input_ipa.name}")
        with zipfile.ZipFile(input_ipa, "r") as zf:
            zf.extractall(tmp_dir)

        # 兼容部分 IPA 不含 Payload/ 顶层目录的情况
        if not payload_dir.exists():
            # 尝试在解压目录下查找 Payload
            found = list(tmp_dir.rglob("Payload"))
            if found:
                payload_dir = found[0]
            else:
                print("[error] IPA 中未找到 Payload 目录", file=sys.stderr)
                sys.exit(1)

        app_bundle = find_app_bundle(payload_dir)
        print(f"[app] Bundle: {app_bundle.name}")

        # ── Step 2: 替换 mobileprovision ──
        print(f"\n[step 2] 替换 embedded.mobileprovision")
        embedded = app_bundle / "embedded.mobileprovision"
        shutil.copy2(provision, embedded)

        # ── Step 3: 提取 entitlements ──
        print(f"\n[step 3] 提取 entitlements")
        ent_path = extract_entitlements(provision, tmp_dir)

        # ── Step 4: 修改 Info.plist ──
        print(f"\n[step 4] 修改 Info.plist")
        patch_info_plist(app_bundle, args)

        # ── Step 5: 重签名 ──
        print(f"\n[step 5] 重签名")
        with TempKeychain(p12_path, args.password) as kc:
            identity = kc.find_identity()
            resign_app(app_bundle, identity, ent_path, kc.path)

        # ── Step 6: 重新打包 IPA ──
        print(f"\n[step 6] 打包 IPA → {output_ipa}")
        output_ipa.parent.mkdir(parents=True, exist_ok=True)
        if output_ipa.exists():
            output_ipa.unlink()

        with zipfile.ZipFile(output_ipa, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in sorted(payload_dir.rglob("*")):
                arcname = file.relative_to(tmp_dir)
                zf.write(file, arcname)

        size_mb = output_ipa.stat().st_size / 1024 / 1024
        print(f"\n[done] 重签名完成: {output_ipa}  ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
