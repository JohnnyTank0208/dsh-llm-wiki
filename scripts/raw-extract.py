#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""raw-extract.py —— LLM-Wiki 原始素材抽取分支（配套 llm-wiki-pipeline.mjs --extract）

职责：扫描 raw/ 下的二进制素材，为**缺失**的 `<原名>.extracted.md` 伴生件生成文本，
使检索链路不再出现「文件在库、正文取不到」的盲区。

安全边界（与 vault 守则一致）：
  1. 只创建缺失的伴生件；**绝不覆盖、绝不删除、绝不改动** raw/ 下的原始文件。
  2. 已存在的伴生件一律 skip（要重跑请显式 --overwrite，此时仍只重写伴生件，不碰原件）。
  3. 不写 wiki/，不写数据库；结果只通过 --out 指定的 JSON 报告给调用方。

依赖策略：.doc 用纯标准库解析（MS-CFB + [MS-DOC] piece table）；.docx 用 zipfile；
.pdf 需要 pypdf（缺失时该项报错并继续处理其他文件，不整体失败）。

用法：
  python raw-extract.py --dir <raw/documents> --out <result.json> [--dry-run] [--overwrite] [--limit N]
"""
import argparse
import io
import json
import os
import re
import struct
import sys
import zipfile
from datetime import datetime, timezone, timedelta

VERSION = "1.0.0"
EOCH, FREEB, FATB, DIFB = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFC
SUPPORTED = (".pdf", ".doc", ".docx")

# Word 97 常见流名，用于给扫描到的目录链打分
KNOWN_STREAMS = re.compile(
    r"^(Root Entry|WordDocument|0Table|1Table|Data|SummaryInformation|"
    r"DocumentSummaryInformation|WpsCustomData|_.*|Macros?|Word8\.0)$"
)

# .doc 抽取的固有失真：Word 自动编号（第X条、一、等）不在文本流里
DOC_CAVEAT = (
    "<!-- 抽取注意：本文本由 [MS-DOC] piece table 解析得到。"
    "Word 自动编号（如「第X条」「一、」）不存储于文本流，故未保留；"
    "章节与条目顺序可靠，条号需回原 .doc 核对。 -->"
)


def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).isoformat()


# ───────────────────────────── MS-CFB 容器 ─────────────────────────────

def build_fat(d):
    """按 [MS-CFB] 正确偏移重建 FAT。返回 (ss, mss, cutoff, dir0, minifat0, fat, maxsec)。"""
    ss = 1 << struct.unpack_from("<H", d, 0x1E)[0]          # SectorShift
    mss = 1 << struct.unpack_from("<H", d, 0x20)[0]         # MiniSectorShift
    cutoff = struct.unpack_from("<I", d, 0x34)[0] or 4096   # 非法 0 时回退默认值
    dir0 = struct.unpack_from("<I", d, 0x2C)[0]             # 目录起始扇区
    minifat0 = struct.unpack_from("<I", d, 0x38)[0]         # 迷你 FAT 起始扇区
    difat0 = struct.unpack_from("<I", d, 0x40)[0]           # DIFAT 链起始扇区
    maxsec = len(d) // ss
    ids, seen = [], set()

    def add(x):
        if x not in (FREEB, EOCH, FATB, DIFB) and x < maxsec and x not in seen:
            seen.add(x)
            ids.append(x)

    for x in struct.unpack_from("<109I", d, 0x48):          # 头部内联 DIFAT 项
        add(x)
    nxt, guard = difat0, 0
    while nxt < maxsec and nxt not in (EOCH, FREEB, FATB, DIFB) and guard < 4096:
        ent = struct.unpack_from("<%dI" % (ss // 4), d, (nxt + 1) * ss)
        for x in ent[:-1]:
            add(x)
        nxt = ent[-1]
        guard += 1
    fat = []
    for s in ids:
        fat += list(struct.unpack_from("<%dI" % (ss // 4), d, (s + 1) * ss))
    return ss, mss, cutoff, dir0, minifat0, fat, maxsec


def make_chain(fat):
    def chain(start, limit=200000):
        out, s, seen = [], start, set()
        while (s < len(fat) and s not in (EOCH, FREEB, FATB, DIFB)
               and s not in seen and len(out) < limit):
            seen.add(s)
            out.append(s)
            s = fat[s]
        return out
    return chain


def parse_entries(raw):
    """把目录原始字节切成条目；畸形项靠 nl/type 双重校验剔除。"""
    res = []
    for i in range(len(raw) // 128):
        e = raw[i * 128:(i + 1) * 128]
        nl = struct.unpack_from("<H", e, 0x40)[0]
        typ = e[0x42]
        if nl < 6 or nl > 64 or typ not in (1, 2, 5):
            continue
        name = e[:nl - 2].decode("utf-16-le", "replace")
        if not name or "\ufffd" in name:
            continue
        res.append((name, typ,
                    struct.unpack_from("<I", e, 0x74)[0],   # 起始扇区
                    struct.unpack_from("<I", e, 0x78)[0]))  # 流字节数
    return res


def read_chain_bytes(d, ch, ss):
    return b"".join(d[(t + 1) * ss:(t + 2) * ss] for t in ch)


def locate_directory(d, fat, chain, ss, maxsec, dir0):
    """先信头部 dir0（快路径），失败再逐扇区扫描（对付元数据不自洽的写入方）。"""
    def score_chain(head, maxlen=40):
        ch = chain(head, maxlen)
        if not ch:
            return None
        clen = 0
        for t in ch:
            clen += 1
            if fat[t] in (EOCH, FREEB, FATB, DIFB):
                break
        raw = read_chain_bytes(d, ch[:clen], ss)
        ents = parse_entries(raw)
        names = [n for n, *_ in ents]
        if "WordDocument" not in names:
            return None
        return (len([n for n in names if KNOWN_STREAMS.match(n)]) * 100 + len(ents), ch[:clen], ents)

    hit = score_chain(dir0)
    if hit:
        return (dir0,) + hit
    limit = min(maxsec, 20000)
    best = None
    for s in range(limit):
        r = score_chain(s)
        if r and (best is None or r[0] > best[1][0]):
            best = (s, r)
    if not best:
        return None
    return (best[0],) + best[1]


def ole_streams(blob):
    """返回 (streams{name:(start,size)}, 读取函数, 诊断信息)。"""
    ss, mss, cutoff, dir0, minifat0, fat, maxsec = build_fat(blob)
    chain = make_chain(fat)
    hit = locate_directory(blob, fat, chain, ss, maxsec, dir0)
    if not hit:
        raise ValueError("未能定位目录流（文件可能不是 OLE2，或扇区链损坏）")
    dhead, _score, dchain, ents = hit
    ent = {n: (t, st, sz) for n, t, st, sz in ents}

    root = ent.get("Root Entry")
    minidata = b""
    if root:
        minidata = read_chain_bytes(blob, chain(root[1], 4096), ss)[:root[2]]
    minifat = []
    s, guard = minifat0, 0
    while (s < len(fat) and s < maxsec and s not in (EOCH, FREEB, FATB, DIFB)
           and guard < 4096):
        minifat += list(struct.unpack_from("<%dI" % (ss // 4), blob, (s + 1) * ss))
        s = fat[s]
        guard += 1

    def stream(name):
        _t, st, sz = ent[name]
        if sz < cutoff and minidata and minifat:
            buf, cur, g = b"", st, 0
            while cur < len(minifat) and cur not in (EOCH, FREEB) and g < 65536:
                buf += minidata[cur * mss:(cur + 1) * mss]
                cur = minifat[cur]
                g += 1
            return buf[:sz]
        return read_chain_bytes(blob, chain(st, 40000), ss)[:sz]

    diag = {"sector_size": ss, "dir_head": dhead, "dir_chain": dchain,
            "streams": {n: {"start": v[1], "size": v[2]} for n, v in ent.items()}}
    return ent, stream, diag


# ───────────────────────────── MS-DOC 文本 ─────────────────────────────

def clean_text(t):
    t = t.replace("\r", "\n").replace("\x07", "\n").replace("\x0b", "\n").replace("\x0c", "\n")
    t = re.sub(r"[\x00-\x06\x08\x0e-\x1f]", "", t)
    t = re.sub(r"[ \t]+\n", "\n", t)
    return re.sub(r"\n{3,}", "\n\n", t).strip()


def extract_doc(path):
    """Word 97 二进制正文抽取。返回 (text, meta)。"""
    with io.open(path, "rb") as f:
        blob = f.read()
    if blob[:8] != bytes.fromhex("D0CF11E0A1B11AE1"):
        raise ValueError("不是 OLE2 复合文档（magic 不匹配），可能是伪装成 .doc 的 HTML/RTF")
    ent, stream, diag = ole_streams(blob)
    wd = stream("WordDocument")
    flags = struct.unpack_from("<H", wd, 0x0A)[0]
    tbl = "1Table" if (flags & 0x0200) else "0Table"
    if tbl not in ent:
        tbl = "1Table" if "1Table" in ent else ("0Table" if "0Table" in ent else None)
        if tbl is None:
            raise ValueError("缺少 0Table/1Table 流，无法解析 piece table")
    tb = stream(tbl)
    ccp_text = struct.unpack_from("<i", wd, 0x4C)[0]
    fc_clx = struct.unpack_from("<I", wd, 0x01A2)[0]
    lcb_clx = struct.unpack_from("<I", wd, 0x01A6)[0]
    clx = tb[fc_clx:fc_clx + lcb_clx]
    i, pcdt = 0, None
    while i < len(clx):
        typ = clx[i]
        if typ == 1:                                   # Prc：跳过
            cb = struct.unpack_from("<H", clx, i + 1)[0]
            i += 3 + cb
        elif typ == 2:                                 # Pcdt
            lcb = struct.unpack_from("<I", clx, i + 1)[0]
            pcdt = clx[i + 5:i + 5 + lcb]
            break
        else:
            break
    if pcdt is None or len(pcdt) < 16:
        raise ValueError("未找到 Pcdt（piece table）")
    n = (len(pcdt) - 4) // 12
    acp = list(struct.unpack_from("<%dI" % (n + 1), pcdt, 0))
    base = 4 * (n + 1)
    parts = []
    for k in range(n):
        pcd = pcdt[base + 8 * k: base + 8 * (k + 1)]
        fc = struct.unpack_from("<I", pcd, 2)[0]
        comp = bool(fc & 0x40000000)
        fcv = fc & 0x3FFFFFFF
        ln = max(0, acp[k + 1] - acp[k])
        if comp:
            parts.append(wd[fcv // 2:fcv // 2 + ln].decode("cp1252", "replace"))
        else:
            parts.append(wd[fcv:fcv + 2 * ln].decode("utf-16-le", "replace"))
    text = clean_text("".join(parts)[:ccp_text] if ccp_text > 0 else "".join(parts))
    meta = {"pieces": n, "ccpText": ccp_text, "table": tbl,
            "worddocument_bytes": len(wd), "table_bytes": len(tb), "cfb": diag}
    return text, meta


def extract_docx(path):
    """.docx：zipfile + word/document.xml，标准库即可，不需要 python-docx。"""
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8", "replace")
    paras = []
    for p in re.findall(r"<w:p[ >][\s\S]*?</w:p>", xml):
        txt = "".join(re.findall(r"<w:t[^>]*>([\s\S]*?)</w:t>", p))
        txt = (txt.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                  .replace("&quot;", '"').replace("&apos;", "'"))
        paras.append(txt)
    text = "\n".join(paras).strip()
    return clean_text(text), {"paragraphs": len(paras)}


def extract_pdf(path):
    """.pdf：需要 pypdf（本机 DSH 运行时自带）。缺失时抛错由上层记录，不影响其他文件。"""
    try:
        from pypdf import PdfReader
    except ImportError:
        try:
            from PyPDF2 import PdfReader          # 兼容旧包名
        except ImportError:
            raise RuntimeError("缺少 pypdf，无法抽取 PDF（pip install pypdf 或设置 LLM_WIKI_PYTHON 指向含 pypdf 的解释器）")
    r = PdfReader(path)
    per_page = []
    for i, pg in enumerate(r.pages):
        try:
            per_page.append(pg.extract_text() or "")
        except Exception as e:                    # 单页损坏不致命：留标记继续
            per_page.append("<!-- 第 %d 页抽取失败: %s -->" % (i + 1, e))
    return "\n\n".join(per_page).strip(), {"pages": len(r.pages), "per_page": per_page}


# ───────────────────────────── 伴生件读写 ─────────────────────────────

def sidecar_path(src):
    return os.path.splitext(src)[0] + ".extracted.md"


def render_sidecar(src_name, text, kind, meta):
    pages = meta.get("pages") if kind == "pdf" else 1
    lines = ["---",
             'source: "%s"' % src_name,
             'ingested_at: "%s"' % now_iso(),
             "type: document",
             "pages: %s" % (pages if pages else 1),
             'chars: %d' % len(text),
             'extractor: "raw-extract.py %s (%s)"' % (VERSION, kind),
             "---", ""]
    if kind == "doc":
        lines += [DOC_CAVEAT, ""]
    if kind == "pdf" and meta.get("per_page"):
        for i, t in enumerate(meta["per_page"]):
            lines += ["<!-- 第 %d 页 -->" % (i + 1), "", t.strip(), ""]
    else:
        lines += [text, ""]
    return "\n".join(lines)


def scan(dirpath):
    items = []
    for name in sorted(os.listdir(dirpath)):
        p = os.path.join(dirpath, name)
        if not os.path.isfile(p):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext not in SUPPORTED:
            continue
        items.append({"source": p, "ext": ext, "sidecar": sidecar_path(p),
                      "exists": os.path.exists(sidecar_path(p)),
                      "size": os.path.getsize(p)})
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="要扫描的 raw 子目录（如 raw/documents）")
    ap.add_argument("--out", required=True, help="结果 JSON 写入路径")
    ap.add_argument("--dry-run", action="store_true", help="只报告将做什么，不写文件")
    ap.add_argument("--overwrite", action="store_true", help="重抽已存在的伴生件")
    ap.add_argument("--limit", type=int, default=0, help="最多处理 N 个待抽文件")
    ap.add_argument("--min-chars", type=int, default=40, help="抽取结果低于该字数视为失败（防加密/图片型空壳）")
    ap.add_argument("--only", default="", help="只处理文件名包含该子串的素材（作用域收窄，避免顺带抽取未授权文件）")
    a = ap.parse_args()

    result = {"version": VERSION, "dir": a.dir, "dry_run": a.dry_run,
              "scanned": 0, "created": 0, "skipped": 0, "failed": 0,
              "items": [], "warnings": []}
    if not os.path.isdir(a.dir):
        result["error"] = "目录不存在: " + a.dir
    else:
        items = scan(a.dir)
        result["scanned"] = len(items)
        if a.only:
            items = [it for it in items if a.only.lower() in os.path.basename(it["source"]).lower()]
            result["only"] = a.only
            result["matched"] = len(items)
        todo = [it for it in items if not it["exists"] or a.overwrite]
        result["already_extracted"] = len(items) - len(todo)
        if a.limit:
            todo = todo[:a.limit]
        for it in todo:
            name = os.path.basename(it["source"])
            rel = {"source": name, "sidecar": os.path.basename(it["sidecar"]), "kind": it["ext"]}
            if a.dry_run:
                rel["status"] = "would-extract"
                result["items"].append(rel)
                continue
            try:
                if it["ext"] == ".pdf":
                    text, meta = extract_pdf(it["source"])
                    kind = "pdf"
                elif it["ext"] == ".doc":
                    text, meta = extract_doc(it["source"])
                    kind = "doc"
                else:
                    text, meta = extract_docx(it["source"])
                    kind = "docx"
                if len(text) < a.min_chars:
                    raise ValueError("抽取结果过短（%d 字 < %d），疑似加密/图片型/正文缺失，未写入伴生件" % (len(text), a.min_chars))
                md = render_sidecar(name, text, kind, meta)
                with io.open(it["sidecar"], "w", encoding="utf-8", newline="\n") as f:
                    f.write(md)
                rel.update({"status": "created", "chars": len(text), "pages": meta.get("pages", 1)})
                if meta.get("pieces", 1) > 1:
                    rel["note"] = "piece 数 %d，文本存在编辑碎片" % meta["pieces"]
                result["created"] += 1
            except Exception as e:
                rel.update({"status": "failed", "error": "%s: %s" % (type(e).__name__, e)})
                result["failed"] += 1
            result["items"].append(rel)

    with io.open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print("scan=%d created=%d failed=%d dry=%s" % (
        result["scanned"], result["created"], result["failed"], result["dry_run"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
