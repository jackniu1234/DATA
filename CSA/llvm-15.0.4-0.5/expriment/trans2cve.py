"""
trans2cve.py

按照文件开头的注释实现：
扫描 CodeChecker 导出的 .plist 报告（可以是单个 plist 或者存放多个 plist 的目录），
提取每条诊断的文件路径和行号，使用同目录下的 `codechecker.json` 中的 mapping
将 CodeChecker 的 check_name 映射为 CWE，然后输出如下格式的 JSON：

{"findings":[{"file":"<relative path>", "line":<n>, "cwe":"CWE-...", "found_by":["codechecker"]}, ...]}

用法（示例）：
    python trans2cve.py --reports ./reports --project-root ../source --output findings.json

如果未指定 --reports，则默认扫描当前目录及子目录的 .plist 文件；
未指定 --project-root 时，使用当前工作目录作为项目根。
如果 mapping 中对应的 check_name 的 cwe 值是 "-" 或者空字符串，将输出空字符串作为 cwe。

"""

import argparse
import json
import os
import plistlib
from typing import List, Dict, Any, Tuple

# 定义警告信息的类型
WarningInfo = Dict[str, Any]


def parse_codechecker_plist(plist_file_path: str, project_root_path: str) -> List[WarningInfo]:
    """解析单个 CodeChecker .plist 文件，返回包含 filename, line, check_name 的列表。

    返回的 filename 为相对于 project_root_path 的相对路径（如果可能），路径分隔符归一为 '/'.
    """
    if not os.path.exists(plist_file_path):
        print(f"错误：未找到文件 {plist_file_path}")
        return []

    try:
        with open(plist_file_path, 'rb') as fp:
            data = plistlib.load(fp)
    except Exception as e:
        print(f"错误：加载 plist 文件 {plist_file_path} 失败: {e}")
        return []

    files_list = data.get('files', [])
    diagnostics = data.get('diagnostics', [])

    warnings: List[WarningInfo] = []
    abs_root = os.path.abspath(project_root_path)
    project_dir_basename = os.path.basename(abs_root)

    for diag in diagnostics:
        loc = diag.get('location', {})
        file_index = loc.get('file')
        if file_index is None:
            continue
        if not (0 <= file_index < len(files_list)):
            continue

        full_path = files_list[file_index]
        # 尝试计算相对路径
        try:
            rel = os.path.relpath(full_path, start=abs_root)
        except Exception:
            rel = full_path

        # 规范化为使用 '/' 分隔
        rel = os.path.normpath(rel).replace('\\', '/')

        # 如果相对路径以项目目录名开头（例如 'openssl-3.0.0/...')，去掉该顶层目录名，
        # 只保留项目内的路径（例如 'crypto/...')。这处理了用户希望去掉像
        # '.../openssl-3.0.0/' 及之前内容的需求。
        parts = [p for p in rel.split('/') if p not in ('.', '')]
        # 如果项目目录名出现在路径的任意位置，去掉其及之前的部分，保留项目内部路径
        if project_dir_basename in parts:
            idx = parts.index(project_dir_basename)
            parts = parts[idx+1:]
        rel = '/'.join(parts)

        line = loc.get('line')
        if line is None:
            # 有些诊断可能只有范围或没有位置，跳过
            continue

        check_name = diag.get('check_name', 'UNKNOWN')

        warnings.append({'filename': rel, 'line': int(line), 'check_name': check_name})

    return warnings


def load_mapping(mapping_file: str) -> Dict[str, str]:
    """从 codechecker.json 加载 mapping: check_name -> cwe (字符串)。"""
    if not os.path.exists(mapping_file):
        raise FileNotFoundError(f"mapping file not found: {mapping_file}")

    with open(mapping_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    mapping = {}
    mapobj = data.get('mapping', {})
    for check, info in mapobj.items():
        # Safely extract cwe, normalize whitespace, treat '-' as empty
        if isinstance(info, dict):
            cwe = info.get('cwe', '')
        else:
            cwe = ''
        # normalize to string and strip
        try:
            cwe = str(cwe).strip()
        except Exception:
            cwe = ''
        if cwe == '-' or cwe == '':
            cwe = ''
        mapping[check] = cwe

    return mapping


def find_plist_files(path: str) -> List[str]:
    """如果 path 是文件则返回单个元素列表；如果是目录则递归查找所有 .plist 文件。"""
    if os.path.isfile(path):
        return [path] if path.lower().endswith('.plist') else []

    plist_paths: List[str] = []
    for root, _, files in os.walk(path):
        for fn in files:
            if fn.lower().endswith('.plist'):
                plist_paths.append(os.path.join(root, fn))
    return plist_paths


def build_findings_from_warnings(warnings: List[WarningInfo], mapping: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for w in warnings:
        file = w.get('filename', '')
        line = w.get('line', 0)
        check = w.get('check_name', '')
        # 仅当 mapping 中存在且非空的 CWE 时才记录
        cwe = mapping.get(check)
        if not cwe:
            # 如果没有映射到 CWE（包括 None 或空字符串），则跳过该条目
            continue

        # key 用于去重
        key = (file, int(line), cwe)
        if key in seen:
            continue
        seen.add(key)

        findings.append({'file': file, 'line': int(line), 'cwe': cwe, 'found_by': ['codechecker']})

    return findings


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description='Convert CodeChecker plist reports to trans2cve JSON format')
    parser.add_argument('--reports', '-r', default='.', help='Path to a .plist file or a directory containing .plist files (default: current dir)')
    parser.add_argument('--project-root', '-p', default='.', help='Project source root used to make file paths relative (default: current dir)')
    parser.add_argument('--mapping', '-m', default=os.path.join(os.path.dirname(__file__), 'codechecker.json'), help='Path to codechecker.json mapping file')
    parser.add_argument('--output', '-o', default=None, help='Output JSON file (default: stdout)')

    args = parser.parse_args(argv)

    try:
        mapping = load_mapping(args.mapping)
    except Exception as e:
        print(f"无法加载 mapping 文件: {e}")
        return 2

    plist_files = find_plist_files(args.reports)
    if not plist_files:
        print(f"未找到任何 .plist 文件，搜索路径: {args.reports}")

    all_warnings: List[WarningInfo] = []
    for p in plist_files:
        ws = parse_codechecker_plist(p, args.project_root)
        all_warnings.extend(ws)

    findings = build_findings_from_warnings(all_warnings, mapping)

    out = {'findings': findings}

    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"已写入 {args.output}，共 {len(findings)} 条发现")
        except Exception as e:
            print(f"写入输出文件失败: {e}")
            return 3
    else:
        print(text)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

