#!/usr/bin/env python3
"""
Nova Cloud Edges - Nginx Syntax & Virtual Host Extractor
Safely extracts and inspects existing Nginx server blocks from the host system
without altering, overwriting, or duplicating configuration files.

Usage:
  python3 extract_nginx_syntax.py [--json] [--out-dir ./extracted_configs]
"""

import os
import re
import sys
import json
import argparse
from typing import List, Dict, Any

def get_nginx_search_dirs() -> List[str]:
    """Finds existing Nginx configuration directories on the host."""
    candidates = [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/sites-available",
        "/etc/nginx/conf.d",
        "/usr/local/nginx/conf"
    ]
    return [d for d in candidates if os.path.isdir(d)]

def scan_nginx_files() -> List[Dict[str, Any]]:
    """Scans Nginx directory tree, resolves symlinks, and extracts active files."""
    search_dirs = get_nginx_search_dirs()
    if not search_dirs:
        print("[Notice] No standard Nginx configuration directories found on this system.")
        return []

    found_files = []
    seen_realpaths = set()

    # Prioritize sites-enabled if available
    prioritized_dirs = []
    if "/etc/nginx/sites-enabled" in search_dirs:
        prioritized_dirs.append("/etc/nginx/sites-enabled")
    if "/etc/nginx/conf.d" in search_dirs:
        prioritized_dirs.append("/etc/nginx/conf.d")
    for d in search_dirs:
        if d not in prioritized_dirs:
            prioritized_dirs.append(d)

    for d in prioritized_dirs:
        try:
            for fname in sorted(os.listdir(d)):
                full_path = os.path.join(d, fname)
                if os.path.isfile(full_path):
                    real_p = os.path.realpath(full_path)
                    is_symlink = os.path.islink(full_path)
                    symlink_target = os.readlink(full_path) if is_symlink else None

                    # Deduplicate by real target path
                    if real_p in seen_realpaths:
                        continue
                    seen_realpaths.add(real_p)

                    found_files.append({
                        "entry_path": full_path,
                        "real_path": real_p,
                        "is_symlink": is_symlink,
                        "symlink_target": symlink_target,
                        "directory": d
                    })
        except Exception as e:
            print(f"[Warning] Error reading directory {d}: {e}")

    return found_files

def extract_server_blocks(file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parses individual server { ... } blocks from an Nginx configuration file."""
    fpath = file_info["real_path"]
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[Warning] Could not read file {fpath}: {e}")
        return []

    if "server" not in content.lower():
        return []

    # Tokenize server blocks using brace depth matching
    blocks = []
    idx = 0
    while True:
        m = re.search(r'\bserver\s*\{', content[idx:], re.IGNORECASE)
        if not m:
            break
        start_pos = idx + m.start()
        brace_start = idx + m.end() - 1
        depth = 0
        end_pos = -1

        for i in range(brace_start, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break

        if end_pos != -1:
            raw_block = content[start_pos:end_pos]
            blocks.append(raw_block)
            idx = end_pos
        else:
            # Fallback to end of file
            blocks.append(content[start_pos:])
            break

    extracted = []
    for raw_block in blocks:
        # Extract server_name
        server_name_m = re.search(r'server_name\s+([^;]+);', raw_block, re.IGNORECASE)
        server_names = []
        if server_name_m:
            raw_sn = server_name_m.group(1).split()
            server_names = [s.strip() for s in raw_sn if s.strip() and not s.startswith('_')]

        # Extract listen ports
        listen_ports = []
        for lm in re.finditer(r'listen\s+([^;]+);', raw_block, re.IGNORECASE):
            port_val = lm.group(1).strip()
            listen_ports.append(port_val)

        # Extract proxy_pass, fastcgi_pass, root
        proxy_pass_m = re.search(r'proxy_pass\s+([^;]+);', raw_block, re.IGNORECASE)
        fastcgi_m = re.search(r'fastcgi_pass\s+([^;]+);', raw_block, re.IGNORECASE)
        root_m = re.search(r'root\s+([^;]+);', raw_block, re.IGNORECASE)

        proxy_pass = proxy_pass_m.group(1).strip() if proxy_pass_m else None
        fastcgi_pass = fastcgi_m.group(1).strip() if fastcgi_m else None
        root_dir = root_m.group(1).strip() if root_m else None

        # Determine architecture stack
        if fastcgi_pass:
            stack_type = "LEMP Stack (PHP-FPM)"
        elif proxy_pass:
            stack_type = "Reverse Proxy Upstream"
        elif root_dir:
            stack_type = "Static Web / SPA"
        else:
            stack_type = "General Virtual Host"

        # Extract SSL cert paths
        cert_m = re.search(r'ssl_certificate\s+([^;]+);', raw_block, re.IGNORECASE)
        key_m = re.search(r'ssl_certificate_key\s+([^;]+);', raw_block, re.IGNORECASE)
        ssl_cert = cert_m.group(1).strip() if cert_m else None
        ssl_key = key_m.group(1).strip() if key_m else None

        # Extract Access Control Directives (allow / deny)
        access_rules = []
        for am in re.finditer(r'(allow|deny)\s+([^;]+);', raw_block, re.IGNORECASE):
            action = am.group(1).strip().lower()
            target = am.group(2).strip()
            access_rules.append(f"{action} {target};")

        # Check if pure HTTP to HTTPS redirect
        is_redirect = bool(re.search(r'return\s+301\s+https', raw_block, re.IGNORECASE)) and not proxy_pass and not fastcgi_pass

        extracted.append({
            "source_file": fpath,
            "display_path": file_info["entry_path"],
            "server_names": server_names,
            "primary_domain": server_names[0] if server_names else "unspecified",
            "stack_type": stack_type,
            "listen_ports": listen_ports,
            "proxy_pass": proxy_pass,
            "fastcgi_pass": fastcgi_pass,
            "root_dir": root_dir,
            "ssl_cert": ssl_cert,
            "ssl_key": ssl_key,
            "has_ssl": bool(ssl_cert or any("ssl" in p for p in listen_ports)),
            "access_rules": access_rules,
            "is_redirect_block": is_redirect,
            "raw_syntax": raw_block.strip()
        })

    return extracted

def main():
    parser = argparse.ArgumentParser(description="Extract and inspect live Nginx configurations cleanly")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--out-dir", type=str, default="", help="Directory to save extracted clean configs")
    args = parser.parse_args()

    files = scan_nginx_files()
    all_blocks = []
    for f in files:
        blocks = extract_server_blocks(f)
        all_blocks.extend(blocks)

    if args.json:
        print(json.dumps(all_blocks, indent=2))
        return

    print("=" * 70)
    print("NOVA CLOUD EDGES - HOST NGINX SYNTAX EXTRACTOR")
    print(f"Total Nginx files inspected: {len(files)}")
    print(f"Total server blocks extracted: {len(all_blocks)}")
    print("=" * 70)

    for i, b in enumerate(all_blocks, 1):
        doms = ", ".join(b["server_names"]) if b["server_names"] else "None (default block)"
        ports = ", ".join(b["listen_ports"]) if b["listen_ports"] else "None"
        target = b["proxy_pass"] or (f"FastCGI: {b['fastcgi_pass']} (Root: {b['root_dir']})" if b["fastcgi_pass"] else (f"Static Root: {b['root_dir']}" if b["root_dir"] else ("HTTP->HTTPS 301 Redirect" if b["is_redirect_block"] else "Local / Custom")))

        print(f"\n--- [Block #{i}] Domain(s): {doms} ---")
        print(f"  Architecture  : {b['stack_type']}")
        print(f"  Source File   : {b['display_path']}")
        print(f"  Real File     : {b['source_file']}")
        print(f"  Listening on  : {ports}")
        print(f"  Target / Root : {target}")
        if b["ssl_cert"]:
            print(f"  SSL Cert Path : {b['ssl_cert']}")
        if b["access_rules"]:
            print(f"  Access Rules  : {', '.join(b['access_rules'])}")

        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
            fname = f"{b['primary_domain']}_{i}.conf"
            out_path = os.path.join(args.out_dir, fname)
            with open(out_path, "w", encoding="utf-8") as out_f:
                out_f.write(b["raw_syntax"] + "\n")
            print(f"  Exported to   : {out_path}")

    print("\n" + "=" * 70)
    print("Extraction complete. Zero original system configuration files were altered.")
    print("=" * 70)

if __name__ == "__main__":
    main()
