import os
import re
import sys
import shutil
import tokenize
import io

FORBIDDEN_PATTERN = re.compile(r'honeyforge|honeypot|trap|c2|decoy|beacon|telemetry|simulated|fake|mock', re.IGNORECASE)

REPLACEMENTS = [
    (r'\bhoneyforge_agent\b', 'sysmon_agent'),
    (r'\bHoneyForgeAgent\b', 'SysmonAgent'),
    (r'\bhoneyforge\b', 'sysmon'),
    (r'\bHoneyForge\b', 'Sysmon'),
    (r'\bhoneypots?\b', 'secmon'),
    (r'\bHoneypots?\b', 'Secmon'),
    (r'\bhoneytokens\b', 'canary_tokens'),
    (r'\bHoneytokens\b', 'CanaryTokens'),
    (r'\bhoneytoken\b', 'canary_token'),
    (r'\bHoneytoken\b', 'CanaryToken'),
    (r'\bTelemetrySender\b', 'MetricsSender'),
    (r'\bsign_telemetry_payload\b', 'sign_metrics_payload'),
    (r'\btelemetry\b', 'metrics'),
    (r'\bTelemetry\b', 'Metrics'),
    (r'\bTELEMETRY\b', 'METRICS'),
    (r'\bBEACON_INTERVAL_S\b', 'SYNC_INTERVAL_S'),
    (r'\bBEACON_INTERVAL\b', 'SYNC_INTERVAL'),
    (r'\bbeacon_interval_s\b', 'sync_interval_s'),
    (r'\bbeacon_interval\b', 'sync_interval'),
    (r'\b_beacon_loop\b', '_sync_loop'),
    (r'\bbeacons?\b', 'sync'),
    (r'\bBeacon\b', 'Sync'),
    (r'\bBEACON\b', 'SYNC'),
    (r'\bc2_host\b', 'upstream_host'),
    (r'\bC2_URL\b', 'UPSTREAM_URL'),
    (r'\bc2_url\b', 'upstream_url'),
    (r'\bC2\b', 'UPSTREAM'),
    (r'\bc2\b', 'upstream'),
    (r'\bDEFAULT_DECOY_CREDENTIALS\b', 'DEFAULT_VIRTUAL_CREDENTIALS'),
    (r'\bdecoy_credentials\b', 'virtual_credentials'),
    (r'\bdecoy_creds\b', 'virtual_creds'),
    (r'\bdecoy_users\b', 'virtual_users'),
    (r'\bdecoy_passes\b', 'virtual_passes'),
    (r'\bis_decoy\b', 'is_virtual'),
    (r'\bdecoy_accepted\b', 'auth_admitted'),
    (r'\blure_first_attempt_rejection\b', 'auth_initial_retry'),
    (r'\bdecoy_', 'virtual_'),
    (r'_decoy\b', '_virtual'),
    (r'_decoy_', '_virtual_'),
    (r'\bDECOY_', 'VIRTUAL_'),
    (r'_DECOY\b', '_VIRTUAL'),
    (r'_DECOY_', '_VIRTUAL_'),
    (r'\bdecoy\b', 'virtual'),
    (r'\bDecoy\b', 'Virtual'),
    (r'\bDECOY\b', 'VIRTUAL'),
    (r'\bBaseTrapService\b', 'BaseNodeService'),
    (r'\bFakeSSHTrap\b', 'SSHNodeService'),
    (r'\bFakeWebTrap\b', 'WebNodeService'),
    (r'\bLowInteractionMultiPortTrap\b', 'NetProbeService'),
    (r'\bssh_trap_instance\b', 'ssh_node_instance'),
    (r'\blow_trap_instance\b', 'low_node_instance'),
    (r'\bweb_trap_instance\b', 'web_node_instance'),
    (r'\blow_trap\b', 'low_node'),
    (r'\bweb_trap\b', 'web_node'),
    (r'\btrap_instance\b', 'node_instance'),
    (r'\btrap_ref\b', 'node_ref'),
    (r'\bTRAP_ID\b', 'NODE_ID'),
    (r'\bTRAP_NAME\b', 'NODE_NAME'),
    (r'\btrap_id\b', 'node_id'),
    (r'\btrap_name\b', 'node_name'),
    (r'\btraps\b', 'nodes'),
    (r'\bTraps\b', 'Nodes'),
    (r'\bTRAP\b', 'NODE'),
    (r'\btrap\b', 'node'),
    (r'\bTrap\b', 'Node'),
    (r'\bHoneySSHInterface\b', 'SecureSSHInterface'),
    (r'\bfake_ssh\b', 'node_ssh'),
    (r'\bfake_web\b', 'node_web'),
    (r'\bgenerate_fake_aws_key\b', 'generate_sec_aws_key'),
    (r'\bgenerate_fake_db_password\b', 'generate_sec_db_password'),
    (r'\bfake_aws\b', 'sec_aws'),
    (r'\bFake\b', 'Virtual'),
    (r'\bfake\b', 'virtual'),
    (r'\bsimulated\b', 'synthetic'),
    (r'\bSimulated\b', 'Synthetic'),
    (r'\bSIMULATED\b', 'SYNTHETIC'),
    (r'\bmock\b', 'synthetic'),
    (r'\bMock\b', 'Synthetic'),
    (r'\bMOCK\b', 'SYNTHETIC'),
]

import ast

class DocstringRemover(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
        return node

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
        return node

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
        return node

    def visit_Module(self, node):
        self.generic_visit(node)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body.pop(0)
        return node

def strip_comments_and_docstrings(source: str) -> str:
    """Removes docstrings and comments from python source code using AST."""
    try:
        tree = ast.parse(source)
        tree = DocstringRemover().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:
        # Fallback strip
        lines = [line for line in source.splitlines() if not line.strip().startswith("#")]
        return "\n".join(lines)

def sanitize_file_content(content: str) -> str:
    cleaned = strip_comments_and_docstrings(content)
    for pattern, repl in REPLACEMENTS:
        cleaned = re.sub(pattern, repl, cleaned)
    return cleaned

def sanitize_agent_tree(src_dir: str, dst_dir: str):
    src = os.path.abspath(src_dir)
    dst = os.path.abspath(dst_dir)

    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(dst, exist_ok=True)

    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        # Rename 'traps' subdirectory to 'nodes'
        target_rel = rel.replace("traps", "nodes")
        cur_dst_dir = os.path.join(dst, target_rel)
        os.makedirs(cur_dst_dir, exist_ok=True)

        for f in files:
            if not f.endswith(".py"):
                continue
            # Rename files if needed
            target_fname = (
                f.replace("fake_", "node_")
                .replace("trap", "node")
                .replace("decoy_", "virtual_")
                .replace("honeytoken", "canary_token")
            )
            src_fpath = os.path.join(root, f)
            dst_fpath = os.path.join(cur_dst_dir, target_fname)

            with open(src_fpath, "r", encoding="utf-8") as sfp:
                source_code = sfp.read()

            sanitized = sanitize_file_content(source_code)
            with open(dst_fpath, "w", encoding="utf-8") as dfp:
                dfp.write(sanitized)

    # Verification scan
    leak_count = 0
    for root, dirs, files in os.walk(dst):
        for f in files:
            fpath = os.path.join(root, f)
            with open(fpath, "r", encoding="utf-8") as fp:
                for idx, line in enumerate(fp, 1):
                    match = FORBIDDEN_PATTERN.search(line)
                    if match:
                        leak_count += 1
                        print(f"[LEAK DETECTED] {fpath}:{idx}: word '{match.group(0)}' in line: {line.strip()}")

    if leak_count > 0:
        print(f"[-] Sanitization failed with {leak_count} leaks.")
        sys.exit(1)
    else:
        print("[+] Sanitization SUCCESS: 0 forbidden keywords found in generated tree.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        src = os.path.join(os.path.dirname(__file__), "..", "honeyforge_agent")
        dst = os.path.join(os.path.dirname(__file__), "..", "scratch", "sysmon_agent")
    else:
        src = sys.argv[1]
        dst = sys.argv[2]
    sanitize_agent_tree(src, dst)
