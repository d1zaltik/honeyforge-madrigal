import os
import uuid
import random
import string
from typing import Dict, Any, List

def generate_synthetic_aws_key() -> Dict[str, str]:
    """Generates authentic-looking random AWS credentials without using known sample patterns."""
    access_id_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    access_key_id = f"AKIA{access_id_suffix}"
    
    # 40 chars of base64-like characters
    b64_chars = string.ascii_letters + string.digits + "+/"
    secret_access_key = ''.join(random.choices(b64_chars, k=40))
    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key
    }

# Alias for backward compatibility
generate_fake_aws_key = generate_synthetic_aws_key

def generate_synthetic_db_password() -> str:
    """Generates realistic complex password without recognizable CorpSecret templates."""
    words = ["vault", "sync", "master", "node", "core", "agent", "cluster", "cache"]
    specials = ["!", "@", "#", "$", "%", "&", "*"]
    w = random.choice(words).capitalize()
    num = random.randint(1024, 9999)
    spec = random.choice(specials)
    rnd_suffix = ''.join(random.choices(string.ascii_letters, k=4))
    return f"{w}{spec}{num}_{rnd_suffix}"

generate_fake_db_password = generate_synthetic_db_password

class HoneytokenManager:
    """
    FR-A6 (Bonus): Manages canary lure tokens planted across fake environments.
    Uses realistic decoy values and neutral cover URLs to prevent honeypot fingerprinting.
    """
    def __init__(self, trap_id: str, c2_url: str):
        self.trap_id = trap_id
        self.c2_url = c2_url
        self.tokens: List[Dict[str, Any]] = []

    def generate_default_tokens(self) -> List[Dict[str, Any]]:
        token_id = f"ht-{uuid.uuid4().hex[:8]}"
        aws_creds = generate_synthetic_aws_key()
        db_pwd = generate_synthetic_db_password()
        
        # Neutral cover domain and path - no honeyforge/c2/canary keywords
        neutral_cover_url = f"https://metrics.cdn-edge-sync.net/sync/{token_id}"
        
        self.tokens = [
            {
                "type": "aws_key",
                "path": "/root/.aws/credentials",
                "content": f"[default]\naws_access_key_id = {aws_creds['access_key_id']}\naws_secret_access_key = {aws_creds['secret_access_key']}\n",
                "description": "AWS Production Pipeline Access Key"
            },
            {
                "type": "canary_url",
                "path": "/var/www/internal_api.env",
                "content": f"METRICS_SYNC_ENDPOINT={neutral_cover_url}\n",
                "canary_url": neutral_cover_url,
                "token_id": token_id,
                "description": "Edge Metrics Sync Webhook Decoy"
            },
            {
                "type": "database_credential",
                "path": "/etc/mysql/my.cnf",
                "content": f"[client]\nuser=db_sync_admin\npassword={db_pwd}\nhost=10.0.5.12\n",
                "description": "MySQL Database Admin Canary Credentials"
            }
        ]
        return self.tokens

    def get_token_by_path(self, path: str) -> Dict[str, Any]:
        for t in self.tokens:
            if t.get("path") == path:
                return t
        return None

