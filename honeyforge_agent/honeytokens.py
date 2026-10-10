import os
import uuid
from typing import Dict, Any, List

class HoneytokenManager:
    """
    FR-A6 (Bonus): Manages canary lure tokens planted across fake environments.
    """
    def __init__(self, trap_id: str, c2_url: str):
        self.trap_id = trap_id
        self.c2_url = c2_url
        self.tokens: List[Dict[str, Any]] = []

    def generate_default_tokens(self) -> List[Dict[str, Any]]:
        canary_url_id = f"canary-{uuid.uuid4().hex[:8]}"
        self.tokens = [
            {
                "type": "aws_key",
                "path": "/root/.aws/credentials",
                "content": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                "description": "Production AWS Canary Access Key"
            },
            {
                "type": "canary_url",
                "path": "/var/www/internal_api.env",
                "content": f"SYNC_WEBHOOK_URL={self.c2_url}/canary/{canary_url_id}\n",
                "canary_url": f"{self.c2_url}/canary/{canary_url_id}",
                "description": "Internal Sync Webhook Canary URL"
            },
            {
                "type": "database_credential",
                "path": "/etc/mysql/my.cnf",
                "content": "[client]\nuser=db_sync_admin\npassword=CorpSecretDB!2026\nhost=10.0.5.12\n",
                "description": "MySQL Database Admin Canary Credentials"
            }
        ]
        return self.tokens

    def get_token_by_path(self, path: str) -> Dict[str, Any]:
        for t in self.tokens:
            if t.get("path") == path:
                return t
        return None
