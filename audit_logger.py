"""
Enclave - Güvenlik Denetim Günlüğü (Security Audit Logger)
Tüm kilit açma, parola denemesi, panik tetiklenmesi, dosya parçalama ve
sistem izi temizleme olaylarını JSON formatında kaydeder ve raporlar.
"""

import os
import json
import csv
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

AUDIT_LOG_FILE = Path(__file__).parent / "logs" / "audit_log.json"

def _ensure_dir():
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def log_security_event(
    event_type: str,
    severity: str = "INFO",
    details: str = "",
    vault_path: str = "",
    drive_letter: str = ""
) -> Dict[str, Any]:
    """Güvenlik olayını denetim günlüğüne ekler."""
    _ensure_dir()
    
    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "timestamp": timestamp_str,
        "epoch": time.time(),
        "event_type": event_type,
        "severity": severity.upper(),
        "details": details,
        "vault_name": Path(vault_path).name if vault_path else "-",
        "drive_letter": drive_letter or "-"
    }
    
    events = []
    if AUDIT_LOG_FILE.exists():
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
                if not isinstance(events, list):
                    events = []
        except Exception:
            events = []
            
    events.append(record)
    if len(events) > 500:
        events = events[-500:]
        
    try:
        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Denetim günlüğü yazılamadı: {e}")
        
    return record

def get_audit_events(limit: int = 100) -> List[Dict[str, Any]]:
    """En son güvenlik olaylarını ters kronolojik sırada döndürür."""
    if not AUDIT_LOG_FILE.exists():
        return []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            events = json.load(f)
            if isinstance(events, list):
                return list(reversed(events[-limit:]))
    except Exception:
        pass
    return []

def clear_audit_events() -> bool:
    """Tüm denetim kayıtlarını adli standartta güvenle sıfırlar ve boş liste ile yeniden oluşturur."""
    _ensure_dir()
    try:
        from enclave_core import secure_wipe_file
        if AUDIT_LOG_FILE.exists():
            secure_wipe_file(str(AUDIT_LOG_FILE), passes=1)
        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
        return True
    except Exception:
        return False

def export_audit_csv(target_path: str) -> bool:
    """Denetim günlüğünü CSV olarak dışa aktarır."""
    events = get_audit_events(limit=500)
    if not events:
        return False
    try:
        with open(target_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Tarih / Saat", "Olay Tipi", "Seviye", "Kasa", "Sürücü", "Detay"])
            for e in reversed(events):
                writer.writerow([
                    e.get("timestamp", ""),
                    e.get("event_type", ""),
                    e.get("severity", ""),
                    e.get("vault_name", ""),
                    e.get("drive_letter", ""),
                    e.get("details", "")
                ])
        return True
    except Exception as e:
        print(f"Audit CSV dışa aktarılamadı: {e}")
        return False
