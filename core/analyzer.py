"""
PromptSentry - Core Inspection & Scoring Engine
Performs multi-layered heuristic analysis, Shannon entropy scoring, and rule matching.
Author: Çınar (prox0959)
"""

import math
import re
from collections import Counter
from .rules import get_builtin_signatures
from .sanitizer import sanitize_prompt

def calculate_shannon_entropy(text: str) -> float:
    """
    TR: Metnin Shannon Bilgi Entropisini hesaplar.
    Yüksek entropi (> 4.8) rastgele şifrelenmiş veya gizlenmiş (obfuscated) veriyi işaret eder.
    Calculates Shannon Entropy in bits per character.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)

class PromptAnalyzer:
    def __init__(self, block_threshold: int = 50, alert_threshold: int = 30):
        self.block_threshold = block_threshold
        self.alert_threshold = alert_threshold
        self.signatures = get_builtin_signatures()

    def analyze(self, raw_prompt: str) -> dict:
        """
        TR: Prompt metnini analiz eder, tehdit skorunu hesaplar ve karar verir (ALLOW, ALERT, BLOCK).
        Performs multi-vector threat evaluation and returns verdict.
        """
        sanitized = sanitize_prompt(raw_prompt)
        text_to_scan = sanitized["clean_text"]
        
        threat_score = 0
        violations = []

        # 1. Zero-width character penalty
        if sanitized["invisible_chars_detected"] > 0:
            penalty = min(sanitized["invisible_chars_detected"] * 10, 40)
            threat_score += penalty
            violations.append({
                "rule_id": "PS-STEALTH-001",
                "category": "Zero-Width Obfuscation",
                "score_added": penalty,
                "detail": f"{sanitized['invisible_chars_detected']} invisible Unicode characters detected"
            })

        # 2. Shannon Entropy Analysis
        entropy = calculate_shannon_entropy(text_to_scan)
        if len(text_to_scan) > 40 and entropy > 4.85:
            penalty = 20
            threat_score += penalty
            violations.append({
                "rule_id": "PS-ENTROPY-001",
                "category": "High Entropy Payload",
                "score_added": penalty,
                "detail": f"Shannon Entropy: {entropy} bits/char (High randomness/encoding indicator)"
            })

        # 3. Embedded Base64 Analysis
        for blob in sanitized["embedded_base64_payloads"]:
            # Check if decoded payload contains injection patterns
            decoded_text = blob["decoded"]
            threat_score += 25
            violations.append({
                "rule_id": "PS-B64-001",
                "category": "Base64 Obfuscation Smuggling",
                "score_added": 25,
                "detail": f"Decoded hidden payload: '{decoded_text[:60]}...'"
            })
            # Also scan the decoded text directly
            text_to_scan += " " + decoded_text

        # 4. Pattern & Signature Matching
        for sig in self.signatures:
            for pat in sig["patterns"]:
                match = re.search(pat, text_to_scan, re.IGNORECASE)
                if match:
                    threat_score += sig["weight"]
                    violations.append({
                        "rule_id": sig["id"],
                        "category": sig["category"],
                        "score_added": sig["weight"],
                        "detail": f"Matched: '{match.group(0)}'",
                        "description": sig["description"]
                    })
                    break # Don't duplicate weight for same rule

        # Determine Verdict
        if threat_score >= self.block_threshold:
            verdict = "BLOCK"
        elif threat_score >= self.alert_threshold:
            verdict = "ALERT"
        else:
            verdict = "ALLOW"

        return {
            "verdict": verdict,
            "threat_score": min(threat_score, 100),
            "entropy": entropy,
            "violations_count": len(violations),
            "violations": violations,
            "sanitized_preview": text_to_scan[:120] + ("..." if len(text_to_scan) > 120 else ""),
            "is_blocked": verdict == "BLOCK"
        }
