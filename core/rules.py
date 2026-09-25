"""
PromptSentry - Attack Signature Database & Heuristics
Categorized rule definitions for LLM prompt injections, jailbreaks, and system prompt leaks.
Author: Çınar (prox0959)
"""

# TR: OWASP Top 10 for LLM (LLM01: Prompt Injection) Kuralları
SIGNATURES = [
    {
        "id": "PS-INJ-001",
        "category": "Instruction Override",
        "description": "Direct instruction ignore or reset attempt",
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules|prompts)",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)",
            r"forget\s+(all\s+)?(previous|prior)\s+(instructions|directives|context)",
            r"clear\s+(your\s+)?(instructions|memory|system\s+prompt)",
            r"reset\s+(your\s+)?(system|instructions|persona)"
        ],
        "weight": 55
    },
    {
        "id": "PS-INJ-002",
        "category": "System Prompt Exfiltration",
        "description": "Attempt to extract secret developer system prompts or instructions",
        "patterns": [
            r"(print|reveal|output|display|show|leak|repeat)\s+(the\s+)?(system\s+prompt|developer\s+message|initial\s+prompt)",
            r"what\s+(is|are)\s+your\s+(exact\s+)?(instructions|system\s+prompt|directives)",
            r"(what\s+was\s+written|what\s+is\s+written)\s+above",
            r"repeat\s+(the\s+)?(exact\s+)?words\s+(written\s+)?above",
            r"transcribe\s+your\s+system\s+instructions"
        ],
        "weight": 50
    },
    {
        "id": "PS-INJ-003",
        "category": "Persona Hijacking / DAN Mode",
        "description": "Roleplay bypass, DAN (Do Anything Now), or fictional framing",
        "patterns": [
            r"you\s+are\s+now\s+(in\s+)?(dan|jailbreak|evil|anarchist|unfiltered)\s+mode",
            r"do\s+anything\s+now",
            r"from\s+now\s+on\s+you\s+(will|must)\s+act\s+as",
            r"roleplay\s+as\s+an\s+unrestricted",
            r"pretend\s+you\s+have\s+no\s+(rules|ethics|guidelines|safety)",
            r"you\s+have\s+no\s+restrictions",
            r"always\s+comply\s+without\s+refusal"
        ],
        "weight": 55
    },
    {
        "id": "PS-INJ-004",
        "category": "Delimiter & Structural Tag Smuggling",
        "description": "Faked XML/HTML/Markdown delimiter boundaries to fool system parser",
        "patterns": [
            r"</?(system|developer|admin|root|instruction|context)>",
            r"\[/?system\]",
            r"={10,}\s*(system|admin|override)\s*={10,}",
            r"BEGIN\s+SYSTEM\s+PROMPT",
            r"END\s+SYSTEM\s+PROMPT"
        ],
        "weight": 50
    },
    {
        "id": "PS-INJ-005",
        "category": "Obfuscated / Encoded Payload",
        "description": "Hex, Base64, or ROT13 encoded instruction triggers",
        "patterns": [
            r"(decode|execute|eval)\s+this\s+(base64|hex|rot13|caesar)",
            r"eyJ[a-zA-Z0-9_\-]{20,}", # Common JWT or Base64 JSON header
            r"base64\.b64decode",
            r"rot_?13"
        ],
        "weight": 20
    }
]

def get_builtin_signatures() -> list:
    """Returns standard signature database."""
    return SIGNATURES
