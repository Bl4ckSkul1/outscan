"""
ModelJSModule — OutSystems model.js Entity Schema Exposure

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

OutSystems auto-generates model.js files containing the full database entity
schemas for each module. These files expose:
- Entity names, field names, data types, and relationships
- Sensitive entity structures (User, Password, Token, OIDC, etc.)
- Internal OutSystems platform schemas

No authentication is required to access model.js in a default configuration.
"""
import re
import json

from ..core import BaseModule, OutSystemsTester, truncate
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, msg_vuln_detail, subsection, progress_bar,
)
from ..data.os_common import (
    COMMON_MODULES, MODEL_JS_PATHS,
    SENSITIVE_FIELDS, SENSITIVE_ENTITIES,
)

REFERENCES = [
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "https://success.outsystems.com/Documentation/11/Developing_an_Application/Secure_the_Application/",
]

# These OutSystems internal modules appearing in model.js schemas indicate
# platform-internal data structures are being leaked
PLATFORM_INTERNAL_MODULES = {
    "ServiceCenter", "LifeTime", "EPA_TaskBox", "ECT_Provider",
    "RichWidgets", "Users", "SAMLAuthentication", "LDAPAuthentication",
    "OIDC_Provider", "ADAuthenticationPlugin",
}


class ModelJSModule(BaseModule):
    NAME        = "model_js"
    DESCRIPTION = "model.js entity schema extraction and analysis"

    def run(self) -> None:
        subsection("model.js — Entity Schema Exposure")
        msg_info("Searching for OutSystems model.js files exposing database schemas")

        modules_to_test = self._get_target_modules()
        total_entities_found = 0
        files_found = 0

        for module in modules_to_test:
            result = self._test_module(module)
            if result:
                files_found += 1
                total_entities_found += result.get("entity_count", 0)

        # Summary finding if multiple files found
        if files_found > 1:
            self.finding(
                severity="high",
                title=f"model.js exposed in {files_found} OutSystems modules",
                description=(
                    f"{files_found} model.js files were found exposing database entity "
                    f"schemas across {files_found} OutSystems modules. "
                    f"Total entities exposed: {total_entities_found}. "
                    "An attacker can map the entire application database structure "
                    "to craft targeted injection, IDOR, and data extraction attacks."
                ),
                evidence=f"Files found: {files_found}, total entities: {total_entities_found}",
                remediation=(
                    "Restrict access to model.js files via web server configuration. "
                    "Apply authentication requirements to static JavaScript resources "
                    "containing sensitive schema information."
                ),
                cwe="CWE-200",
                references=REFERENCES,
            )
        elif files_found == 0:
            msg_info("No accessible model.js files found")
            self.finding(
                severity="info",
                title="No accessible model.js files found",
                description="model.js files were not found at expected paths.",
                evidence="Probed all MODULE_JS_PATHS for all known modules",
                cwe="CWE-200",
            )

    # ─── Per-module testing ───────────────────────────────────────────────────

    def _test_module(self, module: str) -> dict | None:
        """
        Try all known model.js path patterns for a module.
        Returns analysis results if found, None otherwise.
        """
        for path_template in MODEL_JS_PATHS:
            path = path_template.replace("{module}", module)
            url = self.tester.base_url + path

            resp = self.tester.get(url)
            if resp is None:
                continue

            if resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")
            body = resp.text or ""

            # Validate it looks like a model.js (not a generic 200 page)
            if not self._is_model_js(body):
                continue

            msg_warn(f"  model.js found: {url} ({len(body)} bytes)")
            return self._analyze_model_js(module, url, body)

        return None

    def _is_model_js(self, content: str) -> bool:
        """
        Heuristic: does this look like an OutSystems model.js file?
        """
        os_patterns = [
            r"OutSystems\.Internal",
            r"OSApplication",
            r"OSModule",
            r"EntityName",
            r"AttributeName",
            r"EntityIdentifier",
            r'"entities"',
            r'"Entities"',
            r"define\s*\(",              # RequireJS define pattern
            r'"dataTypes"',
            r"screenservices",
            r"moduleservices",
            r"OutSystemsPlatform",
        ]
        matched = sum(
            1 for p in os_patterns
            if re.search(p, content[:5000], re.IGNORECASE)
        )
        return matched >= 2

    # ─── Schema extraction ────────────────────────────────────────────────────

    def _analyze_model_js(self, module: str, url: str, content: str) -> dict:
        """
        Extract entity schemas from model.js and assess sensitivity.
        """
        entities = self._extract_entities(content)
        sensitive_entities_found = []
        sensitive_fields_found = []
        oidc_secrets_found = []
        platform_internals_found = []

        # Analyze each entity
        for entity in entities:
            entity_name = entity.get("name", "")

            # Check if entity is flagged as sensitive by name
            for sens_ent in SENSITIVE_ENTITIES:
                if sens_ent.lower() in entity_name.lower():
                    sensitive_entities_found.append(entity_name)
                    break

            # Check if entity belongs to a platform-internal module
            entity_module = entity.get("module", "")
            if entity_module in PLATFORM_INTERNAL_MODULES:
                platform_internals_found.append(f"{entity_module}.{entity_name}")

            # Check fields for sensitive names
            for field_info in entity.get("fields", []):
                field_name = field_info.get("name", "").lower()
                for sens_field in SENSITIVE_FIELDS:
                    if sens_field in field_name:
                        sensitive_fields_found.append(
                            f"{entity_name}.{field_info.get('name', '')}"
                        )
                        break

            # Check for OIDC/OAuth secrets
            if any(kw in entity_name.lower() for kw in ("oidc", "oauth", "provider", "secret")):
                oidc_secrets_found.append(entity_name)

        # Also do raw text search for secrets in the JS
        raw_secrets = self._find_raw_secrets(content)

        # Store entities in tester state
        self.tester.os_entities[module] = entities

        # ─── Generate findings ────────────────────────────────────────────

        # Base finding: model.js exposed
        severity = "high" if sensitive_entities_found or sensitive_fields_found else "medium"
        self.finding(
            severity=severity,
            title=f"model.js exposed — {len(entities)} entities in module {module}",
            description=(
                f"The file {url} exposes the complete database entity schema for "
                f"OutSystems module '{module}'. "
                f"{len(entities)} entities with their field names, types, and "
                "relationships are publicly accessible without authentication. "
                "This enables an attacker to construct targeted data extraction, "
                "IDOR, and injection attacks."
            ),
            evidence=(
                f"URL: {url}\n"
                f"Entity count: {len(entities)}\n"
                f"Sample entities: "
                f"{', '.join(e.get('name','?') for e in entities[:10])}"
            ),
            request_data=self._request_summary("GET", url),
            response_data={
                "status":        200,
                "content_length": len(content),
                "entity_count":  len(entities),
            },
            remediation=(
                "1. Block access to model.js via web server rules (IIS / nginx). "
                "2. Apply authentication requirements to all *.js files under /{module}/. "
                "3. If model.js must be accessible, ensure it does not expose internal "
                "schema details for sensitive entities. "
                "4. Review OutSystems 'Restrict Access to Script Files' configuration."
            ),
            cwe="CWE-200",
            references=REFERENCES,
        )

        # Sensitive entity finding
        if sensitive_entities_found:
            msg_vuln(
                "high",
                f"Sensitive entities in model.js: {', '.join(sensitive_entities_found[:6])}",
            )
            self.finding(
                severity="high",
                title=(
                    f"Sensitive entity schemas exposed in {module}/model.js: "
                    f"{', '.join(sensitive_entities_found[:5])}"
                ),
                description=(
                    f"The following sensitive entities are exposed in module {module}'s "
                    f"model.js: {', '.join(sensitive_entities_found)}. "
                    "Knowing the field names and structure of these entities enables "
                    "targeted data extraction, SQL injection tuning, and IDOR exploitation."
                ),
                evidence=f"Sensitive entities: {', '.join(sensitive_entities_found)}",
                remediation=(
                    "Ensure model.js is not accessible without authentication. "
                    "Consider using OutSystems obfuscation settings for production deployments."
                ),
                cwe="CWE-200",
                references=REFERENCES,
            )

        # Sensitive fields finding
        if sensitive_fields_found:
            field_str = ", ".join(sensitive_fields_found[:10])
            msg_vuln("high", f"Sensitive fields exposed: {field_str}")
            self.finding(
                severity="high",
                title=f"Sensitive field names exposed in {module}/model.js",
                description=(
                    f"Sensitive field names are exposed in model.js for module {module}: "
                    f"{field_str}. "
                    "Field names matching password, token, secret, key, and PII patterns "
                    "are present in the schema, aiding targeted attacks."
                ),
                evidence=f"Sensitive fields: {field_str}",
                remediation=(
                    "Block model.js access. "
                    "Sensitive entity structures (User credentials, tokens, keys) "
                    "should never be accessible in client-side JavaScript."
                ),
                cwe="CWE-200",
                references=REFERENCES,
            )

        # Platform-internal schemas
        if platform_internals_found:
            intern_str = ", ".join(platform_internals_found[:8])
            self.finding(
                severity="medium",
                title=f"OutSystems platform-internal schemas exposed: {intern_str}",
                description=(
                    "Internal OutSystems platform module schemas are exposed via model.js. "
                    f"Entities from platform modules: {intern_str}. "
                    "Knowledge of platform-internal schemas can facilitate targeted attacks "
                    "against OutSystems platform infrastructure."
                ),
                evidence=f"Platform-internal entities: {intern_str}",
                remediation="Restrict model.js access to authenticated sessions only.",
                cwe="CWE-200",
                references=REFERENCES,
            )

        # OIDC/OAuth secret finding
        if oidc_secrets_found:
            msg_vuln("critical", f"OIDC/OAuth configuration entities exposed: {', '.join(oidc_secrets_found)}")
            self.finding(
                severity="critical",
                title=f"OIDC/OAuth configuration schemas exposed in {module}/model.js",
                description=(
                    f"Entities related to OIDC/OAuth configuration are exposed in model.js: "
                    f"{', '.join(oidc_secrets_found)}. "
                    "OutSystems stores ClientSecret and PrivateKey values in these entities. "
                    "If these values are accessible via the viewName bypass or an exposed "
                    "server action, complete OIDC provider compromise is possible."
                ),
                evidence=f"OIDC entities: {', '.join(oidc_secrets_found)}",
                remediation=(
                    "IMMEDIATE: Restrict model.js access. "
                    "Rotate all OIDC/OAuth client secrets and private keys. "
                    "Audit OIDC_Provider entity access via screenservice logs."
                ),
                cwe="CWE-200",
                references=REFERENCES + [
                    "https://cwe.mitre.org/data/definitions/312.html",
                ],
            )

        # Raw secrets in JS
        if raw_secrets:
            secret_str = "; ".join(raw_secrets[:5])
            msg_vuln("critical", f"Hardcoded secrets/tokens found in model.js")
            self.finding(
                severity="critical",
                title=f"Hardcoded secrets/tokens in {module}/model.js",
                description=(
                    f"Potential hardcoded secrets or tokens found directly in model.js "
                    f"for module {module}: {secret_str}. "
                    "These may include API keys, OIDC secrets, or authentication tokens."
                ),
                evidence=f"Raw secrets: {secret_str}",
                remediation=(
                    "IMMEDIATE: Rotate all exposed secrets. "
                    "Remove hardcoded secrets from JavaScript files. "
                    "Use OutSystems Settings/Site Properties for sensitive configuration."
                ),
                cwe="CWE-312",
                references=REFERENCES + [
                    "https://cwe.mitre.org/data/definitions/312.html",
                ],
            )

        return {
            "module":        module,
            "url":           url,
            "entity_count":  len(entities),
            "sensitive":     sensitive_entities_found,
            "raw_secrets":   raw_secrets,
        }

    # ─── Parsing helpers ──────────────────────────────────────────────────────

    def _extract_entities(self, content: str) -> list[dict]:
        """
        Extract entity definitions from model.js content.
        OutSystems model.js uses a proprietary structure — we use regex
        heuristics to extract entity/attribute information.
        """
        entities = []

        # Pattern 1: JSON-like entity blocks
        # OutSystems 11: {"name":"EntityName","module":"ModuleName","attributes":[...]}
        for m in re.finditer(
            r'\{[^{}]*"[Nn]ame"\s*:\s*"([A-Za-z][A-Za-z0-9_]{1,60})"'
            r'[^{}]*"[Mm]odule"\s*:\s*"([A-Za-z][A-Za-z0-9_.]{1,60})"'
            r'[^{}]*\}',
            content
        ):
            entity = {
                "name":   m.group(1),
                "module": m.group(2),
                "fields": [],
                "raw":    m.group(0)[:200],
            }
            entities.append(entity)

        # Pattern 2: OutSystems React/ODC style entity definitions
        for m in re.finditer(
            r'EntityIdentifier\s*:\s*["\']([A-Za-z][A-Za-z0-9_]{1,60})["\']',
            content
        ):
            entity = {"name": m.group(1), "module": "", "fields": [], "raw": ""}
            # Avoid duplicates
            if not any(e["name"] == entity["name"] for e in entities):
                entities.append(entity)

        # Pattern 3: define/require module style
        for m in re.finditer(
            r'"([A-Za-z][A-Za-z0-9_]{2,50})"\s*:\s*\{[^}]*"[Aa]ttribute',
            content
        ):
            name = m.group(1)
            if name not in ("module", "require", "exports", "define"):
                entity = {"name": name, "module": "", "fields": [], "raw": ""}
                if not any(e["name"] == name for e in entities):
                    entities.append(entity)

        # Extract field names for each entity (best-effort)
        for entity in entities:
            entity["fields"] = self._extract_fields(content, entity["name"])

        return entities

    def _extract_fields(self, content: str, entity_name: str) -> list[dict]:
        """Extract field/attribute names for a specific entity."""
        fields = []

        # Look for attribute blocks near the entity name mention
        # OutSystems: {"AttributeName":"FieldName","DataType":"Text",...}
        pattern = (
            r'"AttributeName"\s*:\s*"([A-Za-z][A-Za-z0-9_]{1,60})"'
            r'(?:[^{}]*"DataType"\s*:\s*"([A-Za-z][A-Za-z0-9_]{1,30})")?'
        )
        # Find within ±2000 chars of entity name
        entity_idx = content.find(f'"{entity_name}"')
        if entity_idx == -1:
            return fields

        window = content[max(0, entity_idx - 200): entity_idx + 3000]
        for m in re.finditer(pattern, window):
            fields.append({
                "name":      m.group(1),
                "data_type": m.group(2) or "unknown",
            })

        return fields[:50]  # cap at 50 fields per entity

    def _find_raw_secrets(self, content: str) -> list[str]:
        """
        Search for hardcoded secrets/tokens directly in model.js content.
        """
        found = []
        secret_patterns = [
            (r'"[Cc]lient[Ss]ecret"\s*:\s*"([^"]{8,})"',     "ClientSecret"),
            (r'"[Pp]rivate[Kk]ey"\s*:\s*"([^"]{16,})"',      "PrivateKey"),
            (r'"[Aa]pi[Kk]ey"\s*:\s*"([^"]{8,})"',           "ApiKey"),
            (r'"[Aa]ccess[Tt]oken"\s*:\s*"([^"]{10,})"',      "AccessToken"),
            (r'"[Ss]ecret"\s*:\s*"([a-zA-Z0-9+/=]{16,})"',   "Secret"),
            (r'"password"\s*:\s*"([^"]{4,})"',                "Password"),
            (r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}', "JWT"),
            (r'["\']?[A-Za-z0-9+/]{40,}={0,2}["\']',         "Base64 blob (potential key)"),
        ]
        for pattern, label in secret_patterns:
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                val = m.group(1) if m.lastindex else m.group(0)
                redacted = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "***"
                found.append(f"{label}: {redacted}")
        return found

    def _get_target_modules(self) -> list[str]:
        """Return modules to test."""
        if self.options.get("module_name"):
            return [self.options["module_name"]]
        if self.tester.os_modules:
            return self.tester.os_modules
        return COMMON_MODULES[:20]
