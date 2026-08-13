"""
bad_python.py — Fixture with deliberately planted code-quality issues.
Used by test_code_analysis_agent.py to verify all 6 detectors fire.

Issues planted:
  1. God function `process_all_data` (200+ lines) → CRITICAL long_method
  2. Single-char variable `x`, `z`, generic name `data` → HIGH/MEDIUM poor_naming
  3. Cyclomatic complexity > 15 in `validate_input` → HIGH high_complexity
  4. Deep nesting depth 5 in `nested_logic` → HIGH deep_nesting
  5. Duplicate code blocks (lines ~20–30 copied at ~35–45) → HIGH duplicate_code
  6. Deep attribute chain `a.b.c.d.e` → HIGH deep_attribute_chain
"""

import os
import sys
import re
import json
import csv
import xml.etree.ElementTree as ET
import sqlite3
import hashlib
import hmac
import base64
import urllib.request
import urllib.parse


# ── Issue #6: high import fan-out (12 external-looking imports above) ────────


class DataProcessor:

    def process_all_data(self, data, x, temp):  # Issue #2: poor params
        """Issue #1: god function — this is deliberately 200+ lines."""
        result = []

        # ── Duplicate block A (lines ~28–37) ────────────────────────────────
        for item in data:
            if item is None:
                continue
            val = str(item).strip()
            if len(val) > 0:
                result.append(val.upper())
            else:
                result.append("EMPTY")

        # ... 10 lines of filler ...
        z = 0  # Issue #2: single-char var
        z += 1
        z += 2
        z += 3
        z += 4
        z += 5
        z += 6
        z += 7
        z += 8
        z += 9

        # ── Duplicate block B (near-copy of block A) ─────────────────────────
        for item in data:
            if item is None:
                continue
            val = str(item).strip()
            if len(val) > 0:
                result.append(val.upper())
            else:
                result.append("EMPTY")

        # ... more padding to push this well over 40 lines ...
        step1 = len(result)
        step2 = step1 * 2
        step3 = step2 + 1
        step4 = step3 - 1
        step5 = step4 / max(step1, 1)
        step6 = step5 ** 2
        step7 = abs(step6)
        step8 = round(step7, 2)
        step9 = str(step8)
        step10 = step9.encode("utf-8")
        step11 = base64.b64encode(step10)
        step12 = step11.decode("ascii")
        step13 = step12.replace("=", "")
        step14 = step13[:16]
        step15 = step14.upper()
        step16 = hashlib.md5(step15.encode()).hexdigest()
        step17 = step16[:8]
        step18 = int(step17, 16)
        step19 = step18 % 100
        step20 = float(step19)
        step21 = step20 / 100.0
        step22 = [step21] * step1
        step23 = sum(step22)
        step24 = step23 / max(len(step22), 1)
        step25 = round(step24, 4)
        step26 = str(step25)
        step27 = step26 + "_done"
        step28 = len(step27)
        step29 = step28 * step18
        step30 = str(step29)
        step31 = step30.zfill(10)
        step32 = list(step31)
        step33 = step32[::-1]
        step34 = "".join(step33)
        step35 = step34.strip("0")
        step36 = step35 or "0"
        step37 = int(step36)
        step38 = step37 + step18
        step39 = hex(step38)
        step40 = step39.replace("0x", "")
        step41 = step40.upper()
        step42 = step41[:4]
        step43 = step42.lower()
        step44 = step43 + "_final"
        step45 = {"result": result, "token": step44}
        step46 = json.dumps(step45)
        step47 = step46.encode("utf-8")
        step48 = base64.b64encode(step47)
        step49 = step48.decode("ascii")
        step50 = len(step49)
        step51 = step50 % 7
        step52 = step51 + step37
        step53 = str(step52)
        step54 = step53.zfill(6)
        step55 = step54 + step44
        step56 = step55.upper()
        step57 = step56.replace("_", "-")
        step58 = step57[:12]
        step59 = step58.lower()
        step60 = step59 + ".json"
        step61 = os.path.join("/tmp", step60)
        step62 = open(step61, "w")   # noqa: SIM115 intentionally unclosed
        step63 = step62.write(step46)
        step64 = step62.close()
        step65 = os.path.exists(step61)
        step66 = os.path.getsize(step61) if step65 else 0
        step67 = step66 > 0
        step68 = "written" if step67 else "failed"
        step69 = {"status": step68, "path": step61}
        return step69  # 140 lines of body


class Validator:

    def validate_input(self, v, user_type, role, env, feature_flag,
                       region, plan, tenant, version, debug):
        """
        Issue #3: cyclomatic complexity > 15.
        Issue #2: poor param names (v, env, role).
        """
        if v is None:
            return False
        if not isinstance(v, (str, int, float)):
            return False
        if user_type == "admin":
            if role == "superuser":
                if env == "prod":
                    if feature_flag:
                        if region == "us-east":
                            if plan == "enterprise":
                                return True
                            elif plan == "pro":
                                return True
                            else:
                                return False
                        elif region == "eu-west":
                            return True
                        else:
                            return False
                    else:
                        return False
                elif env == "staging":
                    return True
                else:
                    return False
            elif role == "manager":
                if tenant and version:
                    return True
                return False
            else:
                return False
        elif user_type == "user":
            if debug:
                return True
            return isinstance(v, str) and len(v) > 0
        elif user_type == "guest":
            return False
        return False


class NestedLogic:

    def nested_logic(self, records):
        """Issue #4: nesting depth 5."""
        output = []
        for record in records:                                 # depth 1
            if record.get("active"):                          # depth 2
                for field in record.get("fields", []):        # depth 3
                    if field.get("required"):                 # depth 4
                        for value in field.get("values", []): # depth 5
                            if value:
                                output.append(value)
        return output


class ChainViolator:

    def get_city(self, order):
        """Issue #6: deep attribute chain (Law of Demeter violation)."""
        # a.b.c.d.e — depth 5
        return order.customer.address.location.city.name


def standalone():
    """
    Issue #5 (duplicate): same block as inside process_all_data.
    Plain function to ensure the detector fires on a file-level duplicate.
    """
    data = [1, 2, None, 4]   # Issue #2: generic name `data`
    result = []
    for item in data:
        if item is None:
            continue
        val = str(item).strip()
        if len(val) > 0:
            result.append(val.upper())
        else:
            result.append("EMPTY")
    return result
