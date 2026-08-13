import re

code = """
String query = "SELECT * FROM users WHERE username = '" + u + "' AND password = '" + p + "'";
MessageDigest md = MessageDigest.getInstance("MD5");
"""

# SQLI CONCAT
_SQLI_CONCAT = re.compile(
    r"""['"][^'"\n]*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^'"\n]*?['"]\s*\+""",
    re.IGNORECASE,
)
print("SQLI CONCAT:", _SQLI_CONCAT.search(code))

_SQLI_CONCAT_NEW = re.compile(
    r"""(['"]).*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\1\s*\+""",
    re.IGNORECASE,
)
print("SQLI CONCAT NEW:", _SQLI_CONCAT_NEW.search(code))

_WEAK_HASH = re.compile(
    r"""hashlib\.(md5|sha1)\b|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1)['"]""",
    re.IGNORECASE,
)
print("WEAK HASH:", _WEAK_HASH.search(code))

