import re

stripped = 'query = "UPDATE users SET email = \'{}\'WHERE id = {}".format(new_email, user_id)'
print('stripped:', repr(stripped))

# Current pattern
pat = re.compile(r"""['""][^'""\n]*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^'""\n]*?['"]\s*\.format\s*\(""", re.IGNORECASE)
m = pat.search(stripped)
print('current match:', m)

# Try broader pattern - just .format( anywhere on line containing SQL keyword
pat2 = re.compile(r"""\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\.format\s*\(""", re.IGNORECASE)
m2 = pat2.search(stripped)
print('broad match:', m2)
