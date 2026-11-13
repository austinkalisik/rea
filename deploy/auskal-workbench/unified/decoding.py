"""Bounded constant-only JavaScript rewriting. Never evals or imports a target."""
import base64,json,re
ATOB=re.compile(r'''(?<![\w$.])(?:window\.)?atob\(\s*["']([A-Za-z0-9+/=]{8,1000})["']\s*\)''')
CHARS=re.compile(r'(?<![\w$.])String\.fromCharCode\(\s*([0-9a-fA-FxX, \t]{1,1500})\s*\)')
def decode_js(text):
 count=0
 def atob(m):
  nonlocal count
  try:value=base64.b64decode(m.group(1),validate=True).decode('utf8')
  except (ValueError,UnicodeError):return m.group(0)
  count+=1;return json.dumps(value,ensure_ascii=True)
 def chars(m):
  nonlocal count
  try:
   parts=[p.strip() for p in m.group(1).split(',')]
   if len(parts)>200 or any(not re.fullmatch(r'(?:[0-9]+|0[xX][0-9a-fA-F]+)',p) for p in parts):return m.group(0)
   values=[int(p,16 if p.lower().startswith('0x') else 10) for p in parts]
   if any(n<0 or n>65535 for n in values):return m.group(0)
   value=''.join(chr(n) for n in values)
  except ValueError:return m.group(0)
  count+=1;return json.dumps(value,ensure_ascii=True)
 text=ATOB.sub(atob,text);text=CHARS.sub(chars,text)
 return text,count
