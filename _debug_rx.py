import re
import sys
sys.path.insert(0, 'lib')
import audit_core as a

rules = a.load_rules(None)
p = [r for r in rules['pii'] if r['id'] == 'abs_windows_path'][0]
print('规则 pattern:', repr(p['pattern']))
print('编译后 pattern:', repr(p['_re'].pattern))

BS = chr(92)
target = 's:' + BS + 'n'
print('\n目标串:', repr(target), '字节:', list(target.encode()))

m = p['_re'].search(target)
print('匹配结果:', m)
if m:
    print('命中片段:', repr(m.group(0)))
