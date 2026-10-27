import sys
sys.path.insert(0, 'lib')
import audit_core as a

rules = a.load_rules(None)
p = [r for r in rules['pii'] if r['id'] == 'abs_windows_path'][0]
rx = p['_re']

NL = chr(92) + 'n'
BS = chr(92)

cases = [
    ('s:' + BS + 'n', False, '转义换行符 s:\\n'),
    ('d:' + BS + 'n{details}', False, '转义+占位 d:\\n{details}'),
    ('s:' + BS + 'n' + BS + 'nConversations', False, '多重转义'),
    ('C:' + BS + 'Users' + BS + 'alice' + BS + 'Documents', True, '真实用户路径'),
    ('F:' + BS + 'Temp' + BS + 'renpu-vault', True, '真实 F 盘路径'),
    ('C:' + BS + 'Windows' + BS + 'System32', True, '系统路径'),
    ('C:' + BS + 'ProgramData' + BS + 'ClaudeCode' + BS + 'managed-settings.json', True, '配置文件路径'),
]

bad = 0
for text, should, note in cases:
    m = rx.search(text)
    got = bool(m)
    ok = got == should
    if not ok:
        bad += 1
    print(('OK ' if ok else 'BAD'), note, '->', got, '(期望', should, ')')

print('异常数:', bad)
sys.exit(1 if bad else 0)
