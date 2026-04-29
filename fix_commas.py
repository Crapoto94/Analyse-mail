with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix missing commas in dicts
old1 = "\"{'success': False, 'message'\"}"
new1 = "\"{'success': False, 'message'\"}"
content = content.replace(old1, new1)

old2 = "\"{'success': 0, 'failed'\"}"
new2 = "\"{'success': 0, 'failed'\"}"
content = content.replace(old2, new2)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('Fixed missing commas')
