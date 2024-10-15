import random

def generate_hex_string(length=24):
    hex_chars = '0123456789abcdef'
    return ''.join(random.choice(hex_chars) for _ in range(length))
for i in range(4):
    print(f"Example {i+1}: {generate_hex_string()}")
