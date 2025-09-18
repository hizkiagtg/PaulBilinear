import random
import string
from charm.core.engine.util import objectToBytes

def measure_size(obj, group):
    """Measures the size of a charm object in bytes."""
    return len(objectToBytes(obj, group))

def generate_random_message(length=2):
    """Generates a random message of a given length."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def print_table(headers, rows, title=""):
    """Prints a simple formatted table to the console."""
    if not rows: return
    col_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]
    
    if title:
        print(f"\n--- {title} ---")
    
    header_row = " | ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
    print(header_row)
    print("-" * len(header_row))
    
    for row in rows:
        data_row = " | ".join(f"{str(item):<{w}}" for item, w in zip(row, col_widths))
        print(data_row)