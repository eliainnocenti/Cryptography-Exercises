from pwn import *

def calculate(a, operator, b):
    """
    Perform a basic arithmetic operation based on the given operator.
    Args:
        a (int): First operand.
        operator (str): Operator ('+', '-', '*').
        b (int): Second operand.
    Returns:
        int: Result of the operation.
    """
    if operator == '+':
        return a + b
    elif operator == '-':
        return a - b
    elif operator == '*':
        return a * b
    else:
        raise ValueError("Unsupported operator")

# Connect to the remote server
r = remote('130.192.5.212', 6500)

# Send the username to authenticate
r.sendlineafter(b'Username:', b'player')

# Solve 128 arithmetic challenges
for _ in range(128):
    # Receive the challenge line containing the arithmetic question
    line = r.recvline_contains(b" = ?").decode().strip()

    # Parse the question to extract operands and operator
    parts = line.split(":")[1].split()
    a = int(parts[0])  # First operand
    operator = parts[1]  # Operator
    b = int(parts[2])  # Second operand

    # Calculate the result
    result = calculate(a, operator, b)

    # Send the result back to the server
    r.sendline(str(result).encode())

# Receive and print the flag
flag = r.recvline_contains(b"CRYPTO25{").decode()
print(f"Flag: {flag}")
