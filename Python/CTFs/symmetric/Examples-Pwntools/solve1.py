from pwn import remote

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

# Authenticate with the server
r.recvuntil(b"Username:")
r.sendline(b"player")

# Read the remaining newline and discard it
r.recvline()

# Solve 128 arithmetic challenges
for _ in range(128):
    # Receive the challenge line
    line = r.recvline().decode()
    print("Received:", line.strip())

    # Parse the question to extract operands and operator
    parts = line.split(":")[1].split()
    a = int(parts[0])  # First operand
    operator = parts[1]  # Operator
    b = int(parts[2])  # Second operand

    # Calculate the result
    result = calculate(a, operator, b)

    # Send the result back to the server
    r.sendline(str(result).encode())

# Receive and print the final response (flag)
print(r.recvall().decode())
