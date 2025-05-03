#!/usr/bin/env python3
from random import randint, choice
import sys

from secret import flag  # Import the flag from a secret module

def main():
    """
    Main function to handle the arithmetic challenge.
    The user must solve 128 arithmetic problems to retrieve the flag.
    """
    print("Username:")
    username = input().strip()

    # Check if the username is valid
    if username != "player":
        print("Access denied.")
        sys.exit(1)

    # Define the possible operators
    ops = ['+', '-', '*']

    # Generate and validate 128 arithmetic challenges
    for i in range(128):
        a = randint(1, 100)  # Generate the first operand
        b = randint(1, 100)  # Generate the second operand
        op = choice(ops)  # Randomly select an operator

        # Formulate the question and calculate the correct answer
        question = f"{a} {op} {b}"
        correct = eval(question)

        # Display the challenge to the user
        print(f"Challenge {i+1}: {question} = ?")
        try:
            # Get the user's answer
            answer = input().strip()
            if int(answer) != correct:
                print("Wrong answer. Bye!")
                sys.exit(1)
        except:
            print("Invalid input. Bye!")
            sys.exit(1)

    # If all challenges are solved correctly, display the flag
    print(f"Congratulations! Here is your flag: {flag}")

if __name__ == "__main__":
    main()
