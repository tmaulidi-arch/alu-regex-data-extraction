# ALU Regex Data Extraction

## Description
This program extracts structured data from raw text using regular expressions.
It also validates input for security threats and handles ALU specific email addresses.

## How to Run
1. Make sure Python is installed
2. Place your input text in input/raw-text.txt
3. Run the program with: python main.py
4. Results will be saved to output/sample-output.json

## Data Types Extracted
- Email addresses including ALU official, alumni and SI emails
- URLs
- Phone numbers
- Credit card numbers (masked for security)

## Security
- Detects XSS attacks
- Detects SQL injection attempts
- Masks credit card numbers in output# alu-regex-data-extraction