# ALU Regex Data Extraction and Secure Validation

## What This Project Does

This program reads a raw text file that looks like it came from a real company system.
It then scans through the text and pulls out specific types of data like emails, phone numbers,
credit card numbers, and URLs using regex patterns.
After extracting the data, it checks if anything looks dangerous or fake, and saves the clean results to a JSON file.

## How to Run It

You need Python 3.8 or higher. No extra installs needed.

Open your terminal in the project folder and run:

```bash
python3 src/main.py
```

The results will print in your terminal and a JSON file will be saved automatically in the output folder.

## Project Structure
alu-regex-data-extraction-tmaulidi-arch/
├── input/
│   └── raw-text.txt          <- the raw messy text the program reads
├── src/
│   └── main.py               <- the main program with all the logic
├── output/
│   └── sample-output.json    <- the results, generated when you run the program
└── README.md
## What the Program Extracts

The program uses regex to find and extract these 8 types of data:

- *Emails - finds all email addresses and sorts them by ALU category
- *URLs - finds web links but only accepts http, https, and ftp
- *Phone numbers- handles international formats like +250 and local formats like 0712
- *Credit card numbers- finds card numbers and checks if they are mathematically valid
- *Times- finds both 12-hour format like 9:00 AM and 24-hour format like 22:30
- *HTML tags- finds all HTML tags like `<h1>` and `<div>`
- *Hashtags - finds hashtags that start with a letter like #ALU2024
- *Currency- finds dollar amounts like $12,500.00

## ALU Email Validation

Every email found is checked and sorted into one of these four groups:

- `alu_official` - ends with @alueducation.com
- `alu_alumni` - ends with @alumni.alueducation.com
- `alu_si` - ends with @si.alueducation.com
- `external` - any other valid email like Gmail or Yahoo

## Security

The program does not trust any input. Here is how it protects against bad data:

- It detects and rejects dangerous content like JavaScript injection and SQL injection
- It blocks URLs that point to private or internal IP addresses
- It uses the Luhn algorithm to check if a credit card number is mathematically valid
- It masks emails in the output so only the first 2 characters are visible
- It masks credit card numbers so only the last 4 digits are visible
- It refuses to process files that are larger than 500,000 characters
