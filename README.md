# Module 8 Final Project - Secret Scanner
**Author:** Jeremy Nally  
**Course:** SDEV245 - Security and Secure Coding  



Copy and Paste of Assignment (delete this later)

Module 8 Final Project - Secret Scanner
Due: Sat May 9, 2026 11:59pmDue: Sat May 9, 2026 11:59pm
Ungraded, 200 Possible Points
200 Points Possible
Attempt
Attempt 1

In Progress
NEXT UP: Submit Assignment

Unlimited Attempts Allowed
Get Ready
Students will build a simple application with user login and role-based access control. This demonstrates the implementation of basic authentication and access restrictions based on role.

This assignment will support the following outcomes:

7.1 Identify relevant mitigation strategies in regards to current OWASP Top 10 threats
9.3 Mitigate injection vulnerabilities that are identified using provided code samples.
10.1 List key components of an effective software security policy.
10.2 Develop a draft security policy addressing secure SDLC requirements.
Supportive Materials
To be successful with this assignment, you must complete each of the materials listed on the Learning Materials page. 

 

Complete Your Work
Instructions:
For the final project, create a Python-based CLI tool that scans files or directories for common patterns indicating hardcoded secrets, such as:

API keys

Passwords

Tokens

Private keys

Requirements:
Accept a directory path or file as input

Use regex to detect common secret patterns

Output a report of findings (filename, line number, matched string)

Include logging and a clear CLI interface (argparse)

README with explanation of detection logic and usage

Example Patterns to Include:
Use this webpage as a resource for patterns to check for (include a minimum of 5): regextokensLinks to an external site. 
Deliverables:
Code files (GitHub link)

README (brief explanation of your app's logic)

(REQUIRED) 1-minute screen recording showing the scanning and results in real time

Rubric
To see how you will be assessed with this assignment, review the associated rubric.

If you have any questions about assignment expectations, it is always best to ask early.

 

Submit Your Assignment
Find the "Choose a submission type" section at the bottom of this assignment page (if this section is not displayed, the submission type has been chosen for you). Choose your submission type from the options listed there.
Complete the assignment for the chosen Submission Type.
Click the Submit Assignment button to submit.
Please see "How do I submit an online assignment?" or contact your instructor if you need assistance.

Secret Scanner Rubric
Secret Scanner Rubric
Criteria	Ratings	Points
Input Handling (File/Directory via CLI)

Full Marks
Accepts both files and directories robustly using argparse, with clear validation, help messages, and error handling
30 pts

Partial Credit
Accepts input but lacks validation or clarity in CLI interface
15 pts

No Marks
Fails to handle input properly or does not use argparse
0 pts
/30 pts
Regex-Based Secret Detection

Full Marks
Implements at least 5 strong regex patterns with good coverage and low false positives
40 pts

Partial Credit
Fewer than 5 patterns or regex is too broad/ineffective
20 pts

No Marks
No regex detection or ineffective matching
0 pts
/40 pts
Output Report (Filename, Line, Match)

Full Marks
Outputs a clean, organized report with filename, line number, and matched string
30 pts

Partial Credit
Output is present but incomplete or unclear
15 pts

No Marks
No output or unusable output
0 pts
/30 pts
Logging & CLI Design

Full Marks
Includes useful logging (e.g., for errors or progress); CLI interface is clear and user-friendly
30 pts

Partial Credit
Logging or CLI present but poorly implemented
15 pts

No Marks
No logging and CLI is difficult or missing
0 pts
/30 pts
README (Detection Logic & Usage)

Full Marks
README clearly explains purpose, regex logic, usage examples, limitations, and how to run the tool
40 pts

Partial Credit
README is present but vague, missing sections, or lacks clarity
20 pts

No Marks
No README or extremely minimal content
0 pts
/40 pts
Code Quality & Documentation

Full Marks
Code is clean, modular, well-structured, and well-commented with consistent styling
30 pts

Partial Credit
Code mostly works but has unclear structure or lacks comments
15 pts

No Marks
Code is messy, poorly structured, or difficult to understand
0 pts
/30 pts
Choose a submission type
