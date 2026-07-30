# ClickFix

ClickFix is a social engineering attack used to distribute malware by ransomware operators and APTs. The attack exploits a users basic understanding and general trust of Captcha based authentication mechanisms to coerce them into executing malware through PowerShell commands. The article below does a great deep dive into the attack. 

https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims/

This code consists of two main components. The first is a false shared file access page that asks a user to input their email address to access a shared file. 

![image](https://github.com/user-attachments/assets/2246b54e-cc16-4e36-af10-4f1099fb8029)

This page then redirects to the false Captcha page that attempts to coerce a user into using the Windows Run window to execute an encoded powershell command that is silently copied into the clipboard. 

![image](https://github.com/user-attachments/assets/70f4f70b-46ef-4939-9c93-1c19324768f6)

This can be modified to run any powershell payload for red team operations and social engineering engagement to replicate this attack vector. 
