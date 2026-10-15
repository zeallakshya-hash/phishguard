# PhishGuard

PhishGuard is a real-time, rule-based phishing detection web application. It evaluates URLs against known phishing indicators across the URL structure, domain registration information, and page content using a weighted heuristic engine.

## Features

- **URL Analysis**: Detects IP usage, excessive length, at-symbols, shorteners, excessive subdomains, and hyphenated domains.
- **Domain Analysis**: Inspects WHOIS records for domain age (flags newly registered domains) and registration anomalies, and checks for SSL certificate validity.
- **Content Analysis**: Scrapes page content to detect insecure login forms, mismatched favicons, external form targets, hidden iFrames, and right-click blocking.
- **Dynamic Dashboard**: A modern, glassmorphism-themed UI that displays an itemized threat assessment and total risk score.

## Installation

1. Ensure you have Python 3 installed.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Flask application:
   ```bash
   python app.py
   ```
4. Open your browser and navigate to `http://127.0.0.1:5000/`.

## Configuration (API Keys)

PhishGuard integrates with external APIs to enhance detection. Create a `.env` file in the root directory (you can copy `.env.example`) and add your API keys:

```ini
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```
If these keys are not provided, PhishGuard will gracefully fall back to using only its local heuristic engine.

## Architecture

- **`app.py`**: The main Flask application that serves the frontend and handles the API request.
- **`engine/scoring.py`**: The core scoring engine that weighs the results of the analyzers to generate a risk score.
- **`rules/`**: Modules handling specific feature extractions:
  - `url_analyzer.py`
  - `domain_analyzer.py`
  - `content_analyzer.py`
- **Frontend**: Custom HTML/CSS/JS in the `templates/` and `static/` directories providing a responsive and interactive user experience.

## Disclaimer

This is a heuristic-based tool intended for educational purposes and should not be the sole mechanism for validating the safety of a website.
