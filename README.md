🔐 SecurePlus – AI Behavioral Biometrics Security System

A real-time cybersecurity defense system that continuously verifies users based on typing rhythm, mouse movement, click behavior, and face verification to detect intruders and prevent account takeovers.

📖 Table of Contents

Overview

Key Features

System Architecture

Tech Stack

Installation & Setup

API Endpoints

Screenshots

Future Enhancements

Contributing

Author

📋 Overview

SecurePlus represents the next generation of identity verification. Unlike static passwords, SecurePlus uses continuous behavioral authentication. By analyzing unique user patterns—such as typing pressure, mouse trajectory, and response latency—combined with AI anomaly detection and facial verification, it creates a dynamic Trust Score to secure sessions in real-time.

🚀 Key Features

🔐 Continuous Behavioral Authentication: Constantly monitors user actions, not just at login.

🧠 AI Anomaly Detection: Utilizes Isolation Forest to detect deviations from baseline behavior.

📍 Timezone & Location Tracking: Flags anomalies if access occurs from impossible locations or unusual timezones.

🖱️ Mouse & Click Analysis: Analyzes movement curves, speed, and click frequency.

⌨️ Keystroke Dynamics: Measures typing pressure, flight time, and dwell time.

⚠️ Dynamic Trust-Score System: Real-time scoring; low scores trigger defensive measures.

🪪 Face Registration & Verification: Biometric confirmation for high-risk actions or low trust scores.

📢 Pop-Up Security Challenges: Interactive challenges deployed when behavior is suspicious.

🛡️ Attack Simulation: Built-in tools to test system resilience.

📊 Threat Intelligence Dashboard: Visual analytics for admins to view logs and alerts.

🧠 How It Works

Stage

Description

1. Data Collection

Captures live data points: typing rhythm, mouse coordinates, timezone, and click behavior.

2. Model Training

The system uses IsolationForest to learn the user's baseline "normal" behavior.

3. Continuous Verification

The backend calculates a real-time Trust Score based on current actions vs. baseline.

4. Challenge Triggering

If the Trust Score drops below a threshold, a pop-up challenge is triggered.

5. Face Verification

If challenges fail or suspicion is high, the system enforces facial recognition.

6. Threat Dashboard

Admins receive alerts, logs, and detailed security insights.

📂 Tech Stack

Category

Tools & Libraries

Backend

Python, Flask

AI / ML

Isolation Forest (Scikit-learn), Pandas, NumPy

Frontend

HTML5, CSS3, JavaScript

Storage

CSV (Logs/Data), Joblib (Model Persistence)

Security

Multi-modal challenge verification, Biometric hashing

🔧 Setup Instructions

Follow these steps to run the project locally:

1. Clone the Repository

git clone [https://github.com/Surya8663/SecurePlus.git](https://github.com/Surya8663/SecurePlus.git)
cd sentinelshield


2. Create a Virtual Environment (Optional but Recommended)

# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate


3. Install Dependencies

pip install -r requirements.txt


4. Run the Application

python app.py


The server will start at http://127.0.0.1:5000/.

🌐 Available Routes

Endpoint

Description

/

Live Security Demo: The main interface for testing.

/collector

Data Collection: Captures behavior to build the dataset.

/train

Train Model: Retrains the Isolation Forest on collected data.

/check

Trust Score: JSON endpoint for real-time behavioral scoring.

/trigger-challenge

Challenge: Manually or automatically triggers a security check.

/verify-face

Biometrics: Validates user identity via webcam.

/threat-dashboard

Analytics: Admin view for threats and anomalies.

/challenge-dashboard

Logs: Monitors user responses to challenges.

/face-registration

Onboarding: Registers a new user's face data.


📦 Future Enhancements

[ ] Voice Biometrics: Add voiceprint analysis for multi-factor authentication.

[ ] Deepfake Detection: AI layer to detect synthetic faces during verification.

[ ] Device Fingerprinting: Analyze hardware headers for device ID consistency.

[ ] Cloud Sync: Encrypted model synchronization across devices.

🤝 Contributing

Contributions are always welcome!

Fork the repository.

Create your feature branch (git checkout -b feature/NewFeature).

Commit your changes (git commit -m 'Add some NewFeature').

Push to the branch (git push origin feature/NewFeature).

Open a Pull Request.

⭐ Support

If you find this project useful or interesting, please give it a Star ⭐ on GitHub! It helps others find the project.

👤 Author

Surya AI & Cybersecurity Enthusiast Made with ❤️ for real-world security innovation.
