from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import numpy as np
import os
from datetime import datetime
import json
import random

app = Flask(__name__)
CORS(app)

CSV_HEADER = "avg_press,avg_interval,mouse_dist,clicks,timezone\n"

# --- Store user sessions and threat intelligence ---
user_sessions = {}
threat_intelligence = {}

# --- NEW: Popup Challenge System ---
challenge_sessions = {}
# Face database for registered users
face_database = {}

@app.route('/register-face', methods=['POST'])
def register_face():
    user_id = request.json['user_id']
    face_database[user_id] = {'registered': True, 'timestamp': datetime.now().isoformat()}
    print(f"✅ Face registered for user: {user_id}")
    return jsonify({'status': 'success', 'message': 'Face registered successfully'})

@app.route('/verify-face-real', methods=['POST'])
def verify_face_real():
    user_id = request.json['user_id']
    
    # Check if face is registered
    if user_id in face_database:
        user_data = face_database[user_id]
        return jsonify({
            'access_granted': True,
            'message': f'✅ {user_id} verified - Welcome back!',
            'user_name': user_id,
            'registration_date': user_data['timestamp']
        })
    else:
        return jsonify({
            'access_granted': False, 
            'message': f'❌ INTRUDER ALERT: {user_id} not in system',
            'alert_level': 'CRITICAL',
            'action': 'TERMINATE_SESSION'
        })

@app.route('/face-registration')
def face_registration_page():
    return """
    <html>
    <body style="font-family: Arial; background: #1a1f2e; color: white; padding: 40px; text-align: center;">
        <h1>📷 Register Your Face</h1>
        <div style="background: #2a2f3e; padding: 30px; border-radius: 10px; display: inline-block;">
            <h3>Enter Your User ID:</h3>
            <input type="text" id="userid" placeholder="e.g., my_face" style="padding: 10px; font-size: 16px;">
            <br><br>
            <button onclick="registerFace()" style="padding: 12px 24px; background: #00ff88; color: black; border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">
                Register My Face
            </button>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        <br><br>
        <a href="/" style="color: #66ccff;">← Back to Demo</a>
        
        <script>
            function registerFace() {
                const userId = document.getElementById('userid').value;
                if(!userId) { alert('Please enter User ID'); return; }
                
                fetch('/register-face', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: userId})
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('result').innerHTML = 
                        '<p style="color: #00ff88; font-size: 18px;">✅ ' + data.message + '</p>' +
                        '<p>Now go back to demo and use this User ID for verification</p>';
                });
            }
        </script>
    </body>
    </html>
    """

@app.route('/submit-data', methods=['POST'])
def submit_data():
    data = request.json['data']
    
    if not os.path.exists('normal_data.csv'):
        with open('normal_data.csv', 'w') as f:
            f.write(CSV_HEADER)
            
    with open('normal_data.csv', 'a') as f:
        f.write(f"{data['avg_press']},{data['avg_interval']},{data['mouse_dist']},{data['clicks']},{data['timezone']}\n")
        
    return jsonify({"status": "data batch received"})

@app.route('/train', methods=['GET'])
def train_model():
    if not os.path.exists('normal_data.csv'):
        return jsonify({"status": "error", "message": "No data found."})

    data = pd.read_csv("normal_data.csv").dropna()
    
    if len(data) < 10:
         return jsonify({"status": "error", "message": f"Not enough data. Need at least 10 batches, have {len(data)}."})

    processed_data = pd.get_dummies(data, columns=['timezone'])
    
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(processed_data)
    
    model_columns = list(processed_data.columns)
    joblib.dump(model, "behavior_model.joblib")
    joblib.dump(model_columns, "model_columns.joblib")
    
    # Initialize user baseline after training
    user_baseline = {
        'typing_speed': data['avg_interval'].mean(),
        'mouse_activity': data['mouse_dist'].mean(),
        'click_frequency': data['clicks'].mean(),
        'timezone': data['timezone'].mode()[0]
    }
    joblib.dump(user_baseline, "user_baseline.joblib")
    
    print(f"Model trained with {len(model_columns)} features: {model_columns}")
    return jsonify({"status": "model trained successfully", "baseline": user_baseline})

# --- Enhanced Check Endpoint with Threat Intelligence ---
@app.route('/check', methods=['POST'])
def check_behavior():
    try:
        model = joblib.load("behavior_model.joblib")
        model_columns = joblib.load("model_columns.joblib")
        user_baseline = joblib.load("user_baseline.joblib")
    except FileNotFoundError:
        return jsonify({"trust_level": "Error", "message": "Model not trained yet!"})

    data = request.json['data']
    session_id = request.json.get('session_id', 'default')
    
    # Multi-Modal Behavioral Fusion
    feature_contributions = calculate_feature_contributions(data, user_baseline)
    
    live_df = pd.DataFrame([data])
    live_df_processed = pd.get_dummies(live_df)
    live_df_reindexed = live_df_processed.reindex(columns=model_columns, fill_value=0)
    
    raw_score = model.decision_function(live_df_reindexed)[0]
    
    # Adaptive Trust Scoring
    trust_score, trust_level, mitigation_action = calculate_enhanced_trust_score(
        raw_score, feature_contributions, session_id
    )
    
    # NEW: Check if we should trigger security challenge
    trigger_challenge = False
    if trust_score < 40:  # Trigger challenge for low trust scores
        trigger_challenge = True
    
    # Store threat intelligence
    threat_intelligence[session_id] = {
        'timestamp': datetime.now().isoformat(),
        'trust_score': trust_score,
        'raw_score': raw_score,
        'feature_contributions': feature_contributions,
        'mitigation_action': mitigation_action,
        'live_data': data,
        'trigger_challenge': trigger_challenge
    }
    
    # Keep only last 100 entries
    if len(threat_intelligence) > 100:
        oldest_key = min(threat_intelligence.keys(), key=lambda k: threat_intelligence[k]['timestamp'])
        del threat_intelligence[oldest_key]
    
    return jsonify({
        "trust_level": trust_level,
        "trust_score": trust_score,
        "raw_score": raw_score,
        "mitigation_action": mitigation_action,
        "feature_contributions": feature_contributions,
        "session_id": session_id,
        "trigger_challenge": trigger_challenge  # NEW: Tell frontend to show popup
    })

# --- NEW: Popup Challenge System Endpoints ---

@app.route('/trigger-challenge', methods=['POST'])
def trigger_challenge():
    session_id = request.json['session_id']
    challenge_id = f"challenge_{datetime.now().timestamp()}_{random.randint(1000,9999)}"
    
    # Store challenge details
    challenge_sessions[challenge_id] = {
        'session_id': session_id,
        'trigger_time': datetime.now().isoformat(),
        'response_time': None,
        'status': 'pending',  # pending, responded, timeout
        'face_verified': False,
        'user_type': 'unknown'  # real_user, attacker
    }
    
    print(f"🔒 Security challenge triggered: {challenge_id} for session {session_id}")
    
    return jsonify({
        'challenge_id': challenge_id,
        'message': 'Security verification required',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/challenge-response', methods=['POST'])
def challenge_response():
    challenge_id = request.json['challenge_id']
    response_time = datetime.now().isoformat()
    
    if challenge_id in challenge_sessions:
        challenge = challenge_sessions[challenge_id]
        trigger_time = datetime.fromisoformat(challenge['trigger_time'])
        response_time_dt = datetime.fromisoformat(response_time)
        
        # Calculate response time in seconds
        response_delay = (response_time_dt - trigger_time).total_seconds()
        challenge['response_time'] = response_delay
        challenge['status'] = 'responded'
        
        # Analyze response time to determine user type
        if response_delay < 3.0:  # Real users respond quickly (< 3 seconds)
            challenge['user_type'] = 'real_user'
            trust_boost = 25
            print(f"✅ Quick response ({response_delay:.1f}s) - Likely REAL USER")
        elif response_delay < 8.0:  # Moderate delay
            challenge['user_type'] = 'suspicious'
            trust_boost = 0
            print(f"⚠️  Slow response ({response_delay:.1f}s) - SUSPICIOUS")
        else:  # Long delay = likely attacker
            challenge['user_type'] = 'attacker'
            trust_boost = -20
            print(f"🚨 Very slow response ({response_delay:.1f}s) - LIKELY ATTACKER")
            
        return jsonify({
            'status': 'challenge_accepted',
            'response_time': response_delay,
            'trust_boost': trust_boost,
            'user_type': challenge['user_type'],
            'next_step': 'face_verification'
        })
    
    return jsonify({'status': 'invalid_challenge'})

# --- FIXED: Verify Face Endpoint with POST method ---
@app.route('/verify-face', methods=['POST'])  # FIXED: Added methods=['POST']
def verify_face():
    try:
        challenge_id = request.json['challenge_id']
        user_type = request.json.get('user_type', 'unknown')
        
        print(f"🔍 Face verification request for {challenge_id}, user type: {user_type}")
        
        if challenge_id in challenge_sessions:
            # Simulate face verification based on user type
            # Real users have 95% success rate, attackers have 5% success rate
            if user_type == 'real_user':
                is_verified = random.random() > 0.05  # 95% success
                print(f"🎯 Real user verification - Success: {is_verified}")
            elif user_type == 'suspicious':
                is_verified = random.random() > 0.5  # 50% success  
                print(f"⚠️ Suspicious user verification - Success: {is_verified}")
            else:  # attacker
                is_verified = random.random() > 0.95  # 5% success
                print(f"🚨 Attacker verification - Success: {is_verified}")
            
            challenge_sessions[challenge_id]['face_verified'] = is_verified
            
            if is_verified:
                print(f"✅ Face verification SUCCESS for {challenge_id}")
                return jsonify({
                    'status': 'face_verified',
                    'access_granted': True,
                    'message': 'Identity confirmed - Full access restored',
                    'trust_restored': 95
                })
            else:
                print(f"❌ Face verification FAILED for {challenge_id}")
                return jsonify({
                    'status': 'face_rejected', 
                    'access_granted': False,
                    'message': 'Face verification failed - Security violation detected',
                    'trust_restored': 0
                })
        
        return jsonify({'status': 'error', 'message': 'Invalid challenge ID'})
    
    except Exception as e:
        print(f"❌ Error in verify-face: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'})

@app.route('/get-challenge-status/<challenge_id>')
def get_challenge_status(challenge_id):
    if challenge_id in challenge_sessions:
        return jsonify(challenge_sessions[challenge_id])
    return jsonify({'status': 'not_found'})

# --- Threat Intelligence Endpoint ---
@app.route('/threat-intel')
def get_threat_intel():
    return jsonify({
        'threat_intelligence': threat_intelligence,
        'active_challenges': challenge_sessions,
        'registered_faces': list(face_database.keys())
    })

# --- Simulated Attack Endpoint ---
@app.route('/simulate-attack', methods=['POST'])
def simulate_attack():
    attack_type = request.json['attack_type']
    original_data = request.json['original_data']
    
    simulated_data = original_data.copy()
    
    if attack_type == 'typing_attack':
        simulated_data['avg_press'] *= 0.5
        simulated_data['avg_interval'] *= 0.6
    elif attack_type == 'mouse_attack':
        simulated_data['mouse_dist'] *= 0.1
        simulated_data['clicks'] = 0
    elif attack_type == 'location_attack':
        simulated_data['timezone'] = 'America/New_York'
    elif attack_type == 'bot_attack':
        simulated_data['avg_press'] = 100
        simulated_data['avg_interval'] = 150
        simulated_data['mouse_dist'] = 0
    
    # Create a mock check for the simulated data
    mock_trust_score = 25 if attack_type != 'location_attack' else 15
    mock_trust_level = "ANOMALY DETECTED"
    
    return jsonify({
        "attack_type": attack_type,
        "simulated_data": simulated_data,
        "security_response": {
            "trust_score": mock_trust_score,
            "trust_level": mock_trust_level,
            "mitigation_action": "LOCKDOWN - Require Reauthentication",
            "trigger_challenge": True
        }
    })

# --- Helper Functions ---
def calculate_feature_contributions(live_data, baseline):
    contributions = {}
    
    # Typing speed contribution
    typing_deviation = abs(live_data['avg_interval'] - baseline['typing_speed']) / baseline['typing_speed']
    contributions['typing_rhythm'] = min(typing_deviation * 100, 100)
    
    # Mouse activity contribution
    if baseline['mouse_activity'] > 0:
        mouse_deviation = abs(live_data['mouse_dist'] - baseline['mouse_activity']) / baseline['mouse_activity']
        contributions['mouse_behavior'] = min(mouse_deviation * 100, 100)
    else:
        contributions['mouse_behavior'] = 0
    
    # Click pattern contribution
    if baseline['click_frequency'] > 0:
        click_deviation = abs(live_data['clicks'] - baseline['click_frequency']) / baseline['click_frequency']
        contributions['click_pattern'] = min(click_deviation * 100, 100)
    else:
        contributions['click_pattern'] = 0
    
    # Timezone anomaly
    timezone_match = 1 if live_data['timezone'] == baseline['timezone'] else 0
    contributions['location_trust'] = 0 if timezone_match else 100
    
    return contributions

def calculate_enhanced_trust_score(raw_score, feature_contributions, session_id):
    MAX_NORMAL_SCORE = 0.12
    MIN_ANOMALY_SCORE = -0.2
    
    scaled_score = (raw_score - MIN_ANOMALY_SCORE) / (MAX_NORMAL_SCORE - MIN_ANOMALY_SCORE)
    base_trust_score = int(np.clip(scaled_score * 100, 0, 100))
    
    # More lenient adjustments
    adjustment = 0
    
    if feature_contributions['location_trust'] > 80:
        adjustment -= 15
    
    if feature_contributions['typing_rhythm'] > 85:
        adjustment -= 10
    elif feature_contributions['typing_rhythm'] > 60:
        adjustment -= 5
        
    if feature_contributions['mouse_behavior'] > 90:
        adjustment -= 8
        
    final_trust_score = max(0, min(100, base_trust_score + adjustment))
    
    # More lenient trust levels
    if final_trust_score >= 70:
        trust_level = "Verified"
        action = "Full Access"
    elif final_trust_score >= 50:
        trust_level = "Suspicious" 
        action = "Monitor Closely"
    elif final_trust_score >= 30:
        trust_level = "Warning"
        action = "Limit Sensitive Operations"
    else:
        trust_level = "ANOMALY DETECTED"
        action = "LOCKDOWN - Require Reauthentication"
    
    return final_trust_score, trust_level, action

# --- Routes ---
@app.route('/collector')
def collector_page():
    return render_template('collector.html')

@app.route('/')
def demo_page():
    return render_template('demo.html')

@app.route('/threat-dashboard')
def threat_dashboard():
    return render_template('threat_dashboard.html')

# --- NEW: Challenge Dashboard ---
@app.route('/challenge-dashboard')
def challenge_dashboard():
    return render_template('challenge_dashboard.html')

# Enhance your pre-registered users
face_database['john_doe'] = {
    'registered': True,
    'timestamp': datetime.now().isoformat(),
    'face_data': 'pre_registered_face_john',
    'photo_count': 1,
    'role': 'Admin',
    'clearance': 'High'
}

face_database['sarah_smith'] = {
    'registered': True, 
    'timestamp': datetime.now().isoformat(),
    'face_data': 'pre_registered_face_sarah', 
    'photo_count': 1,
    'role': 'User',
    'clearance': 'Standard'
}

print("✅ Pre-registered demo users:", list(face_database.keys()))

if __name__ == '__main__':
    # Clean start
    for file in ['normal_data.csv', 'behavior_model.joblib', 'model_columns.joblib', 'user_baseline.joblib']:
        if os.path.exists(file): 
            os.remove(file)
            
    print("🚀 Starting Enhanced Behavioral Biometrics System...")
    print("📊 Available routes:")
    print("   http://localhost:5000/collector - Data Collection & Training")
    print("   http://localhost:5000/ - Live Security Demo")
    print("   http://localhost:5000/face-registration - Register Your Face")
    print("   http://localhost:5000/threat-dashboard - Threat Intelligence")
    print("   http://localhost:5000/challenge-dashboard - Challenge Monitor")
    print("\n🎯 IMPORTANT: Register your face FIRST at /face-registration")
    
    app.run(debug=True, port=5000)