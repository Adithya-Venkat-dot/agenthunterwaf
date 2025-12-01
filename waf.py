import numpy as np
import pandas as pd
import tensorflow as tf
import joblib
import time
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

# --- CONFIGURATION ---
LOOKBACK = 10
BLOCK_THRESHOLD = 0.90
CHALLENGE_THRESHOLD = 0.50
LOG_FILE = "waf_logs.csv"

# --- 1. SETUP LOGGING (OPTIMIZED) ---
# We keep the file handle OPEN to avoid opening/closing it 50 times a second
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("Timestamp,Source IP Address,Rolling_RPS,Packet_Variance,AI_Probability,Action\n")

# Open in append mode with line buffering (1)
log_handle = open(LOG_FILE, "a", buffering=1)

# --- 2. INITIALIZE RESOURCES ---
print("🔥 WAF STARTUP: Loading AI Brain...")
model = tf.keras.models.load_model('agent_hunter_model.h5')
scaler = joblib.load('scaler.pkl')
print("✅ AI Brain Loaded.")

# Connect to Redis
try:
    import redis
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    r.ping()
    print("✅ Connected to Native Redis.")
except:
    import fakeredis
    r = fakeredis.FakeStrictRedis(version=6, decode_responses=True)
    print("⚠️ Native Redis not found. Switched to FAKE Redis (In-Memory).")

app = FastAPI()

# --- 3. THE CORE WAF LOGIC ---
def analyze_traffic(ip: str, packet_size: int):
    current_time = time.time()
    
    # Pipeline for speed
    pipe = r.pipeline()
    key = f"traffic:{ip}"
    data = f"{current_time}:{packet_size}"
    pipe.rpush(key, data)
    pipe.ltrim(key, -50, -1) 
    pipe.expire(key, 60)
    pipe.execute()
    
    # Read History
    raw_history = r.lrange(key, 0, -1)
    if len(raw_history) < LOOKBACK:
        return 0.0, 0, 0
        
    timestamps = []
    sizes = []
    for h in raw_history:
        ts, size = h.split(":")
        timestamps.append(float(ts))
        sizes.append(int(size))
        
    df = pd.DataFrame({'time': timestamps, 'size': sizes})
    
    # Calculate Features
    one_sec_ago = current_time - 1
    recent = df[df['time'] > one_sec_ago]
    
    rolling_rps = len(recent) 
    packet_variance = recent['size'].var() if len(recent) > 1 else 0
    
    # Sequence Construction
    seq_data = []
    for i in range(len(df) - LOOKBACK, len(df)):
        seq_data.append([rolling_rps, packet_variance, sizes[i], sizes[i]])
        
    seq_data = np.array(seq_data)
    if seq_data.shape[0] != LOOKBACK:
         return 0.0, rolling_rps, packet_variance
         
    # Inference (Fast Tensor Mode)
    features_df = pd.DataFrame(seq_data, columns=['Rolling_RPS', 'Packet_Variance', 'Bytes_Sent', 'Bytes_Received'])
    scaled_seq = scaler.transform(features_df)
    input_tensor = tf.convert_to_tensor([scaled_seq], dtype=tf.float32)
    prediction = model(input_tensor, training=False).numpy()[0][0]
    
    return prediction, rolling_rps, packet_variance

# --- 4. THE MIDDLEWARE ---
@app.middleware("http")
async def ai_firewall_middleware(request: Request, call_next):
    client_ip = request.client.host
    packet_size = int(request.headers.get("content-length", 500)) 
    
    threat_score, rps, var = analyze_traffic(client_ip, packet_size)
    
    # Determine Action
    if threat_score > BLOCK_THRESHOLD:
        action = "BLOCK"
        status_code = 403
    elif threat_score > CHALLENGE_THRESHOLD:
        action = "CHALLENGE"
        status_code = 403
    else:
        action = "ALLOW"
        status_code = 200 # We don't return here, we pass to next
        
    # --- FAST LOGGING ---
    # We write directly to the open file handle (much faster)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_handle.write(f"{timestamp},{client_ip},{rps:.2f},{var:.2f},{threat_score:.4f},{action}\n")
    
    # --- BLOCKING LOGIC ---
    if action == "BLOCK":
        return JSONResponse(status_code=403, content={"error": "WAF Block", "score": float(threat_score)})
    if action == "CHALLENGE":
        return JSONResponse(status_code=403, content={"error": "CAPTCHA Required", "score": float(threat_score)})

    # Pass if safe
    response = await call_next(request)
    return response

@app.get("/")
def read_root():
    return {"message": "Protected Server Online"}

if __name__ == "__main__":
    # Disable Uvicorn access logs to save even more speed
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
