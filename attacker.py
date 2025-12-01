import requests
import time
import concurrent.futures

# CONFIGURATION
TARGET_URL = "http://localhost:8000/"
TOTAL_REQUESTS = 50
CONCURRENT_THREADS = 10 # Send 10 requests at the exact same time

print(f"🚀 LAUNCHING PARALLEL ATTACK ON {TARGET_URL}...")

def send_request(i):
    try:
        start = time.time()
        response = requests.get(TARGET_URL)
        latency = (time.time() - start) * 1000
        
        if response.status_code == 200:
            return f"✅ 200 OK ({latency:.0f}ms)"
        elif response.status_code == 403:
            return f"⛔ 403 BLOCKED! AI CAUGHT YOU!"
        else:
            return f"⚠️ {response.status_code}"
    except Exception as e:
        return f"❌ Error: {e}"

# Run requests in parallel using ThreadPool
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as executor:
    # Fire off 50 requests
    futures = [executor.submit(send_request, i) for i in range(TOTAL_REQUESTS)]
    
    for future in concurrent.futures.as_completed(futures):
        print(future.result())

print("\n--- ATTACK FINISHED ---")