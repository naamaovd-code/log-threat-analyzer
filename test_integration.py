from engine import securityEngine
from parser import read_logs 
def test_full_flow():
    
    log_file_path = "logs/server_logs.txt" 
    
    print("🚀 Initilize security Engine...")
    engine = securityEngine()

    print(f"📂 Read file: {log_file_path}")
    line_count = 0
    

    for parsed_data in read_logs(log_file_path):
        line_count += 1
        
        
        engine.process_line(parsed_data)
        
    
    print("-" * 30)
    print(f"✅ finish! read {line_count} Log lines.")
    print(f"🚨 Detected alerts: {len(engine.alerts)}\n")
    
   
    for alert in engine.alerts:
        print(f"[{alert['timestamp']}] {alert['type']} - IP: {alert['ip_address']} | {alert['details']}")

if __name__ == "__main__":
    test_full_flow()
