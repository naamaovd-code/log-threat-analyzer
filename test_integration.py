# חשוב לוודא ששמות הקבצים והמחלקות תואמים למה שכתבת אצלך
from engine import securityEngine
from parser import read_logs # אני מניחה שכך קראת לפונקציית הגנרטור או למחלקה

def test_full_flow():
    # נתיב לקובץ הלוגים שיצרת בשלב 1
    log_file_path = "logs/server_logs.txt" 
    
    # 1. אתחול המנוע
    print("🚀 מאתחל את מנוע זיהוי ההתקפות...")
    engine = securityEngine()
    
    # 2. ריצה על קובץ הלוג שורה-שורה באמצעות הפארסר
    print(f"📂 מתחיל לקרוא ולנתח את הקובץ: {log_file_path}")
    line_count = 0
    
    # הפארסר שלך אמור להחזיר dict בעזרת yield בכל פעם
    for parsed_data in read_logs(log_file_path):
        line_count += 1
        
        # מעבירים את הנתונים המפוענחים למנוע
        engine.process_line(parsed_data)
        
    # 3. סיכום התוצאות
    print("-" * 30)
    print(f"✅ סיום הריצה! עברנו על {line_count} שורות לוג רלוונטיות.")
    print(f"🚨 סך הכל התראות שזוהו: {len(engine.alerts)}\n")
    
    # הדפסת ההתראות המפורטות
    for alert in engine.alerts:
        print(f"[{alert['timestamp']}] {alert['type']} - IP: {alert['ip_address']} | {alert['details']}")

if __name__ == "__main__":
    test_full_flow()