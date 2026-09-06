import random
from datetime import datetime, timedelta


def generate_ip():
    part1 = random.randint(0, 255)
    part2 = random.randint(0, 255)
    part3 = random.randint(0, 255)
    part4 = random.randint(0, 255)
    return f"{part1}.{part2}.{part3}.{part4}"

def generate_event():
    events = [
        '"GET /home HTTP/1.1" 200',
        '"GET /about HTTP/1.1" 200',
        '"POST /login HTTP/1.1" 401',  
        '"POST /login HTTP/1.1" 401',  
        '"GET /backup.zip HTTP/1.1" 404',
        '"GET /admin_panel HTTP/1.1" 403' 
    ]
    return random.choice(events)
def format_timestap(dt):
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

if __name__ == "__main__":
    current_time = datetime.now()
    with open("logs/server_logs.txt", "w") as file:
        for _ in range(10000):
            current_time += timedelta(seconds=random.randint(1, 15))

            chaos_chance = random.random()

            if chaos_chance < 0.02:
                file.write("ERROR: System memory dump failed. Restarting service...\n")
                continue
            elif chaos_chance < 0.07:
                ip = generate_ip()
                ssh_time = current_time.strftime('%b %d %H:%M:%S')
                file.write(f"{ssh_time} ubuntu-server sshd[1422]: Failed password for root from {ip} port 22 ssh2\n")
                continue
            ip = generate_ip()
            timestamp = format_timestap(current_time)
            event = generate_event()

            log_line = f"{ip} - - {timestamp} {event}\n"
            file.write(log_line)
    

    