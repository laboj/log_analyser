#==============================================================================================================================
#author@laboj
#date@23-07-2026
#lesson: Log File Analyzer
#description: read file, reusable functions, loop control, extracting values
#==============================================================================================================================

#Function
def is_failed_login(line):
    return "Failed password" in line

#Declaring variables
failed_count=0
usernames =[]
ips=[]
ip_counts={}
highest_count=0
most_active_ip=None

#Reading log file
with open ("auth.log", "r") as logfile:
    for line in logfile:
        
        if is_failed_login(line):
            
            failed_count +=1

            parts = line.split()
            username=parts[7]
            ip=parts[9]

            usernames.append(username)
            ips.append(ip)

            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] =1

#Security Report
print(f"""
    Security Report
==========================

Failed logins: {failed_count}
        """)

print("Username:")
for username in usernames:
    print(f"- {username}")
print(" ")

print("IPs:")
for ip in ips:
    print(f"- {ip}")

print("\n   Failed attempts by IPs")
print("==============================\n")
for ip, count in ip_counts.items():
    print(f"{ip}: {count}")
    if count > highest_count:
        highest_count = count
        most_active_ip = ip
print(f"\nMost active IP is {most_active_ip} with a count of {highest_count}!\n")

for ip, count in ip_counts.items():
    if count >= 3:
        print(f"Alert suspicious activity from {ip} with {count} attempts")
    else:
        print(f"Normal activity from {ip}")

 
