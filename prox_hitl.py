import json
import boto3
import telebot
import sys

# --- CONFIGURATION ---
BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
CHAT_ID = "TELEGRAM_CHAT_ID"  # Must be a string, e.g., "123456789"

bot = telebot.TeleBot(BOT_TOKEN)
ec2 = boto3.client('ec2', region_name='us-east-1')
s3 = boto3.client('s3', region_name='us-east-1')

# --- INGESTION ---
print("[BOT] Prox AI: Reading Prowler telemetry...")
try:
    with open('prowler_report.json', 'r') as f:
        scan_data = json.load(f)
except FileNotFoundError:
    print("❌ Error: prowler_report.json not found.")
    sys.exit()

vulns = []

for finding in scan_data:
    if finding.get('Status') == 'FAIL':
        check_id = finding.get('CheckID', '')
        if 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22' in check_id:
            vulns.append(('EC2', finding.get('ResourceId', '')))
        if 's3_bucket_public_access' in check_id or 's3_bucket_level_public_access_block' in check_id:
            vulns.append(('S3', finding.get('ResourceName', finding.get('ResourceId', ''))))

# Deduplicate findings
vulns = list(set(vulns))

if not vulns:
    print(" [PASS] Environment is clean. No critical misconfigurations.")
    sys.exit()

# --- HUMAN IN THE LOOP (HITL) ---
msg = " *PROX AI ALERT* \nCritical cloud misconfigurations detected:\n\n"
for v_type, v_id in vulns:
    msg += f"⚠️ {v_type}: `{v_id}`\n"
msg += "\nDo you authorize automated Boto3 remediation? Reply *Y* to execute."

bot.send_message(CHAT_ID, msg, parse_mode='Markdown')
print("📲 Approval request sent to Telegram. Waiting for authorization...")

# --- EXECUTION ---
@bot.message_handler(func=lambda message: True)
def handle_approval(message):
    if str(message.chat.id) != CHAT_ID:
        return

    if message.text.strip().upper() == 'Y':
        bot.reply_to(message, "⚙️ Authorization accepted. Executing Boto3 Remediation Protocol...")
        print("⚡ Authorization received. Patching cloud infrastructure...")
        
        for v_type, v_id in vulns:
            if v_type == 'EC2':
                try:
                    ec2.revoke_security_group_ingress(
                        GroupId=v_id,
                        IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
                    )
                    bot.send_message(CHAT_ID, f" *Success:* Port 22 locked on `{v_id}`", parse_mode='Markdown')
                except Exception as e:
                    bot.send_message(CHAT_ID, f"⚠️ *Error on EC2:* {e}", parse_mode='Markdown')
            
            if v_type == 'S3':
                try:
                    s3.put_public_access_block(
                        Bucket=v_id,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
                        }
                    )
                    bot.send_message(CHAT_ID, f" *Success:* S3 Bucket `{v_id}` isolated.", parse_mode='Markdown')
                except Exception as e:
                    bot.send_message(CHAT_ID, f"⚠️ *Error on S3:* {e}", parse_mode='Markdown')
        
        bot.send_message(CHAT_ID, "[PASS] Remediation complete. Shutting down Prox agent.")
        print("Accomplished... Exiting...")
        bot.stop_polling()
    else:
        bot.reply_to(message, "[X] Remediation aborted by user.")
        print("[X] Aborted by user... Exiting...")
        bot.stop_polling()

bot.infinity_polling()