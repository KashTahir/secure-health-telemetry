# secure-health-telemetry

# Author

Kashmain Tahir

# Overview

Thie project enables the secure transmission of health telemetry for remote monitoring of patient vitals

The client is a patient monitor that sends patient data to the server which is a central monitoring station

This project uses:

- sockets for TCP communication
- Diffie-Hellman for key exchange
- HKDF with SHA-256 for key derivation
- RSA digital signatures for integrity and authentication
- AES-GCM for integrity and confidentiality

# Project Structure:

client/
patient_monitor.py
server/
monitoring_station.py
data/
test_alert.txt
test_empty.txt
test_normal.txt
keys/

# populated only after running the key generation script

    client_pr.pem
    client_pu.pem
    server_pr.pem
    server_pu.pem

scripts/
generate_rsa_keys.py
utils/
aes_utils.py
dh_utils.py
rsa_utils.py

# Requirements

run this command:
pip install -r requirements.txt

# Starting the porgram

generate RSA keys using
python3 scripts/generate_rsa_keys.py

terminal 1 - server
python3 -m server.monitoring_station

terminal 2 - client
python3 -m client.patient_monitor

# Tamper mode

to demonstrate authentication and public key integrity
set key_tamper_mode = True
in either patient_monitor.py or monitoring_station.py

to demonstrate data integrity
set data_tamper_mode = True
in patient_monitor.py
