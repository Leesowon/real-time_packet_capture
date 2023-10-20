import pyshark
import csv
#import time

# MQTT 패킷을 캡처할 네트워크 인터페이스 선택
# network_interface = 'eth0'  # 이더넷 인터페이스
network_interface = 'Adapter for loopback traffic capture'  # 무선 LAN 인터페이스

# CSV 파일에 저장할 파일 경로
output_csv_file = 'C:/workspace/lab/real-time_packet_capture/mqtt_packets_test.csv'

# 캡처를 시작한 시간 기록
# start_time = time.time()

# 패킷 캡처와 CSV 파일 저장
cap = pyshark.LiveCapture(interface=network_interface, bpf_filter='mqtt')

with open(output_csv_file, 'w', newline='') as csvfile:
    fieldnames = ['Timestamp', 'Source', 'Destination', 'MQTT Topic', 'MQTT Payload']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for packet in cap.sniff_continuously():
        try:
            timestamp = packet.sniff_timestamp
            source = packet.ip.src
            destination = packet.ip.dst
            mqtt_topic = packet.mqtt.topic
            mqtt_payload = packet.mqtt.payload.decode('utf-8')

            writer.writerow({'Timestamp': timestamp, 'Source': source, 'Destination': destination, 'MQTT Topic': mqtt_topic, 'MQTT Payload': mqtt_payload})
        except AttributeError:
            # MQTT 패킷이 아닌 경우 AttributeError가 발생할 수 있음
            pass

'''
        # 3분(180초) 동안 캡처
        current_time = time.time()
        if current_time - start_time >= 180:
            break  # 3분이 지나면 루프를 종료
'''     