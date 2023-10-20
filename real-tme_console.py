import pyshark

def pkt_callback(pkt):
    if 'mqtt' in pkt:
        try:
            timestamp = pkt.sniff_timestamp
            source = pkt.ip.src
            destination = pkt.ip.dst
            mqtt_topic = pkt.mqtt.topic
            mqtt_payload = pkt.mqtt.payload.decode('utf-8')

            # MQTT 패킷 정보를 콘솔에 출력
            print(f'Timestamp: {timestamp}, Source: {source}, Destination: {destination}, MQTT Topic: {mqtt_topic}, MQTT Payload: {mqtt_payload}')
        except AttributeError:
            # MQTT 패킷이 아닌 경우 AttributeError가 발생할 수 있음
            pass

# MQTT 패킷을 캡처할 네트워크 인터페이스 선택
network_interface = 'Adapter for loopback traffic capture'  # 무선 LAN 인터페이스

# 패킷 캡처
capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='mqtt')

# 캡처된 패킷에 대해 pkt_callback 함수를 적용
capture.apply_on_packets(pkt_callback)


'''
# 패킷 캡처와 MQTT 패킷 정보 출력
# capture = pyshark.LiveCapture(interface=network_interface, bpf_filter='MQTT')
capture = pyshark.LiveCapture(interface=network_interface, bpf_filter = 'tcp')

capture = pyshark.LiveCapture(interface=network_interface,
    bpf_filter='tcp port 1883',
    use_json=True, include_raw=True) 

for packet in capture.sniff_continuously():
    
    print("loop", cnt)
    cnt = cnt+1
    
    if ('tcp' not in packet): continue
    srcport = int(packet.tcp.srcport)
    dstport = int(packet.tcp.dstport)
    if dstport != 1883: continue
    print(f'{packet.ip.src}:{srcport} -> {packet.ip.dst}:{dstport}')
   
    if ('tcp' not in packet) or ('mqtt' not in packet.layers):
        continue
    
    try:
        timestamp = packet.sniff_timestamp
        source = packet.ip.src
        destination = packet.ip.dst
        mqtt_topic = packet.mqtt.topic
        mqtt_payload = packet.mqtt.payload.decode('utf-8')

        # MQTT 패킷 정보를 콘솔에 출력
        print(f'Timestamp: {timestamp}, Source: {source}, Destination: {destination}, MQTT Topic: {mqtt_topic}, MQTT Payload: {mqtt_payload}')
    except AttributeError:
        # MQTT 패킷이 아닌 경우 AttributeError가 발생할 수 있음
        pass
        '''