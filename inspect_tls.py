try:
    from scapy.layers.tls.session import readConnState
    print("Found readConnState in scapy.layers.tls.session")
    print(dir(readConnState))
except Exception as e:
    print(f"Error importing readConnState: {e}")

try:
    from scapy.layers.tls.keyexchange import readConnState
    print("Found readConnState in scapy.layers.tls.keyexchange")
except Exception as e:
    print(f"Error: {e}")
