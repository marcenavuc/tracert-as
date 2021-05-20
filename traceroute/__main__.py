from traceroute.tracer import Tracer
from traceroute.parse import parse_args
import socket


args = parse_args()
destination = args.host
try:
    print("Start processing")
    with Tracer(destination) as tracer:
        results = tracer.start()
        for num, result in enumerate(results):
            print(f'{num + 1} {result}\r\n')
except socket.gaierror:
    print(f'Address {destination} is invalid')
except PermissionError:
    print('Not enough rights for access to socket')
