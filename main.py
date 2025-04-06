# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WifiSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
import argparse
import socket
import asyncio


class Sniffer:
    
    __slots__ = ('_queue', '_interface')
    
    def __init__(self):
        self._queue          = asyncio.Queue()
        self._interface:str  = None

    
    def _main(self) -> None:
        try:
            self._validate_arguments()
        except Exception as error: print()



    def _validate_arguments(self) -> None:
        arguments = sys.argv[1:] if sys.argv[1:] else None
        parser    = argparse.ArgumentParser(description='Sniffer argparser')    
        parser.add_argument('-i', '--interface', type=str, help='Specify an interface to sniff')
        parser          = parser.parse_args(arguments)
        self._interface = parser.interface



    async def capture_packets(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sniffer:
            if self._interface:
                sniffer.bind((self._interface, 0))
            sniffer.setblocking(False)
            loop = asyncio.get_event_loop()

            while True:
                try:
                    data = await loop.sock_recv(sniffer, 65535)
                    await self._queue.put(data)
                except Exception as e:
                    print(f"Capture error: {e}")
                    sys.exit()