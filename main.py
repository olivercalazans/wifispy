# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WifiSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
import argparse
import socket
import struct
import asyncio


class Sniffer:
    
    __slots__ = ('_queue', '_running', '_interface', '_data')
    
    def __init__(self):
        self._queue     = asyncio.Queue()
        self._running   = True
        self._interface = None
        self._data      = {}



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self._running = False
        return False


    
    async def _main(self) -> None:
        try:
            self._validate_arguments()
            await asyncio.gather(
                self._star_sniffing(),
                self._process_packets()
            )
        except KeyboardInterrupt:  print(self.yellow('Process stopped'))
        except Exception as error: print(self.red('Error') + f': {error}')



    def _validate_arguments(self) -> None:
        arguments = sys.argv[1:] if sys.argv[1:] else None
        parser    = argparse.ArgumentParser(description='Sniffer argparser')    
        parser.add_argument('-i', '--interface', type=str, help='Specify an interface to sniff')
        parser          = parser.parse_args(arguments)
        self._interface = parser.interface


    
    # SNIFFER =================================================================

    async def _star_sniffing(self) -> None:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sniffer:
            if self._interface:
                sniffer.bind((self._interface, 0))
            sniffer.setblocking(False)
            
            loop = asyncio.get_event_loop()
            while self._running:
                try:
                    data = await loop.sock_recv(sniffer, 65535)
                    await self._queue.put(data)
                except Exception:
                    continue


    
    # PACKET DISSECTOR =======================================================

    async def _process_packets(self) -> None:
        while self._running:
            packet   = await self._queue.get()
            packet   = memoryview(packet)
            mac_info = self._get_mac_addresses(packet[:14])
            if mac_info[0] is False: continue
            ip_info  = self._get_ip_addresses(packet[14:34])


    
    ETHERNET = struct.Struct("!6s6sH")
    @staticmethod
    def _get_mac_addresses(ethernet_bytes:memoryview) -> tuple[str, str, bool]:
        ethernet_header = Sniffer.ETHERNET.unpack(ethernet_bytes)
        dst_mac         = Sniffer._format_mac(ethernet_header[0])
        src_mac         = Sniffer._format_mac(ethernet_header[1])
        eth_proto       = socket.ntohs(ethernet_header[2])
        ip_layer        = True if eth_proto == 0x0800 else False
        return ip_layer, dst_mac, src_mac
        


    @staticmethod
    def _format_mac(raw_mac:int) -> str:
        return ":".join(f"{b:02x}" for b in raw_mac)
    


    IP = struct.Struct("!BBHHHBBH4s4s")
    @staticmethod
    def _get_ip_addresses(ip_header:memoryview) -> tuple[str, str]:
        iph       = Sniffer.IP.unpack(ip_header)
        src_ip    = socket.inet_ntoa(iph[8])
        dst_ip    = socket.inet_ntoa(iph[9])
        return dst_ip, src_ip
    


    # DISPLAY ================================================================
    
    @staticmethod
    def pink(message: str) -> str:
        return '\033[35m' + message + '\033[0m'

    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'

    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'

    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'
    



if __name__ == '__main__':
    with Sniffer() as sniffer:
        asyncio.run(sniffer._main())
