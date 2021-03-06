#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

import secrets
import socket
import select
import struct
import argparse
import logging
import os
from typing import NamedTuple


SSS_IP = 'localhost'
SSS_ID = 1

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.INFO)


Device = NamedTuple('Device', [('id', int), ('status', int), ('csock', socket.socket)])

# generate random keys for our deployment
key = secrets.token_bytes(16) 
hmac_key = secrets.token_bytes(16)
iv = secrets.token_bytes(16)

badKey = bytearray(16) # blank key of 16 bytes

# keys sent to device, initally blank
regKey = bytearray(16)
regHmac_key = bytearray(16)
regIV = bytearray(16)

class SSS:
    def __init__(self, sockf):
        # Make sure the socket does not already exist
        try:
            os.unlink(sockf)
        except OSError:
            if os.path.exists(sockf):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockf)
        self.sock.listen(10)
        self.devs = {}
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready

    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')
        data = b''
        while len(data) < 20:
            recvd = csock.recv(20 - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')
        _, _, _, _, dev_id, op, passcode, regNum = struct.unpack('<HHHHHHLL', data)

        #initalize keys to random keys
        regKey = key
        regHmac_key = hmac_key
        regIV = iv

        #compare passcode sent from device, and blank keys if not a match
        f = open("/secrets/data.txt", "r") 
        if passcode != int(f.read(), 10):
            regKey = badKey
            regHmac_key = badKey
            regIV = badKey
        f.close()

        #check if device registration file exists, if not blank keys
        if not os.path.isfile("/secrets/%s.data1" % dev_id):
            regKey = badKey
            regHmac_key = badKey
            regIV = badKey
        else: #check if device registration file matches device supplied registration number
            f = open("/secrets/%s.data1" % dev_id , "r") 
            if regNum != int(f.read(), 10): # if not a match, blank keys
                regKey = badKey
                regHmac_key = badKey
                regIV = badKey
            f.close()

        # requesting repeat transaction
        if dev_id in self.devs and self.devs[dev_id].status == op:
            resp_op = ALREADY
            logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
        # record transaction
        else:
            self.devs[dev_id] = Device(dev_id, op, csock)
            resp_op = op
            logging.info(f'{dev_id}:{"Registered" if op == REG else "Deregistered"}')

        # send response, along with keys
        resp = struct.pack('<2sHHHHh16s16s16s', b'SC', dev_id, SSS_ID, 52, dev_id, resp_op, regKey, regHmac_key, regIV)
        logging.debug(f'Sending response {repr(data)}')
        csock.send(resp)

    def start(self):
        unattributed_socks = set()

        # serve forever
        while True:
            # check for new client
            if self.sock_ready(self.sock):
                csock, _ = self.sock.accept()
                logging.info(f':New connection')
                unattributed_socks.add(csock)
                continue

            # check pool of unattributed sockets first
            for csock in unattributed_socks:
                try:
                    if self.sock_ready(csock):
                        self.handle_transaction(csock)
                        unattributed_socks.remove(csock)
                        break
                except (ConnectionResetError, BrokenPipeError):
                    logging.info(':Connection closed')
                    unattributed_socks.remove(csock)
                    csock.close()
                    break
            
            # check pool of attributed sockets first
            old_ids = []
            for dev in self.devs.values():
                if dev.csock and self.sock_ready(dev.csock):
                    try:
                        self.handle_transaction(dev.csock)
                    except (ConnectionResetError, BrokenPipeError):
                        logging.info(f'{dev.id}:Connection closed')
                        dev.csock.close()
                        old_ids.append(dev.id)
            
            for dev_id in old_ids:
                del self.devs[dev_id]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()


if __name__ == '__main__':
    main()
