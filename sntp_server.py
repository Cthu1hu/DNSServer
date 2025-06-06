# sntp_server.py

import socket
import struct
import time
import threading

class SNTPServer:

    def __init__(self, listen_addr='0.0.0.0', port=123):
        self.addr = listen_addr
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.addr, self.port))
        print(f"[sntp_server] SNTP-сервер запущен на {self.addr}:{self.port}.")

    def start(self):
        while True:
            try:
                data, client_addr = self.sock.recvfrom(48)
                threading.Thread(
                    target=self.handle_request, args=(data, client_addr), daemon=True
                ).start()
            except Exception as e:
                print(f"[sntp_server] Ошибка recvfrom: {e}")

    def handle_request(self, data: bytes, client_addr):
        """
        Обрабатывает один NTP-запрос (48 байт) и отвечает корректным SNTP-пакетом.
        Если пришло меньше 48 байт — просто игнорируем.
        """
        if len(data) < 48:
            return

        orig_ts_secs, orig_ts_frac = struct.unpack('!II', data[40:48])

        recv_unix = time.time()
        recv_ntp = recv_unix + 2208988800  # перевод Unix→NTP

        LI = 0
        VN = 4
        Mode = 4
        first_byte = (LI << 6) | (VN << 3) | Mode

        stratum = 1
        poll = 6
        precision = (-20) & 0xFF

        root_delay = 0
        root_dispersion = 0
        ref_id = b'LOCL'

        ref_ts_secs = int(recv_ntp)
        ref_ts_frac = int((recv_ntp - ref_ts_secs) * (1 << 32))

        recv_ts_secs = ref_ts_secs
        recv_ts_frac = ref_ts_frac

        xmit_unix = time.time()
        xmit_ntp = xmit_unix + 2208988800
        xmit_ts_secs = int(xmit_ntp)
        xmit_ts_frac = int((xmit_ntp - xmit_ts_secs) * (1 << 32))

        resp = b''
        resp += struct.pack('!B', first_byte)
        resp += struct.pack('!B', stratum)
        resp += struct.pack('!b', poll)
        resp += struct.pack('!b', precision)
        resp += struct.pack('!I', root_delay)
        resp += struct.pack('!I', root_dispersion)
        resp += ref_id
        resp += struct.pack('!I', ref_ts_secs)
        resp += struct.pack('!I', ref_ts_frac)
        resp += struct.pack('!I', recv_ts_secs)
        resp += struct.pack('!I', recv_ts_frac)
        resp += struct.pack('!I', xmit_ts_secs)
        resp += struct.pack('!I', xmit_ts_frac)

        resp += struct.pack('!I', orig_ts_secs)
        resp += struct.pack('!I', orig_ts_frac)

        try:
            self.sock.sendto(resp, client_addr)
        except Exception:
            pass
