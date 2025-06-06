import threading
import signal
import time
import sys

from cache_utils import load_cache_from_disk, save_cache_to_disk, forward_cache, reverse_cache
import dns_server
import sntp_server

def graceful_shutdown(signum, frame):
    print("\n[main] Caught signal, saving cache and exiting...")
    save_cache_to_disk()
    sys.exit(0)

def user_input_loop(dns_srv):
    while True:
        try:
            cmd = input("Введите команду ('cache' чтобы вывести кэш, 'exit' — выйти): ").strip()
            if cmd == "cache":
                dns_srv.print_cache()
            elif cmd == "exit":
                print("[main] Завершаем по команде 'exit'")
                graceful_shutdown(None, None)
                break
        except KeyboardInterrupt:
            print("\n[main] Завершаем по Ctrl+C")
            graceful_shutdown(None, None)
            break

if __name__ == '__main__':
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    loaded = load_cache_from_disk()
    if loaded:
        fwd, rev = loaded
        forward_cache.clear()
        forward_cache.update(fwd)
        reverse_cache.clear()
        reverse_cache.update(rev)

    from cache_utils import cleanup_cache
    def cache_cleaner():
        while True:
            time.sleep(30)
            cleanup_cache()

    t_clean = threading.Thread(target=cache_cleaner, daemon=True)
    t_clean.start()

    dns_srv = dns_server.CachedDNSServer(listen_addr='0.0.0.0', port=53)
    t_dns = threading.Thread(target=dns_srv.start, daemon=True)
    t_dns.start()

    sntp_srv = sntp_server.SNTPServer(listen_addr='0.0.0.0', port=123)
    t_sntp = threading.Thread(target=sntp_srv.start, daemon=True)
    t_sntp.start()

    print("[main] DNS и SNTP сервера запущены. Чтобы остановить, нажмите Ctrl+C.")

    t_input = threading.Thread(target=user_input_loop, args=(dns_srv,), daemon=True)
    t_input.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        graceful_shutdown(None, None)
