# cache_utils.py
import time
import pickle
import os
from threading import Lock

class ResourceRecord:
    __slots__ = ('name', 'rtype', 'rclass', 'ttl', 'rdata', 'expire')

    def __init__(self, name, rtype, rclass_, ttl, rdata):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass_
        self.ttl = ttl
        self.rdata = rdata
        self.expire = time.time() + ttl

    def remaining_ttl(self):
        rem = int(self.expire - time.time())
        return max(rem, 0)

forward_cache = {}
reverse_cache = {}
cache_lock = Lock()


def cleanup_cache():
    now = time.time()
    with cache_lock:
        to_delete = []
        for dname, rr_list in forward_cache.items():
            new_list = [rr for rr in rr_list if rr.expire > now]
            if new_list:
                forward_cache[dname] = new_list
            else:
                to_delete.append(dname)
        for dname in to_delete:
            del forward_cache[dname]

        to_delete = []
        for ip, rr_list in reverse_cache.items():
            new_list = [rr for rr in rr_list if rr.expire > now]
            if new_list:
                reverse_cache[ip] = new_list
            else:
                to_delete.append(ip)
        for ip in to_delete:
            del reverse_cache[ip]


def save_cache_to_disk(filename='cache.pickle'):
    with cache_lock:
        try:
            with open(filename, 'wb') as f:
                pickle.dump((forward_cache, reverse_cache), f)
            print(f"[cache_utils] Cache saved to '{filename}'.")
        except Exception as e:
            print(f"[cache_utils] ERROR saving cache to disk: {e}")


def load_cache_from_disk(filename='cache.pickle'):
    if not os.path.exists(filename):
        return None

    try:
        with open(filename, 'rb') as f:
            fwd, rev = pickle.load(f)
    except Exception as e:
        print(f"[cache_utils] ERROR loading cache from '{filename}': {e}")
        return None

    now = time.time()
    cleaned_fwd = {}
    for dname, rr_list in fwd.items():
        new_list = [rr for rr in rr_list if rr.expire > now]
        if new_list:
            cleaned_fwd[dname] = new_list

    cleaned_rev = {}
    for ip, rr_list in rev.items():
        new_list = [rr for rr in rr_list if rr.expire > now]
        if new_list:
            cleaned_rev[ip] = new_list

    print(f"[cache_utils] Cache loaded from '{filename}', cleaned expired records.")
    return cleaned_fwd, cleaned_rev
