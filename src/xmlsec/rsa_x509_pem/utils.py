__author__ = 'leifj'

from multiprocessing import RLock
from threading import local


def _lock_for_object(o):
    thread_local = local()
    locks = getattr(thread_local, "locks", None)

    if locks is None:
        thread_local.locks = dict()

    if o not in thread_local.locks:
        thread_local.locks[o] = RLock()

    return thread_local.locks[o]


class SingleAccessCallable(object):

    def __init__(self, inner):
        self._i = inner

    def __call__(self, *args, **kwargs):
        lock = _lock_for_object(self._i)
        locked = False
        try:
            lock.acquire()
            locked = True
            res = self._i(*args, **kwargs)
            lock.release()
            locked = False
            return res
        finally:
            if locked:
                try:
                    lock.release()
                except Error:
                    pass
