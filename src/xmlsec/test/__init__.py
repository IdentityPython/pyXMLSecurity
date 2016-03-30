import os
import subprocess
import logging

__author__ = 'leifj'


def find_alts(alts):
    for a in alts:
        if os.path.exists(a):
            return a
    return None


def run_cmd(args,softhsm_conf=None):
    env = {}
    if softhsm_conf is not None:
        env['SOFTHSM_CONF'] = softhsm_conf
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = proc.communicate()
    if err is not None and len(err) > 0:
        logging.error(err)
    if out is not None and len(out) > 0:
        logging.debug(out)
    rv = proc.wait()
    if rv:
        raise RuntimeError("command exited with code != 0: %d" % rv)