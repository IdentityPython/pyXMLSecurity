import os
import subprocess
import logging

__author__ = 'leifj'


def paths_for_component(component, default_paths):
    env_path = os.environ.get(component)
    return [env_path] if env_path else default_paths


def find_alts(alts):
    for a in alts:
        if os.path.exists(a):
            return a
    return None


def run_cmd(args, softhsm_conf=None):
    env = {}
    if softhsm_conf is not None:
        env['SOFTHSM_CONF'] = softhsm_conf
        env['SOFTHSM2_CONF'] = softhsm_conf
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = proc.communicate()
    if err is not None and len(err) > 0:
        logging.error(err)
    if out is not None and len(out) > 0:
        logging.debug(out)
    rv = proc.wait()
    if rv:
        with open(softhsm_conf) as f:
            conf = f.read()
        msg = '[cmd: {cmd}] [code: {code}] [stdout: {out}] [stderr: {err}] [config: {conf}]'
        msg = msg.format(
            cmd=" ".join(args), code=rv, out=out.strip(), err=err.strip(), conf=conf,
        )
        raise RuntimeError(msg)
