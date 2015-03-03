#!/usr/bin/env python3

import os
import random
import argparse
import itertools
import subprocess


homedir = os.getcwd() + '/gpg-home'
keyserver = 'hkp://keys.fedoraproject.org'

fields = {
    'pub': 'Public key',
    'crt': 'X.509 certificate',
    'crs': 'X.509 certificate and private key available',
    'sub': 'Subkey (secondary key)',
    'sec': 'Secret key',
    'ssb': 'Secret subkey (secondary key)',
    'uid': 'User id (only field 10 is used).',
    'uat': 'User attribute (same as user id except for field 10).',
    'sig': 'Signature',
    'rev': 'Revocation signature',
    'fpr': 'Fingerprint (fingerprint is in field 10)',
    'pkd': 'Public key data [*]',
    'grp': 'Keygrip',
    'rvk': 'Revocation key',
    'tru': 'Trust database information [*]',
    'spk': 'Signature subpacket [*]',
    'cfg': 'Configuration data [*]',
}


def list_sigs():
    output = subprocess.check_output(
        ('gpg', '--homedir', homedir, '--keyserver', keyserver,
         '--batch', '--list-sigs', '--with-colons'))
    pubkeys = []
    cur_pubkey = None
    cur_uid = None
    for line in output.splitlines():
        parts = line.split(b':')
        if not line or not parts:
            continue
        record = parts[0].decode()
        key_id = parts[4].decode()
        uid_hash = parts[7].decode()
        if record in ('uid', 'sig'):
            user_id = parts[9]
            try:
                user_id = user_id.decode('utf8')
            except UnicodeDecodeError:
                user_id = user_id.decode('latin1')
        if record not in fields:
            raise ValueError("Unknown line kind %r" % (record,))
        elif record == 'pub':
            cur_pubkey = {
                'key_id': key_id,
                'uids': [],
                'sigs': [],
            }
            pubkeys.append(cur_pubkey)
            cur_uid = None
        elif record == 'uid':
            cur_uid = {
                'id': uid_hash,
                'name': user_id,
                'sigs': []
            }
            cur_pubkey['uids'].append(cur_uid)
        elif record == 'sig':
            if user_id == '[User ID not found]':
                user_id = None
            if cur_uid is None:
                cur_pubkey['sigs'].append({
                    'key_id': key_id,
                    'name': user_id,
                })
            else:
                cur_uid['sigs'].append({
                    'key_id': key_id,
                    'name': user_id,
                })
    print("We know of %d public keys" % len(pubkeys))
    return pubkeys


def recv_keys(key_ids):
    print("recv-keys: %s" % ' '.join(key_ids))
    subprocess.check_call(
        ('gpg', '--homedir', homedir, '--keyserver', keyserver,
         '--batch', '--recv-keys',) + tuple(key_ids))


def get_unknown(pubkeys, source=None):
    unknown = set()
    for pubkey in pubkeys:
        for uid in pubkey['uids']:
            for sig in uid['sigs']:
                if sig['name'] is None:
                    unknown.add(sig['key_id'])
    print("%d unknown public keys" % len(unknown))
    return sorted(unknown)


def find_pubkey(pubkeys, key_id):
    result = []
    for pubkey in pubkeys:
        x = pubkey['key_id']
        if x[-len(key_id):].upper() == key_id[-len(x):].upper():
            result.append(pubkey)
    if len(result) == 0:
        return None
    elif len(result) == 1:
        return result[0]
    else:
        raise ValueError("%r is not a unique public key" % (key_id,))


def get_strong_set(pubkeys, root):
    root = root['key_id']
    edges = set()
    for pubkey in pubkeys:
        for uid in pubkey['uids']:
            for sig in uid['sigs']:
                edges.add((pubkey['key_id'], sig['key_id']))
    strong_edges = edges & set((v, u) for u, v in edges)
    edge_lists = {
        u: set(v for u_, v in group)
        for u, group in itertools.groupby(
            sorted(strong_edges), key=lambda x: x[0])
    }
    strong_set = set([root])
    frontier = edge_lists[root] - strong_set
    distance = 0
    while frontier:
        next_frontier = set.union(*[edge_lists[u] for u in frontier])
        distance += 1
        strong_set |= frontier
        frontier = next_frontier - strong_set
        print("dist=%d n=%d" % (distance, len(strong_set)))
    return [p for p in pubkeys if p['key_id'] in strong_set]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root')
    args = parser.parse_args()

    if not os.path.exists(homedir):
        os.mkdir(homedir)
        os.chmod(homedir, 0o700)

    pubkeys = list_sigs()
    root = find_pubkey(pubkeys, args.root)
    if root is None:
        recv_keys([args.root])
        pubkeys = list_sigs()
        root = find_pubkey(pubkeys, args.root)

    strong_set = get_strong_set(pubkeys, root)
    unknown = get_unknown(strong_set)
    while unknown and len(strong_set) < 400:
        print("The strong set has size %d" % len(strong_set))
        recv_keys(random.sample(unknown, min(len(unknown), 16)))
        pubkeys = list_sigs()
        strong_set = get_strong_set(pubkeys, root)
        unknown = get_unknown(strong_set)
    print("The strong set has size %d" % len(strong_set))


if __name__ == "__main__":
    main()
