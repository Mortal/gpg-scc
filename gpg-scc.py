#!/usr/bin/env python3

import os
import random
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
         '--batch', '--list-sigs', '--with-colons'),
        universal_newlines=True)
    pubkeys = []
    cur_pubkey = None
    cur_uid = None
    for line in output.splitlines():
        parts = line.split(':')
        if not line or not parts:
            pass
        elif parts[0] not in fields:
            raise ValueError("Unknown line kind %r" % (parts[0],))
        elif parts[0] == 'pub':
            key_id = parts[4]
            cur_pubkey = {
                'key_id': parts[4],
                'uids': [],
            }
            pubkeys.append(cur_pubkey)
            cur_uid = None
        elif parts[0] == 'uid':
            cur_uid = {
                'id': parts[7],
                'name': parts[9],
                'sigs': []
            }
            cur_pubkey['uids'].append(cur_uid)
        elif parts[0] == 'sig':
            key_id = parts[4]
            name = parts[9]
            if name == '[User ID not found]':
                name = None
            cur_uid['sigs'].append({
                'key_id': key_id,
                'name': name,
            })
    print("We know of %d public keys" % len(pubkeys))
    return pubkeys


def recv_keys(key_ids):
    print("recv-keys: %s" % ' '.join(key_ids))
    subprocess.check_call(
        ('gpg', '--homedir', homedir, '--keyserver', keyserver,
         '--batch', '--recv-keys',) + tuple(key_ids))


def get_unknown(pubkeys):
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
        if x[:len(key_id)].upper() == key_id[:len(x)].upper():
            result.append(pubkey)
    if len(result) == 0:
        return None
    elif len(result) == 1:
        return result[0]
    else:
        raise ValueError("%r is not a unique public key" % (key_id,))


def get_sig_graph(pubkeys):
    edge_lists = {}
    for pubkey in pubkeys:
        edge_list = set()
        edge_lists[pubkey['key_id']] = edge_list
        for uid in pubkey['uids']:
            for sig in uid['sigs']:
                edge_list.add(sig['key_id'])
    return edge_lists


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root')
    args = parser.parse_args()

    if not os.path.exists(homedir):
        os.mkdir(homedir)

    pubkeys = list_sigs()
    root = find_pubkey(pubkeys, args.root)
    if root is None:
        recv_keys([args.root])
        pubkeys = list_sigs()

    unknown = get_unknown(pubkeys)
    while unknown and len(pubkeys) < 100:
        recv_keys(random.sample(unknown, min(len(unknown), 48)))
        pubkeys = list_sigs()
        graph = get_sig_graph(pubkeys)
        unknown = get_unknown(pubkeys)
