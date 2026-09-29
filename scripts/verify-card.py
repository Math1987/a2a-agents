#!/usr/bin/env python3
"""Verify a public card using a separately trusted issuer origin (no owner key).

Uses official A2A Python protobuf descriptors, RFC 8785 and cryptography/OpenSSL,
independently of the server's Rust normalization table and signing backend.
"""
import argparse
import base64
import copy
import json
from urllib.parse import urlsplit

import httpx
import rfc8785
from a2a.types import a2a_pb2 as a2a
from google.api import field_behavior_pb2
from google.protobuf.json_format import ParseDict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def normalize(value, descriptor):
    # Struct is arbitrary application JSON, not an A2A schema message.
    if descriptor.full_name == 'google.protobuf.Struct':
        return
    for field in descriptor.fields:
        name = field.json_name
        required = field_behavior_pb2.REQUIRED in field.GetOptions().Extensions[field_behavior_pb2.field_behavior]
        if name not in value:
            if required:
                raise ValueError('Missing required field: ' + name)
            continue
        item = value[name]
        default = (item == [] or item == {}) if field.is_repeated else item == field.default_value
        if not required and not field.has_presence and default:
            del value[name]
            continue
        if field.message_type:
            if field.is_repeated and field.message_type.GetOptions().map_entry:
                child = field.message_type.fields_by_name['value'].message_type
                if child:
                    for entry in item.values():
                        normalize(entry, child)
            elif field.is_repeated:
                for entry in item:
                    normalize(entry, field.message_type)
            else:
                normalize(item, field.message_type)


def verify(card, jwks, trusted_origin):
    ParseDict(card, a2a.AgentCard())  # Strict official SDK wire validation.
    signature = card['signatures'][0]
    protected = signature['protected']
    header = json.loads(decode(protected))
    require(header['alg'] == 'ES256', 'Expected ES256')
    require(header['jku'] == trusted_origin.rstrip('/') + '/.well-known/jwks.json', 'Untrusted key origin')
    require(not header.get('crit') and header.get('b64', True) is True, 'Unsupported JWS header')
    keys = [k for k in jwks['keys'] if k['kid'] == header['kid']]
    require(len(keys) == 1, 'Missing or ambiguous key ID')
    key = keys[0]
    require(key['kty'] == 'EC' and key['crv'] == 'P-256' and key['alg'] == 'ES256', 'Unexpected key type')
    require('d' not in key, 'JWKS must contain only public keys')
    payload = copy.deepcopy(card)
    del payload['signatures']
    normalize(payload, a2a.AgentCard.DESCRIPTOR)
    canonical = rfc8785.dumps(payload)
    signing_input = protected.encode('ascii') + b'.' + base64.urlsafe_b64encode(canonical).rstrip(b'=')
    raw = decode(signature['signature'])
    require(len(raw) == 64, 'Invalid ES256 signature length')
    der = encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(key['x']), 'big'), int.from_bytes(decode(key['y']), 'big'), ec.SECP256R1()).public_key()
    public.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('card_url')
    parser.add_argument('--trusted-origin', required=True, help='Issuer origin trusted independently of the card')
    args = parser.parse_args()
    origin = urlsplit(args.trusted_origin)
    if origin.scheme != 'https' or origin.path not in ('', '/') or origin.query or origin.fragment or origin.username:
        parser.error('Trusted issuer must be an HTTPS origin')
    if urlsplit(args.card_url).scheme != 'https':
        parser.error('Card URL must use HTTPS')
    with httpx.Client(timeout=20, follow_redirects=False) as http:
        response = http.get(args.card_url)
        response.raise_for_status()
        keys = http.get(args.trusted_origin.rstrip('/') + '/.well-known/jwks.json')
        keys.raise_for_status()
        verify(response.json(), keys.json(), args.trusted_origin)
    print('PASS: A2A 1.0 card signature verified against the trusted issuer.')


if __name__ == '__main__':
    main()
