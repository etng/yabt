#!/bin/env python
# coding=utf-8
from flask import Flask, Blueprint, request, session, g, redirect, url_for, abort, render_template, flash, send_from_directory
import json
import time
import os
from bencode import bencode, bdecode
import hashlib
import cgi
import socket
from binascii import b2a_hex
from struct import pack

app = Flask(__name__)
app.config.update(dict(
    DEBUG=True,
    SECRET_KEY='4th',
    USE_X_SENDFILE=False,
    SESSION_COOKIE_NAME='st',
    ANNOUNCE_INTERVAL=600,
    ALLOW_MISSING_INFOHASH=True,
    LISTEN_PORT=3008,
    LISTEN_HOST='0.0.0.0',
))

rk_torrents = 'torrents'
# fmt_rk_peer = 'peer:{}'
fmt_rk_torrent = 'torrent:{}'
fmt_rk_torrent_seed = 'torrent:seed:{}'
fmt_rk_torrent_leech = 'torrent:leech:{}'

def get_rk_peer(peer_id):
    return 'peer:%s' % peer_id

def babort(message):
    return bresponse({
        'failure reason': message,
    })
def bresponse(payload):
    payload['interval'] = app.config['ANNOUNCE_INTERVAL']
    print payload
    return bencode(payload)


def client_ip():
    ip = request.args.get('ip', request.remote_addr)
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        ip = request.remote_addr
    except socket.error:
        pass
    return ip

def get_info_hash(multiple=False):
    qv = cgi.parse_qs(request.query_string).get('info_hash', [])
    if not multiple:
        return b2a_hex(qv[0])
    else:
        hashes = set()
        for hash in qv:
            hashes.add(b2a_hex(hash))
        return hashes


from redis import StrictRedis
redis = StrictRedis(host='localhost', port=6379, db=4)


@app.route("/")
@app.route("/torrents")
def hello():
    torrents = []
    fields = 'name created_at downloaded complete incomplete filename'.split()
    for info_hash in redis.smembers(rk_torrents):
        update_torrent(info_hash)
        info = dict(zip(fields, redis.hmget(fmt_rk_torrent.format(info_hash), *fields))) 
        torrents.append(info)
    return json.dumps(torrents)

def update_torrent(info_hash):
    torrent_key = fmt_rk_torrent.format(info_hash)
    seed_set_key  = fmt_rk_torrent_seed.format(info_hash)
    leech_set_key  = fmt_rk_torrent_leech.format(info_hash)
    redis.hmset(torrent_key, {
        #'downloaded': int(downloaded) if downloaded is not None else 0,
        'complete': redis.scard(seed_set_key) or 0,
        'incomplete': redis.scard(leech_set_key) or 0,
    })

def get_scrape_info(info_hash):
    update_torrent(info_hash)
    fields = 'name downloaded complete incomplete'.split()
    return dict(zip(fields, redis.hmget(fmt_rk_torrent.format(info_hash), *fields))) 


@app.route('/stats')
def stats():
    return json.dumps({
        'torrents': redis.scard(rk_torrents),
    })


@app.route('/media/<path:path>')
def media(path):
    return send_from_directory('media', path)

from werkzeug.utils import secure_filename
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        status = True
        message = 'ok'
        f = request.files['torrent']
        torrent_file_path = 'media/torrents/' + secure_filename(f.filename)
        print f
        print f.filename
        #import ipdb;ipdb.set_trace();
        f.save(torrent_file_path)
        with open(torrent_file_path, 'rb') as f:
            info_dict = bdecode(f.read())['info']
            info_hash = b2a_hex(hashlib.sha1(bencode(info_dict)).hexdigest())
            redis.sadd(rk_torrents, info_hash)
            torrent_key = fmt_rk_torrent.format(info_hash)
            redis.hmset(torrent_key, {
                'name': info_dict['name'],
                'filename': torrent_file_path,
                'created_at': int(time.time() * 1000),
            })
        return json.dumps(dict(status=status, message=message))
    return render_template('upload.html')


@app.route('/scrape')
def scape():
    info_hash_list = [
        info_hash for info_hash in get_info_hash(multiple=True)
        if redis.sismember(rk_torrents, info_hash)
    ]
    return bresponse({'files': map(get_scrape_info, info_hash_list)})


@app.route('/announce')
def announce():
    need_args = 'info_hash peer_id port uploaded downloaded left'.split()
    missing_args = [arg for arg in need_args if arg not in request.args]
    if missing_args:
        return babort('missing argument ({})'.format('|'.join(missing_args)))
    info_hash = b2a_hex(get_info_hash())
    peer_id = request.args['peer_id']
    rk_torrent = fmt_rk_torrent.format(info_hash)
    rk_peer = get_rk_peer(peer_id)
    if not redis.sismember(rk_torrents, info_hash):
        if not app.config['ALLOW_MISSING_INFOHASH']:
            return babort('torrent {} not allowed'.format(info_hash))
    compact_mode = False
    compact_mode = request.args.get('compact', False, bool)
    ip = client_ip()
    redis.hmset(rk_peer, {
        'ip': ip,
        'port': request.args.get('port', int),
        'uploaded': request.args['uploaded'],
        'downloaded': request.args['downloaded'],
        'left': request.args['left'],
    })
    redis.expire(rk_peer, app.config['ANNOUNCE_INTERVAL'] + 60)

    seed_set_key  = fmt_rk_torrent_seed.format(info_hash)
    leech_set_key  = fmt_rk_torrent_leech.format(info_hash)

    if request.args.get('event') == 'stopped':
        redis.srem(seed_set_key, peer_id)
        redis.srem(leech_set_key, peer_id)
        redis.delete(rk_peer)
        return bresponse({'peers': '' if compact_mode else []})
    elif request.args.get('event') == 'completed':
        redis.hincrby(rk_torrent, 'downloaded', 1)

    if request.args.get('left', 1, int) == 0 or request.args.get('event') == 'completed':
        redis.sadd(seed_set_key, peer_id)
        redis.srem(leech_set_key, peer_id)
    else:
        redis.sadd(leech_set_key, peer_id)
        redis.srem(seed_set_key, peer_id)

    peer_count = 0
    peers = []
    for peer_id in redis.sunion(seed_set_key, leech_set_key):
        rk_peer = get_rk_peer(peer_id)
        ip, port, left = redis.hmget(rk_peer, 'ip', 'port', 'left')
        if (ip and port) is None:
            redis.srem(seed_set_key, peer_id)
            redis.srem(leech_set_key, peer_id)
            continue
        elif peer_count >= request.args.get('numwant', 50, int):
            continue
        elif int(left) == 0 and request.args.get('left', 1, int) == 0:
            continue

        peer_count += 1
        if compact_mode:
            try:
                ip = socket.inet_pton(socket.AF_INET, ip)
            except socket.error:
                continue
            peers.append('{}{}'.format(ip, pack(">H", int(port))))
        else:
            peer = {'ip': ip, 'port': int(port)}
            if 'no_peer_id' not in request.args:
                peer['peer_id'] = peer_id
            peers.append(peer)

    return bresponse({
        'complete': redis.scard(seed_set_key),
        'incomplete': redis.scard(leech_set_key),
        'peers': ''.join(peers) if compact_mode else peers,
    })


if __name__ == "__main__":
    app.run(host=app.config['LISTEN_HOST'], port=app.config['LISTEN_PORT'])

