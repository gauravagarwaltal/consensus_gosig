#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr  4 14:09:35 2019

@author: gaurava
"""
from json import dumps, loads
import os
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
from blspy import PrivateKey
from block import Block
from transaction import Transaction
from flask.logging import default_handler
os.system("clear")
app = Flask(__name__)
import random
# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


@app.route('/send', methods=['POST'])
def create_transaction():
    values = request.get_json()
    print(values)
    try:
        to = values.get("node")
    except:
        return jsonify("bad request, parameters not found"), 401
    if to is None:
        to = "127.0.0.1:5001"

    seed = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    from_sk = PrivateKey.from_seed(seed)
    from_pk = from_sk.get_public_key()
    amount = random.randint(1, 100)

    seed = []
    for i in range(0, 32):
        seed.append(random.randint(0, 254))
    seed = bytes(seed)
    to_sk = PrivateKey.from_seed(seed)
    to_pk = to_sk.get_public_key()
    tx = Transaction(str(from_pk.serialize(), "ISO-8859-1"), str(to_pk.serialize(), "ISO-8859-1"), amount, from_sk)
    print(tx.verify_signature())
    url = "http://" + to + "/transactions/new"
    response = requests.post(url, json=tx.jsonify_Transaction())
    print(response.status_code)
    return jsonify("transaction created and sent to destination"), 200


@app.route('/block', methods=['GET'])
def create_block():
    # msg = dumps({
    #     "index": self.index,
    #     "harvester": self.harvester,
    #     "previous_hash": self.previous_hash,
    #     "txn": txn_hash,
    #     "signature": "",
    #     "signers": "",
    #     "timestamp": self.timestamp,
    # })
    _block = Block(2, "har", "33", [], "33", "23", "42424")
    url = "http://localhost:4999/send"
    response = requests.post(url, json=_block.jsonify_block())
    print(response.status_code)
    print(response.json())

    return _block.jsonify_block(), 200


def temp_fxn():
    dictionary = dict()
    dictionary["1"] = "1"
    dictionary["2"] = "2"
    values = dumps({"dict": dictionary, "d": "sdsds"})
    print(values)
    dictionary_1 = loads(values)["dict"]
    print(dictionary_1["1"])
    pass


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=4999, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.logger.removeHandler(default_handler)
    app.run(host='0.0.0.0', port=port)
    # temp_fxn()
