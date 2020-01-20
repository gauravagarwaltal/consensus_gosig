#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr  4 14:09:35 2019

@author: gaurava
"""

import configparser
import logging
import os
from uuid import uuid4

from flask import Flask, request
from flask.logging import default_handler

from blockchain import *
from consensus import *

os.system("clear")

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


@app.route('/balance', methods=['GET'])
def balance():
    response = {
        'utxo': blockchain.UTXO
    }
    return jsonify(response), 200


@app.route('/check_conflict', methods=['POST'])
def check_conflicts():
    values = request.get_json()
    return GoSigConsensus.check_conflict(blockchain, logger, values)


@app.route('/proposed', methods=['POST'])
def check_proposed():
    values = request.get_json()
    return GoSigConsensus.check_proposed(blockchain, logger, values)


@app.route('/check', methods=['GET'])
def check():
    response = {
        'isValid': list(blockchain.nodes),
        'pub_key_list': blockchain.public_key_list,
        'txn': blockchain.current_transactions,
        'round_number': str(blockchain.roundNumber),
    }
    return jsonify(response), 200


@app.route('/commit', methods=['POST'])
def commit():
    values = request.get_json()
    return GoSigConsensus.commit(blockchain, logger, values)


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'Hash': blockchain.Hash,
    }
    return jsonify(response), 200


@app.route('/fetch/txn', methods=['POST'])
def fetch_transaction():
    values = request.get_json()
    return GoSigConsensus.fetch_transaction(blockchain, values)


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    return GoSigConsensus.new_transaction(blockchain, logger, values)


@app.route('/ping', methods=['POST'])
def ping():
    values = request.get_json()
    return GoSigConsensus.ping(blockchain, logger, values)


@app.route('/reply_proposal', methods=['POST'])
def reply_proposed():
    values = request.get_json()
    return GoSigConsensus.reply_proposed(blockchain, logger, values)


@app.route('/reply_commit', methods=['POST'])
def reply_commit():
    values = request.get_json()
    return GoSigConsensus.reply_commit(blockchain, logger, values)


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    return GoSigConsensus.register_nodes(blockchain, logger, values)


@app.route('/verified_commit', methods=['POST'])
def verified_commit():
    values = request.get_json()
    return GoSigConsensus.verified_commit(blockchain, logger, values)


def read_config(_blockchain):
    config = configparser.RawConfigParser()
    config.read('configuration.properties')

    _blockchain.round_time = float(config.get('time', 'round_time'))
    _blockchain.sign_proposed_block_delay = float(config.get('time', 'sign_proposed_block_delay'))
    _blockchain.propose_block_check = float(config.get('time', 'propose_block_check'))
    _blockchain.sign_commit_block_delay = float(config.get('time', 'sign_commit_block_delay'))
    _blockchain.commit_delay = float(config.get('time', 'commit_delay'))

    _blockchain.min_participants = float(config.get('consensus', 'min_participants'))
    _blockchain.leader_hash_check = config.get('consensus', 'leader_hash_check')


def setup_logger(name, log_file, _formatter, _level=logging.INFO):
    """Function setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(_formatter)

    _logger = logging.getLogger(name)
    _logger.setLevel(_level)
    _logger.addHandler(handler)
    return _logger


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5002, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    # Instantiate the Blockchain
    LOG_FILENAME = "logFiles/" + str(port) + "_1" + time.strftime("-%m%d-%H%M") + ".log"
    block_LOG_FILENAME = "logFiles/" + str(port) + time.strftime("-%m%d-%H%M") + ".log"

    if not os.path.isdir("logFiles"):
        os.makedirs("logFiles")

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    LOG_FILENAME = os.path.join(os.path.dirname(os.path.realpath(__file__)), LOG_FILENAME)
    block_LOG_FILENAME = os.path.join(os.path.dirname(os.path.realpath(__file__)), block_LOG_FILENAME)

    # first file logger
    logger = setup_logger('flask_logger', LOG_FILENAME, formatter, _level=logging.DEBUG)

    # second file logger
    block_logger = setup_logger('block_logger', block_LOG_FILENAME, formatter, _level=logging.INFO)
    logger.debug("Author   : gaurav agarwal")
    logger.debug("Application : GoSig Consensus")
    logger.debug("")
    logger.info('This is a debug message')
    blockchain = Blockchain(port, block_logger)
    blockchain_thread = threading.Thread(target=blockchain.leader_process)
    blockchain_thread.setDaemon(True)
    blockchain_thread.start()
    read_config(blockchain)
    app.run(host='0.0.0.0', port=port)
