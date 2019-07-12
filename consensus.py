"""
Created on Thu Apr  4 14:09:35 2019

@author: gaurava
"""

import threading
from copy import copy
from hashlib import sha256
from urllib.parse import urlparse
import requests
from blspy import (PublicKey, Signature, AggregationInfo)
from flask import jsonify
from bls import BLS
from transaction import Transaction
from block import Block


class GoSigConsensus:
    @staticmethod
    def check_proposed(blockchain, logger, values):
        block = values.get('block')
        sig = values.get('sig')
        a = values.get('int_a')
        b = values.get('int_b')

        if (block is None) or (sig is None) or (a is None) or (b is None):
            return jsonify("Error: invalid json data received"), 301
        # sig = bytes(sig, "ISO-8859-1")
        # sig = Signature.from_bytes(sig)
        block = Block.create_block(block)
        flag = block.verify_block(blockchain)
        node_address = block.harvester
        if not flag:

            url = "http://" + node_address + "/check_conflict"
            json_data = {'node_address': blockchain.address}
            try:
                response = requests.post(url, json=json_data)
                blockchain.logger.info("----conflict response----")
                blockchain.logger.info(response.status_code)
                blockchain.logger.info(response.json())
                blockchain.logger.info("****conflict response****")
            except:
                pass
            print(node_address, " block didn't verified ")
            return jsonify("invalid block!"), 302


        # leader verification
        blockchain.logger.info("----fp----")
        blockchain.logger.info("before_true_leader " + node_address)
        blockchain.logger.info("first_sign_hash " + sha256(a.encode()).hexdigest())
        blockchain.logger.info("second_sign_hash " + sha256(b.encode()).hexdigest())
        blockchain.logger.info("****fp****")
        is_verified_leader = blockchain.true_leader(a, b, node_address)

        if not is_verified_leader:
            print("invalid leader", node_address)
            return jsonify("invalid leader!"), 303
        sig = BLS.deserialize(sig, Signature)
        # verify whether proposed block is from valid validator(node) with valid signature
        if node_address in blockchain.public_key_list and block.get_hash() not in blockchain.broadcast_list:
            _block = copy(block)
            _block.signature = sig
            _block.signers = []
            _block.signers.append(node_address)
            if _block.verify_block_signature(blockchain):

                # print("received proposed block, signature verified")

                blockchain.broadcast_list.append(block.get_hash())
                blockchain.broadcast_it("/proposed", values)
                logger.debug("proposed fxn call using hash: " + block.get_hash())

                blockchain.proposal_queue[a] = block
                threading.Thread(target=blockchain.sign_proposed_block,
                                 args={blockchain.sign_proposed_block_delay}).start()
            else:
                print("verify_block_signature")
                return jsonify("block signature couldn't verified"), 304
        return jsonify("True"), 200

    @staticmethod
    def commit(blockchain, logger, values):
        block_hash = values.get('block')
        signers = values.get('n_list')
        co_sig = values.get('co_sig')
        if block_hash is None or co_sig is None:
            return jsonify("tempered Data"), 300
        # co_sig = bytes(co_sig, "ISO-8859-1")
        # co_sig = Signature.from_bytes(co_sig)
        block = blockchain.proposal_verified_list.get(block_hash)
        if (block is None) or (signers is None):
            return jsonify("tempered Data"), 301
        # temp_co_sig = []
        # if type(co_sig) == list:
        #     for each_sig in co_sig:
        #         each_sig = bytes(each_sig, "ISO-8859-1")
        #         each_sig = Signature.from_bytes(each_sig)
        #         temp_co_sig.append(each_sig)
        #
        #     co_sig = Signature.aggregate(temp_co_sig)
        #     co_sig = str(co_sig.serialize(), "ISO-8859-1")
        node_address = block.harvester
        co_sig = BLS.deserialize(co_sig, Signature)
        block_hash_hash_digest = sha256(str(block_hash).encode()).hexdigest()
        if node_address in blockchain.public_key_list and block_hash_hash_digest not in blockchain.broadcast_list:
            if len(signers) / len(blockchain.public_key_list) > 0.66:
                _block = copy(block)
                _block.signature = co_sig
                _block.signers = signers
                if _block.verify_block_signature(blockchain):
                    blockchain.broadcast_list.append(block_hash_hash_digest)
                    blockchain.broadcast_it("/commit", values)
                    logger.debug("commit fxn call using hash: " + block_hash)
                    blockchain.commit_queue[block_hash] = block
                    threading.Thread(target=blockchain.sign_commit_block, args={blockchain.sign_commit_block_delay}).start()
                    return jsonify("BlockChain should be updated "), 200
                else:
                    logger.warning("given signature for commit verification is tempered")
                    return jsonify("BlockChain couldn't updated "), 201
            else:
                logger.warning("you did not get majority")
                return jsonify("BlockChain couldn't updated "), 202
        logger.warning("tempered data or retransmitted data")
        return jsonify("BlockChain couldn't updated "), 203

    @staticmethod
    def fetch_transaction(blockchain, values):
        txn_hash = values.get("txn_hash")
        if txn_hash is None:
            return jsonify("invalid txn hash"), 201
        if txn_hash in blockchain.current_transactions:
            response = {
                'txn': blockchain.current_transactions[txn_hash],
            }
            return jsonify(response), 200
        else:
            return jsonify("invalid txn hash"), 201

    @staticmethod
    def new_transaction(blockchain, logger, values):

        required = ['from', 'to', 'amount', 'signature', 'timestamp']
        if not all(k in values for k in required):
            return 'Missing values', 400
        transaction = Transaction.createTransaction(values)
        if transaction is None:
            logger.warning("transaction could not created")
            return 'Missing values', 500
        flag = transaction.verify_signature()
        if flag:
            txn_hash = transaction.get_hash()
            if txn_hash in blockchain.current_transactions:
                return jsonify("txn exists already"), 201
            # Create a new Transaction
            logger.debug("txn hash " + txn_hash)
            blockchain.current_transactions[txn_hash] = values
            blockchain.broadcast_it("/transactions/new", values)
            index = len(blockchain.chain) + 1
            response = f'Transaction will be added to Block {index}'
            logger.debug("transaction added in own list")
            return jsonify(response), 200
        else:
            logger.warning("transaction signature could not verified")
            return jsonify("transaction signature could not verified"), 201

    @staticmethod
    def ping(blockchain, logger, values):
        is_new_node = values.get("new_node")
        new_node_pub_key = values.get("pub_key")
        new_node_pub_key_list = values.get('pub_key_list')
        round_number = values.get('round_number')
        logger.debug(" ping received from " + is_new_node)
        if is_new_node and new_node_pub_key and round_number is not None:
            parsed_url = urlparse(is_new_node)
            if parsed_url.netloc or parsed_url.path:
                blockchain.nodes.add(is_new_node)
                blockchain.public_key_list[is_new_node] = new_node_pub_key
                for address in new_node_pub_key_list:
                    if address not in blockchain.public_key_list:
                        blockchain.public_key_list[address] = new_node_pub_key_list[address]
                        blockchain.register_node(address)
                logger.debug(blockchain.resolve_conflict(is_new_node))
                if blockchain.roundNumber < round_number:
                    blockchain.roundNumber = round_number
                return jsonify({"pub_key_list": blockchain.public_key_list,
                                "round_number": blockchain.roundNumber}), 200
            else:
                return jsonify('Invalid URL'), 200
        else:
            return jsonify("pingBack"), 201

    @staticmethod
    def reply_proposed(blockchain, logger, values):
        logger.debug("in reply_proposed fxn")
        signature = values.get('p_signed')
        node_address = values.get('address')
        if signature is None or node_address is None:
            return jsonify("Error: invalid json received, Bad request"), 200
        if node_address not in blockchain.public_key_list:
            return jsonify("Bad request"), 200
        signature = BLS.deserialize(signature, Signature)
        _block = copy(blockchain.proposed_block)
        _block.signature = signature
        _block.signers = []
        _block.signers.append(node_address)
        if _block.verify_block_signature(blockchain):
            logger.debug("reply proposal signature verified")
            blockchain.proposal_accepted[node_address] = signature
            return jsonify("proposal reply signature verified"), 200
        else:
            logger.warning("proposal reply signature tempered")
            return jsonify("proposal reply signature tempered"), 400

    @staticmethod
    def reply_commit(blockchain, logger, values):
        logger.debug("in reply_commit fxn")
        signature = values.get('tc_signed')
        node_address = values.get('address')
        if signature is None or node_address is None:
            return jsonify("Error: invalid json received, Bad request"), 400
        if node_address not in blockchain.public_key_list:
            return jsonify("Bad request"), 400

        signature = BLS.deserialize(signature, Signature)
        hash_of_priority_block = blockchain.proposed_block.get_hash()
        temp_array = []
        for c in hash_of_priority_block:
            temp_array.append(ord(c))
        msg = bytes(temp_array)

        signature.set_aggregation_info(
            AggregationInfo.from_msg(
                PublicKey.from_bytes(bytes(blockchain.public_key_list[node_address], "ISO-8859-1")), msg))
        verify_sign = signature.verify()

        if verify_sign:
            logger.debug("reply commit signature verified")
            blockchain.commit_accepted[node_address] = signature
            # print("commit accepted by ", len(blockchain.commit_accepted))
            return jsonify("True"), 200
        else:
            logger.warning("reply commit signature tempered")
            return jsonify("False"), 300

    @staticmethod
    def register_nodes(blockchain, logger, values):
        nodes = values.get('nodes')
        if nodes is None:
            return jsonify("Error: Please supply a valid list of nodes"), 400
        nodes = str(nodes).split(",")
        for node in nodes:
            logger.debug(node)
            if blockchain.register_node(node):
                blockchain.resolve_conflict(node)
        response = {
            'message': 'New nodes have been added',
            'total_nodes': list(blockchain.nodes),
        }
        return jsonify(response), 201

    @staticmethod
    def check_conflict(blockchain, logger, values):
        node_address = values.get('node_address')
        if node_address is None:
            return jsonify("bad request"), 400
        flag = blockchain.resolve_conflict(node_address)

        if flag == 1:
            response = "blockchain replaced, new hash " + blockchain.Hash
            return jsonify(response), 200
        elif flag == 0:
            response = "blockchain is up-to-date"
            return jsonify(response), 201
        elif flag == -2:
            response = "tempered chain received, couldn't update"
            return jsonify(response), 401
        else:
            return jsonify("error in /chain request"), 400

    @staticmethod
    def verified_commit(blockchain, logger, values):
        block_hash = values.get('block')
        if block_hash is None:
            return jsonify("tempered Data"), 401
        block = blockchain.commit_verified_list.get(block_hash)
        if block is None:
            return jsonify("verification block missing"), 402
        signers = values.get('n_list')
        co_sig = values.get('co_sig')
        if (signers is None) or (co_sig is None):
            return jsonify("tempered block data"), 403
        co_sig = BLS.deserialize(co_sig, Signature)
        flag = block.verify_block(blockchain)
        if not flag:
            return jsonify("invalid block!"), 301
        node_address = block.harvester
        block_hash_hexdigest = block.get_hash()
        if node_address in blockchain.public_key_list:
            if len(signers) / len(blockchain.public_key_list) > 0.66:

                temp_array = []
                for c in block_hash_hexdigest:
                    temp_array.append(ord(c))
                msg = bytes(temp_array)
                agg_info_list = []
                for node in signers:
                    if node in blockchain.public_key_list:
                        agg_info = AggregationInfo.from_msg(
                            PublicKey.from_bytes(bytes(blockchain.public_key_list[node], "ISO-8859-1")), msg)
                        agg_info_list.append(agg_info)
                    else:
                        return jsonify("BlockChain couldn't updated "), 302

                agg_public_key = AggregationInfo.merge_infos(agg_info_list)
                co_sig.set_aggregation_info(agg_public_key)
                verify_signature = co_sig.verify()

                if verify_signature:
                    logger.debug("hey you verified commit block" + block.get_hash())
                    block.signers = signers
                    block.signature = values.get('co_sig')
                    blockchain.update_blockchain(block)
                    return jsonify("BlockChain should be updated "), 200
                else:
                    return jsonify("BlockChain couldn't updated "), 303
            else:
                logger.warning("you didn't get majority")
                return jsonify("BlockChain couldn't updated "), 304
        logger.debug("node address didn't exists")
        return jsonify("BlockChain couldn't updated "), 305
