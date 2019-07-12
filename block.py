from hashlib import sha256
from json import dumps, loads
from copy import copy
from blspy import PublicKey, Signature, AggregationInfo
from bls import BLS
from transaction import Transaction

"""
block ->
    {
        index,
        harvester,
        previous_hash,
        timestamp,
        txn[],
        signature,
        signer[]
    }
"""


# noinspection PyTypeChecker
class Block:
    def __init__(self, _index=None, _harvester=None, _previous_hash=None,
                 _txn=None, _signature=None, _signers=None, _timestamp=None):
        if (_index is None) or (_harvester is None) or (_previous_hash is None) or (_txn is None) or (
                _signature is None) or (_signers is None) or (_timestamp is None):
            pass
        else:
            self.index = _index
            self.harvester = _harvester
            self.previous_hash = _previous_hash
            self.txn = _txn
            self.signature = _signature
            self.signers = _signers
            self.timestamp = _timestamp

    @staticmethod
    def create_block(json_data):
        try:
            block = Block()
            block.index = json_data["index"]
            block.harvester = json_data["harvester"]
            block.previous_hash = json_data["previous_hash"]
            block.txn = json_data["txn"]
            block.signature = json_data["signature"]
            block.signers = json_data["signers"]
            block.timestamp = json_data["timestamp"]
            return block
        except:
            try:
                json_data = loads(json_data)
                block = Block()
                block.index = json_data["index"]
                block.harvester = json_data["harvester"]
                block.previous_hash = json_data["previous_hash"]
                block.txn = json_data["txn"]
                block.signature = json_data["signature"]
                block.signers = json_data["signers"]
                block.timestamp = json_data["timestamp"]
                return block
            except:
                return None

    def jsonify_block(self):
        block_content = dumps({
            "index": self.index,
            "harvester": self.harvester,
            "previous_hash": self.previous_hash,
            "txn": self.txn,
            "signature": self.signature,
            "signers": self.signers,
            "timestamp": self.timestamp,
        })
        return block_content

    def get_hash(self):
        return sha256(self.jsonify_block().encode()).hexdigest()

    def sign_block(self, private_key):
        if type(self.txn) == list:
            txn_hash = self.txn
            txn_hash.sort()
        elif type(self.txn) == dict:
            txn_hash = list(self.txn.keys())
            txn_hash.sort()
        else:
            return False

        msg = dumps({
            "index": self.index,
            "harvester": self.harvester,
            "previous_hash": self.previous_hash,
            "txn": txn_hash,
            "signature": "",
            "signers": "",
            "timestamp": self.timestamp,
        })
        temp_array = []
        for c in msg:
            temp_array.append(ord(c))
        msg = bytes(temp_array)

        sig = private_key.sign(msg)
        return str(sig.serialize(), "ISO-8859-1")

    def verify_block(self, blockchain):
        transactions = self.txn
        local_utxo = blockchain.UTXO.copy()
        for txn_hash in transactions:
            if txn_hash not in blockchain.current_transactions:
                txn = blockchain.fetch_txn(txn_hash, loads(blockchain.chain[blockchain.Hash])['harvester'])
                txn = Transaction.createTransaction(txn)
                if txn:
                    blockchain.current_transactions[txn_hash] = txn.jsonify_Transaction()
                else:
                    return False
            txn = blockchain.current_transactions[txn_hash]
            tx = Transaction().createTransaction(txn)
            flag = tx.verify_signature()
            if not flag:
                return False
            if tx.sender in local_utxo:

                if tx.amount <= local_utxo[tx.sender]:
                    local_utxo[tx.sender] = local_utxo[tx.sender] - tx.amount
                else:
                    return False
            else:
                return False
        flag = blockchain.Hash == self.previous_hash
        if flag:
            return flag
        else:
            blockchain.resolve_conflict(self.harvester)
            return flag

    def verify_offline_block(self, blockchain):
        if self.verify_block_signature(blockchain):

            return blockchain.Hash == self.previous_hash
            # print(blockchain.Hash, self.previous_hash)
            # if flag:
            #     return flag
            # else:
            #     blockchain.resolve_conflict(self.harvester)
            #     return flag
            # return flag
        else:
            if self.harvester == "genesis":
                return True
            print("tempered offline block signature")
            return False

    def update_block(self, blockchain):
        if blockchain.Hash == self.previous_hash:
            block_transactions = dict()
            for txn_hash in self.txn:
                txn = Transaction.createTransaction(blockchain.current_transactions[txn_hash])
                if txn.sender in blockchain.UTXO:
                    if txn.amount <= blockchain.UTXO[txn.sender]:
                        if txn.to not in blockchain.UTXO:
                            blockchain.UTXO[txn.to] = 0
                        blockchain.UTXO[txn.sender] = blockchain.UTXO[txn.sender] - txn.amount
                        blockchain.UTXO[txn.to] = blockchain.UTXO[txn.to] + txn.amount
                        block_transactions[txn.get_hash()] = txn.jsonify_Transaction()
                        blockchain.current_transactions.pop(txn_hash)
            self.txn = block_transactions

    def verify_block_signature(self, blockchain):
        if type(self.txn) == list:
            txn_hash = self.txn
            txn_hash.sort()
        elif type(self.txn) == dict:
            txn_hash = list(self.txn.keys())
            txn_hash.sort()
        else:
            return False
        msg = dumps({
            "index": self.index,
            "harvester": self.harvester,
            "previous_hash": self.previous_hash,
            "txn": txn_hash,
            "signature": "",
            "signers": "",
            "timestamp": self.timestamp,
        })
        temp_array = []
        for c in msg:
            temp_array.append(ord(c))
        msg = bytes(temp_array)

        if type(self.signature) == Signature:
            pass
        else:
            self.signature = BLS.deserialize(self.signature, Signature)

        agg_info_list = []
        for node in self.signers:
            if node in blockchain.public_key_list:
                agg_info = AggregationInfo.from_msg(
                    PublicKey.from_bytes(bytes(blockchain.public_key_list[node], "ISO-8859-1")), msg)
                agg_info_list.append(agg_info)
            else:
                return False
        agg_public_key = AggregationInfo.merge_infos(agg_info_list)
        self.signature.set_aggregation_info(agg_public_key)
        return self.signature.verify()

    def verify_offline_block_signature(self, blockchain):
        if type(self.txn) == list:
            txn_hash = self.txn
            txn_hash.sort()
        elif type(self.txn) == dict:
            txn_hash = list(self.txn.keys())
            txn_hash.sort()
        else:
            return False
        block = copy(self)
        block.signature = ""
        block.signers = ""
        block.txn = txn_hash
        msg = block.get_hash()

        temp_array = []
        for c in msg:
            temp_array.append(ord(c))
        msg = bytes(temp_array)

        if type(self.signature) == Signature:
            pass
        else:
            self.signature = BLS.deserialize(self.signature, Signature)

        agg_info_list = []
        for node in self.signers:
            if node in blockchain.public_key_list:
                agg_info = AggregationInfo.from_msg(
                    PublicKey.from_bytes(bytes(blockchain.public_key_list[node], "ISO-8859-1")), msg)
                agg_info_list.append(agg_info)
            else:
                return False
        agg_public_key = AggregationInfo.merge_infos(agg_info_list)
        self.signature.set_aggregation_info(agg_public_key)
        return self.signature.verify()

    # def temp(self, public_key_list):
    #     if type(self.txn) == list:
    #         txn_hash = self.txn
    #         txn_hash.sort()
    #     elif type(self.txn) == dict:
    #         txn_hash = list(self.txn.keys())
    #         txn_hash.sort()
    #     else:
    #         return False
    #     block = copy(self)
    #     block.signature = ""
    #     block.signers = ""
    #     block.txn = txn_hash
    #     msg = block.get_hash()
    #
    #     temp_array = []
    #     for c in msg:
    #         temp_array.append(ord(c))
    #     msg = bytes(temp_array)
    #     print("ph ", self.previous_hash)
    #     if type(self.signature) == Signature:
    #         pass
    #     else:
    #         self.signature = BLS.deserialize(self.signature, Signature)
    #
    #     agg_info_list = []
    #     for node in self.signers:
    #         if node in public_key_list:
    #             agg_info = AggregationInfo.from_msg(public_key_list[node], msg)
    #             agg_info_list.append(agg_info)
    #         else:
    #             return False
    #     agg_public_key = AggregationInfo.merge_infos(agg_info_list)
    #
    #     self.signature.set_aggregation_info(agg_public_key)
    #     return self.signature.verify()


# _block = Block("1", "22", "hash", ["2"], "sig", ["22"])
# js = _block.jsonify_block()
# print(_block.jsonify_block())
#
# _block1 = Block.create_block({"index": "1", "harvester": "22", "previous_hash": "hash",
#                               "txn": ["2"], "signature": "sig", "signers": ["22"], "timestamp": 1562159814.1128297})
# print(_block1.verify_block())
