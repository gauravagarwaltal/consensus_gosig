"""
Transcation class for creating, verifying transaction
"""
from blspy import PrivateKey, PublicKey, Signature, AggregationInfo
from json import dumps, loads
from hashlib import sha256
import time
import sys


# noinspection PyTypeChecker
class Transaction:
    def __init__(self, _sender=None, _to=None, _amount=None, private_key=None):
        if (_sender is None) or (_to is None) or (_amount is None) or (private_key is None):
            pass
        else:
            self.sender = _sender
            self.to = _to
            self.amount = _amount
            self.timestamp = time.time()
            self.signature = self.do_signature(private_key)

    @staticmethod
    def createTransaction(json_data):
        try:
            tx = Transaction()
            tx.sender = json_data["from"]
            tx.to = json_data["to"]
            tx.amount = json_data["amount"]
            tx.signature = json_data["signature"]
            tx.timestamp = json_data["timestamp"]
            return tx
        except:
            try:
                json_data = loads(json_data)
                tx = Transaction()
                tx.sender = json_data["from"]
                tx.to = json_data["to"]
                tx.amount = json_data["amount"]
                tx.signature = json_data["signature"]
                tx.timestamp = json_data["timestamp"]
                return tx
            except:
                return None

    def jsonify_Transaction(self):
        txn_content = dumps({
            "from": self.sender,
            "to": self.to,
            "amount": self.amount,
            "signature": self.signature,
            "timestamp": self.timestamp,
        })
        return txn_content

    def get_hash(self):
        return sha256(self.jsonify_Transaction().encode()).hexdigest()

    def do_signature(self, private_key):
        temp_array = []
        msg = self.sender + self.to + str(self.amount) + str(self.timestamp)

        for c in msg:
            temp_array.append(ord(c))
        msg = bytes(temp_array)
        if type(private_key) is PrivateKey:
            sig = private_key.sign(msg)
        else:
            sig = PrivateKey.from_bytes(bytes(private_key, "ISO-8859-1")).sign(msg)
        return str(sig.serialize(), "ISO-8859-1")

    def verify_signature(self):
        temp_array = []
        msg = self.sender + self.to + str(self.amount) + str(self.timestamp)
        for c in msg:
            temp_array.append(ord(c))
        msg = bytes(temp_array)

        _signature = bytes(self.signature, "ISO-8859-1")
        _signature = Signature.from_bytes(_signature)
        public_key = PublicKey.from_bytes(bytes(self.sender, "ISO-8859-1"))
        _signature.set_aggregation_info(AggregationInfo.from_msg(public_key, msg))
        return _signature.verify()

    @staticmethod
    def process_transaction(blockchain):
        hashed_txn = []
        transactions = blockchain.current_transactions.keys()
        dummy_txn = []

        local_utxo = blockchain.UTXO.copy()
        for txn_hash in transactions:
            txn = blockchain.current_transactions[txn_hash]
            tx = Transaction().createTransaction(txn)
            if tx.sender in local_utxo:
                if tx.amount <= local_utxo[tx.sender]:
                    local_utxo[tx.sender] = local_utxo[tx.sender] - tx.amount
                    hashed_txn.append(sha256(str(txn).encode()).hexdigest())
                else:
                    dummy_txn.append(txn_hash)
            else:
                dummy_txn.append(txn_hash)
            if len(hashed_txn) > 50:
                break
        # print(len(dummy_txn), len(hashed_txn))
        return hashed_txn, dummy_txn


# seed = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
# from_sk = PrivateKey.from_seed(seed)
# from_pk = from_sk.get_public_key()
#
# seed = bytes([0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
#               19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
#               82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22])
# to_sk = PrivateKey.from_seed(seed)
# to_pk = to_sk.get_public_key()
# tx = Transaction(str(from_pk.serialize(), "ISO-8859-1"), str(from_pk.serialize(), "ISO-8859-1"), 12, from_sk)
# sss = tx.jsonify_Transaction()
# print(sss)
# tx2 = Transaction.createTransaction(tx.jsonify_Transaction())
# print(tx2.verify_signature())
#
# print(sys.getsizeof("00b739f43e0176b25532e0b58f45e7fca7cd0566ca53f2b1d605c75aead4b9eb: {\"index\": 3, \"harvester\": \"127.0.0.1:5001\", \"previous_hash\": \"cd005d6daf0ada838d5169ce810f2e4e6ecaa39b4d46ec0d1f4072f385f26d8a\", \"txn\": {\"c0a822d94844ba16f248acb9c24b5d8d292421fcf5b1b798d27550d48918d1ea\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u0017\\\\u00cb\\\\b\\\\u001b\\\\u00ce=U\\\\u00f5~\\\\u001b\\\\u00e1\\\\u0094\\\\u00c5\\\\b\\\\u00f9W+\\\\u00d5\\\\u00f5\\\\u00d9\\\\u00aeg\\\\u00a4\\\\u0081\\\\u0006\\\\u000b\\\\u00f9]\\\\b\\\\u00a5\\\\u00e8\\\\u008a\\\\\\\\\\\\u0080|\\\\b\\\\u00d0\\\\u0010\\\\u00ff\\\\u008c\\\\u00d0\\\\u00bb\\\\u00bc\\\\u00c8\\\\u00be\\\\u00a5\\\\u000b\\\\u00e8\\\", \\\"amount\\\": 65, \\\"signature\\\": \\\"\\\\t\\\\u0099\\\\u00de\\\\u00f10\\\\u00f8\\\\u00c7*Y\\\\u001a\\\\u00a1\\\\u0006\\\\u0091\\\\u00b0\\\\u0094\\\\u00a2.\\\\u00f3y\\\\\\\"L\\\\u00e1\\\\u00c8(\\\\u00cd\\\\u00bbiR>\\\\u00e4W\\\\u00f3\\\\u00a0zz \\\\u00d9\\\\u009c\\\\u00ab\\\\u00f8\\\\u00ea\\\\u00ea.g\\\\u00dc\\\\u009f\\\\u009b\\\\u00b9\\\\u0006S\\\\u00853UQ\\\\u00bc\\\\u000fp,\\\\u00f6G>>\\\\u00d3jM!\\\\u00d5\\\\u00c4\\\\u008e\\\\u00fd\\\\u001b\\\\u00ab\\\\u00897\\\\u00cfcpg_\\\\u00e4g\\\\u0091\\\\u00c6C}\\\\u00b2}\\\\u001d\\\\u00ba\\\\u00e7\\\\u00ad* \\\\u0092\\\\u00fcQ\\\", \\\"timestamp\\\": 1562912721.6483772}\", \"e2139da7bbb5ff1963a5012cf748caa035d34b83706d05bf094d06711f4f50ff\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\nET\\\\u00ae\\\\u00eb~\\\\u0095\\\\u0005g`\\\\u00d8,\\\\u0094/\\\\u00ceY(\\\\u00c6\\\\u00ba\\\\u00da\\\\\\\\(\\\\u009bO\\\\u00a6}\\\\u00e4f\\\\u000b\\\\u0006e\\\\u00d1\\\\u00a4@[u\\\\u00f7\\\\u009b\\\\u00aa\\\\u00dd\\\\\\\"M\\\\u00b291\\\\u009c0F\\\", \\\"amount\\\": 71, \\\"signature\\\": \\\"\\\\f\\\\u009f\\\\u00ab\\\\u007f\\\\u00f0\\\\u00a1/\\\\u009b\\\\u0081v\\\\u0019i\\\\u00d1\\\\u0087\\\\u0090\\\\u00d6@\\\\u009aR\\\\u0080\\\\u0092\\\\u00d2\\\\u00a4\\\\u00e1\\\\u00ae\\\\u0094\\\\u00a4y1{i\\\\u009c\\\\u00f2\\\\u00cbq<HE\\\\u00d3IpC\\\\u00b1\\\\u00c5\\\\u00d8\\\\u00aa\\\\u00a5\\\\u0096\\\\ro\\\\u00908\\\\u00dc\\\\u00cf\\\\u008c?\\\\u00ef\\\\u00ed\\\\u000ba\\\\u001f\\\\u00a3{2\\\\u0097\\\\u00a8\\\\u0000\\\\u00bcY\\\\u00b4\\\\u00a8\\\\u00eco\\\\u00ff\\\\u0013a\\\\u00af\\\\u00cf\\\\u00a9\\\\u0098f\\\\u001c\\\\u00b1\\\\\\\"\\\\u00eb\\\\u00c7\\\\u00e9b\\\\u00fc?\\\\u0016\\\\u00be\\\\u00fc\\\\u00b1*\\\\u009d\\\", \\\"timestamp\\\": 1562912728.7052476}\", \"e405e23828c73efe7aee54407d849da8dd3d84a186bcfa2e24733ac7c83796a8\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u008d\\\\u00d6\\\\u0091\\\\u00125\\\\u00cd\\\\u009a:\\\\u0088\\\\u00d1\\\\u00a7J\\\\r\\\\u00ab/4k\\\\u00be\\\\u00c9\\\\u0092\\\\u00bbm\\\\u00bd\\\\u00af\\\\u0010\\\\u00d4\\\\u00c0k\\\\u008a=e\\\\u00e2\\\\bn\\\\bb\\\\u009ce\\\\u00be\\\\u0085\\\\u00fa\\\\u0090[\\\\u001e\\\\u00a4A5\\\\u00d6\\\", \\\"amount\\\": 49, \\\"signature\\\": \\\"\\\\u0019yxSs\\\\u0019\\\\u00e4\\\\u0085\\\\u00ab\\\\u00c7\\\\u0085\\\\u001d\\\\u00d9\\\\u0099!\\\\u0010\\\\u0092\\\\u0017\\\\u00f4\\\\\\\"\\\\u00b85\\\\u00eb\\\\u00d7\\\\u00fa\\\\u00be\\\\u0095&\\\\u00a0\\\\u0000m)\\\\u00ea\\\\u00ffR\\\\u00e3=M*\\\\r\\\\b\\\\u00d3\\\\u00b0T\\\\u00a0\\\\u00b2t\\\\u00e0\\\\u0011A\\\\u0095\\\\u00cc\\\\u00d7\\\\u008a\\\\u00d7\\\\u0084\\\\u001f\\\\u00b7\\\\u0005|\\\\u0084\\\\u0015\\\\u00e0\\\\u00e6,JD\\\\u00b1\\\\u00ed\\\\u001b\\\\u00c8z\\\\u00a0\\\\u009f\\\\u00ed\\\\u00b8\\\\u0080\\\\u00e5\\\\u00f3\\\\u008ax\\\\u00aa',\\\\u0098VE+=\\\\u00aa\\\\u0005\\\\u00b4\\\\u00f4\\\\u0012\\\\u0018\\\\u00e5\\\", \\\"timestamp\\\": 1562912714.5846517}\", \"ebd3189589d575800cd9deba9751031603b6e0acdc30c719bb53045ce85acb0c\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u0006\\\\u00db\\\\u00e6\\\\u00b6\\\\u007f(\\\\u00c4\\\\u00bd\\\\u00faY\\\\u0002\\\\u00c4 Y\\\\u00b0M\\\\u00ac\\\\u0001\\\\u00a0\\\\u00d2\\\\u008160\\\\u0014\\\\u000b_\\\\u00cc\\\\u008f|U\\\\n\\\\u0088/\\\\u00bb\\\\u001a\\\\u0093\\\\u0082\\\\u009f\\\\u00b5\\\\tU\\\\u0095\\\\n0\\\\u00d8E\\\\u00eb\\\\u00b2\\\", \\\"amount\\\": 100, \\\"signature\\\": \\\"\\\\u0014\\\\u00ae\\\\u00e5\\\\u00e6\\\\b.\\\\u0006`\\\\u0083C\\\\u009ap\\\\u008d\\\\u00df\\\\u0090QQ\\\\u00f9\\\\u00d4\\\\u00ae6\\\\u009d\\\\u00a4\\\\u0084<\\\\u009b\\\\u00f7\\\\u00e93\\\\u00f5\\\\u00ca\\\\u00bd\\\\u0016\\\\u00e5v^\\\\u00c6K(Md(\\\\u001b\\\\u00f3\\\\u009a\\\\f\\\\u00c0;\\\\u0013\\\\u00dc\\\\u00d7x\\\\u0002\\\\u0017\\\\u00bb\\\\u0002\\\\u000f\\\\u00ca\\\\u00c6\\\\u00d8\\\\u00f9\\\\u0092\\\\u00f7`\\\\u00be\\\\u0001\\\\u0004\\\\u00bb(\\\\u00f6\\\\u00f8\\\\u00d7c\\\\u00fd\\\\u00ed\\\\u008a\\\\u0092\\\\u0081\\\\u00176\\\\u00c4*\\\\u00d1\\\\u00c3<TH\\\\u00b1\\\\u00b5\\\\u0081\\\\u0011\\\\u0092\\\\u00d1\\\\u00de\\\\u00c6C\\\", \\\"timestamp\\\": 1562912707.5153232}\"}, \"signature\": \"\\u0099O\\u000f\\u00d8\\u0091R\\u00a7\\u008b\\u0014\\u0092\\u0091\\u0081\\u00ce\\u00d11\\u00ec\\\\\\u00aaUU\\u00ce\\u00a5\\u00b8\\u0089\\u0005#\\u00c5\\u00ba\\u0003\\u00d9h\\u00e33\\u00beW\\u009faj\\u00dd\\u00da\\u0006\\u008c9\\u00daBs\\u0007(\\u0017\\u000f\\u00e5s\\u000e\\u00a4\\u009d\\u00e2\\u00c3\\u0085\\u0019\\u00a4f\\u009bR\\u0081?/U\\u00ea\\u00ea\\u00cb\\f\\u00f6\\u00c4Ms\\u00f4\\u00e8%\\u0018\\u00bd\\u00c1R:\\u00b5\\u0080\\u0014\\u00d1N4!\\\\\\u00b8\\u00cf\\u00dc\\u00103\", \"signers\": [\"127.0.0.1:5001\", \"127.0.0.1:5000\", \"127.0.0.1:5003\", \"127.0.0.1:5002\"], \"timestamp\": 1562912731.465246}"))
# print(len("00b739f43e0176b25532e0b58f45e7fca7cd0566ca53f2b1d605c75aead4b9eb: {\"index\": 3, \"harvester\": \"127.0.0.1:5001\", \"previous_hash\": \"cd005d6daf0ada838d5169ce810f2e4e6ecaa39b4d46ec0d1f4072f385f26d8a\", \"txn\": {\"c0a822d94844ba16f248acb9c24b5d8d292421fcf5b1b798d27550d48918d1ea\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u0017\\\\u00cb\\\\b\\\\u001b\\\\u00ce=U\\\\u00f5~\\\\u001b\\\\u00e1\\\\u0094\\\\u00c5\\\\b\\\\u00f9W+\\\\u00d5\\\\u00f5\\\\u00d9\\\\u00aeg\\\\u00a4\\\\u0081\\\\u0006\\\\u000b\\\\u00f9]\\\\b\\\\u00a5\\\\u00e8\\\\u008a\\\\\\\\\\\\u0080|\\\\b\\\\u00d0\\\\u0010\\\\u00ff\\\\u008c\\\\u00d0\\\\u00bb\\\\u00bc\\\\u00c8\\\\u00be\\\\u00a5\\\\u000b\\\\u00e8\\\", \\\"amount\\\": 65, \\\"signature\\\": \\\"\\\\t\\\\u0099\\\\u00de\\\\u00f10\\\\u00f8\\\\u00c7*Y\\\\u001a\\\\u00a1\\\\u0006\\\\u0091\\\\u00b0\\\\u0094\\\\u00a2.\\\\u00f3y\\\\\\\"L\\\\u00e1\\\\u00c8(\\\\u00cd\\\\u00bbiR>\\\\u00e4W\\\\u00f3\\\\u00a0zz \\\\u00d9\\\\u009c\\\\u00ab\\\\u00f8\\\\u00ea\\\\u00ea.g\\\\u00dc\\\\u009f\\\\u009b\\\\u00b9\\\\u0006S\\\\u00853UQ\\\\u00bc\\\\u000fp,\\\\u00f6G>>\\\\u00d3jM!\\\\u00d5\\\\u00c4\\\\u008e\\\\u00fd\\\\u001b\\\\u00ab\\\\u00897\\\\u00cfcpg_\\\\u00e4g\\\\u0091\\\\u00c6C}\\\\u00b2}\\\\u001d\\\\u00ba\\\\u00e7\\\\u00ad* \\\\u0092\\\\u00fcQ\\\", \\\"timestamp\\\": 1562912721.6483772}\", \"e2139da7bbb5ff1963a5012cf748caa035d34b83706d05bf094d06711f4f50ff\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\nET\\\\u00ae\\\\u00eb~\\\\u0095\\\\u0005g`\\\\u00d8,\\\\u0094/\\\\u00ceY(\\\\u00c6\\\\u00ba\\\\u00da\\\\\\\\(\\\\u009bO\\\\u00a6}\\\\u00e4f\\\\u000b\\\\u0006e\\\\u00d1\\\\u00a4@[u\\\\u00f7\\\\u009b\\\\u00aa\\\\u00dd\\\\\\\"M\\\\u00b291\\\\u009c0F\\\", \\\"amount\\\": 71, \\\"signature\\\": \\\"\\\\f\\\\u009f\\\\u00ab\\\\u007f\\\\u00f0\\\\u00a1/\\\\u009b\\\\u0081v\\\\u0019i\\\\u00d1\\\\u0087\\\\u0090\\\\u00d6@\\\\u009aR\\\\u0080\\\\u0092\\\\u00d2\\\\u00a4\\\\u00e1\\\\u00ae\\\\u0094\\\\u00a4y1{i\\\\u009c\\\\u00f2\\\\u00cbq<HE\\\\u00d3IpC\\\\u00b1\\\\u00c5\\\\u00d8\\\\u00aa\\\\u00a5\\\\u0096\\\\ro\\\\u00908\\\\u00dc\\\\u00cf\\\\u008c?\\\\u00ef\\\\u00ed\\\\u000ba\\\\u001f\\\\u00a3{2\\\\u0097\\\\u00a8\\\\u0000\\\\u00bcY\\\\u00b4\\\\u00a8\\\\u00eco\\\\u00ff\\\\u0013a\\\\u00af\\\\u00cf\\\\u00a9\\\\u0098f\\\\u001c\\\\u00b1\\\\\\\"\\\\u00eb\\\\u00c7\\\\u00e9b\\\\u00fc?\\\\u0016\\\\u00be\\\\u00fc\\\\u00b1*\\\\u009d\\\", \\\"timestamp\\\": 1562912728.7052476}\", \"e405e23828c73efe7aee54407d849da8dd3d84a186bcfa2e24733ac7c83796a8\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u008d\\\\u00d6\\\\u0091\\\\u00125\\\\u00cd\\\\u009a:\\\\u0088\\\\u00d1\\\\u00a7J\\\\r\\\\u00ab/4k\\\\u00be\\\\u00c9\\\\u0092\\\\u00bbm\\\\u00bd\\\\u00af\\\\u0010\\\\u00d4\\\\u00c0k\\\\u008a=e\\\\u00e2\\\\bn\\\\bb\\\\u009ce\\\\u00be\\\\u0085\\\\u00fa\\\\u0090[\\\\u001e\\\\u00a4A5\\\\u00d6\\\", \\\"amount\\\": 49, \\\"signature\\\": \\\"\\\\u0019yxSs\\\\u0019\\\\u00e4\\\\u0085\\\\u00ab\\\\u00c7\\\\u0085\\\\u001d\\\\u00d9\\\\u0099!\\\\u0010\\\\u0092\\\\u0017\\\\u00f4\\\\\\\"\\\\u00b85\\\\u00eb\\\\u00d7\\\\u00fa\\\\u00be\\\\u0095&\\\\u00a0\\\\u0000m)\\\\u00ea\\\\u00ffR\\\\u00e3=M*\\\\r\\\\b\\\\u00d3\\\\u00b0T\\\\u00a0\\\\u00b2t\\\\u00e0\\\\u0011A\\\\u0095\\\\u00cc\\\\u00d7\\\\u008a\\\\u00d7\\\\u0084\\\\u001f\\\\u00b7\\\\u0005|\\\\u0084\\\\u0015\\\\u00e0\\\\u00e6,JD\\\\u00b1\\\\u00ed\\\\u001b\\\\u00c8z\\\\u00a0\\\\u009f\\\\u00ed\\\\u00b8\\\\u0080\\\\u00e5\\\\u00f3\\\\u008ax\\\\u00aa',\\\\u0098VE+=\\\\u00aa\\\\u0005\\\\u00b4\\\\u00f4\\\\u0012\\\\u0018\\\\u00e5\\\", \\\"timestamp\\\": 1562912714.5846517}\", \"ebd3189589d575800cd9deba9751031603b6e0acdc30c719bb53045ce85acb0c\": \"{\\\"from\\\": \\\"\\\\u008d\\\\u0006\\\\u00efP^\\\\u0091P^\\\\u00ae\\\\u00caW\\\\u00b4\\\\\\\\\\\\u00e5\\\\u00ea1\\\\u0084\\\\r\\\\u001au\\\\u00c9\\\\u00a5\\\\u00ea2H;z\\\\u0087\\\\u00ed\\\\u0016Hv\\\\u00a7\\\\u0000\\\\u00c8^gkE\\\\u0018\\\\f\\\\u0017\\\\u0016\\\\u00a2\\\\u0007\\\\u00fa\\\\u0004\\\\u00b0\\\", \\\"to\\\": \\\"\\\\u0006\\\\u00db\\\\u00e6\\\\u00b6\\\\u007f(\\\\u00c4\\\\u00bd\\\\u00faY\\\\u0002\\\\u00c4 Y\\\\u00b0M\\\\u00ac\\\\u0001\\\\u00a0\\\\u00d2\\\\u008160\\\\u0014\\\\u000b_\\\\u00cc\\\\u008f|U\\\\n\\\\u0088/\\\\u00bb\\\\u001a\\\\u0093\\\\u0082\\\\u009f\\\\u00b5\\\\tU\\\\u0095\\\\n0\\\\u00d8E\\\\u00eb\\\\u00b2\\\", \\\"amount\\\": 100, \\\"signature\\\": \\\"\\\\u0014\\\\u00ae\\\\u00e5\\\\u00e6\\\\b.\\\\u0006`\\\\u0083C\\\\u009ap\\\\u008d\\\\u00df\\\\u0090QQ\\\\u00f9\\\\u00d4\\\\u00ae6\\\\u009d\\\\u00a4\\\\u0084<\\\\u009b\\\\u00f7\\\\u00e93\\\\u00f5\\\\u00ca\\\\u00bd\\\\u0016\\\\u00e5v^\\\\u00c6K(Md(\\\\u001b\\\\u00f3\\\\u009a\\\\f\\\\u00c0;\\\\u0013\\\\u00dc\\\\u00d7x\\\\u0002\\\\u0017\\\\u00bb\\\\u0002\\\\u000f\\\\u00ca\\\\u00c6\\\\u00d8\\\\u00f9\\\\u0092\\\\u00f7`\\\\u00be\\\\u0001\\\\u0004\\\\u00bb(\\\\u00f6\\\\u00f8\\\\u00d7c\\\\u00fd\\\\u00ed\\\\u008a\\\\u0092\\\\u0081\\\\u00176\\\\u00c4*\\\\u00d1\\\\u00c3<TH\\\\u00b1\\\\u00b5\\\\u0081\\\\u0011\\\\u0092\\\\u00d1\\\\u00de\\\\u00c6C\\\", \\\"timestamp\\\": 1562912707.5153232}\"}, \"signature\": \"\\u0099O\\u000f\\u00d8\\u0091R\\u00a7\\u008b\\u0014\\u0092\\u0091\\u0081\\u00ce\\u00d11\\u00ec\\\\\\u00aaUU\\u00ce\\u00a5\\u00b8\\u0089\\u0005#\\u00c5\\u00ba\\u0003\\u00d9h\\u00e33\\u00beW\\u009faj\\u00dd\\u00da\\u0006\\u008c9\\u00daBs\\u0007(\\u0017\\u000f\\u00e5s\\u000e\\u00a4\\u009d\\u00e2\\u00c3\\u0085\\u0019\\u00a4f\\u009bR\\u0081?/U\\u00ea\\u00ea\\u00cb\\f\\u00f6\\u00c4Ms\\u00f4\\u00e8%\\u0018\\u00bd\\u00c1R:\\u00b5\\u0080\\u0014\\u00d1N4!\\\\\\u00b8\\u00cf\\u00dc\\u00103\", \"signers\": [\"127.0.0.1:5001\", \"127.0.0.1:5000\", \"127.0.0.1:5003\", \"127.0.0.1:5002\"], \"timestamp\": 1562912731.465246}"))