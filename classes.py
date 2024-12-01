import uuid

class Client:
    def __init__(self, cid, name, public_key, last_seen, aes):
        self.cid = cid
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes = aes

class File:
    def __init__(self, cid, file_name, path_name, verified):
        self.cid = cid
        self.file_name = file_name
        self.path_name = path_name
        self.verified = verified