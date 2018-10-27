from datetime import date
import hashlib
from Crypto.PublicKey import RSA

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

def main():
        Access()

class Block:
    index = 0
    data = ""
    timestamp = ""
    previousHash = "0"
    currentHash = ""

    def __init__(self, previousHash: str, data: str) -> str:
        self.data = data

        self.previousHash = previousHash
        self.timestamp = date.today()
        print(self.timestamp)
        self.currentHash = self.getHash(data, previousHash)

    def getHash(self, data, previousHash):
        newStr = data + " " + previousHash
        return encrypt_string(newStr)

    def printBlock(self):
        print("Block " + str(
            self.index) + "{\n" + "data:" + self.data + "\nprevious hash:" + self.previousHash + "\ncurrent hash:" + self.currentHash)





class Access:
    print("Welcome\n1-Add Patient:\n2-Create PKs")
    print("your choice is:", end=" ")
    choice = input()
    print("Choice" + choice)

    if choice == "1":
        name = ""
        blockchain = list()
        print("Enter patient name:", end=" ")
        name = input()
        genesisBlock = Block("00000", name)

        blockchain.append(genesisBlock)
        for x in range(len(blockchain)):
            print(blockchain[x].printBlock())
        prevH = genesisBlock.currentHash
        while int(choice) == int('1'):
        print("Enter patient name:", end=" ")
        name = input()
        newBlock = Block(prevH, name)

        prevH = newBlock.currentHash
        blockchain.append(newBlock)
        for x in range(len(blockchain)):
            blockchain[x].index = x
            print(blockchain[x].printBlock())
    else:
        # Generate a public/ private key pair using 4096 bits key length (512 bytes)
        new_key = RSA.generate(4096, e=65537)

        # The private key in PEM format
        private_key = new_key.exportKey("PEM")

        # The public key in PEM Format
        public_key = new_key.publickey().exportKey("PEM")

        print(private_key)
        fd = open("private_key.pem", "wb")
        fd.write(private_key)
        fd.close()

        print(public_key)

        fd = open("public_key.pem", "wb")
        fd.write(public_key)
        fd.close()



if __name__=="__main__":main()




