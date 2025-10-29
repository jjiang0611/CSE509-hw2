
from multiprocessing import Pipe, Process
from random import randint, getrandbits 
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes

# lengh of public key (bytes)
key_length = 1000
# length of item (bits)
item_bit_length = 5
# length of mask (lambda)
mask_bit_length = 6
# number of items
num_item = 8

##########################################################################################

# Alice's process
def Alice(end_a): 
  
    # set held by Alice
    item_set = [28, 15, 7, 3, 23, 20, 31, 19]

    # intersection of Bob's and Alice's sets
    intersection = set()

    # iterate over each item of Alice's
    for item in item_set:
        
        # iterate over each item of Bob's
        for i in range(num_item):
            
            # check whether x is in Bob's set using private equality test
            for j in range(item_bit_length):
                
                ### Todo:
                # (1) get the j-th bit of item using the operator '>>'
                jth = (item >> (item_bit_length - j - 1)) & 1
                # (2) generate a pair of keys (using the parameter 'key_length')
                k_pair = ElGamal.generate(key_length, randfunc = lambda x: get_random_bytes(x))
                pubkey = k_pair.publickey()
                # (3) generate a plausible random public key using 'getrandbits'
                rand_pkey = randint(1, pubkey.p-1)
                rand_pubkey_val = pow(pubkey.g, rand_pkey, pubkey.p)
                rand_pubkey = ElGamal.PublicKey(rand_pubkey_val, pubkey.g, pubkey.p)
                # (4) construct a message sent to Bob
                msg= (i, j, jth, (pubkey, rand_pubkey))
                # send message to Bob
                end_a.send(msg)

                # receive a message from Bob
                msg = end_a.recv()

                ### Todo:
                # (5) decrypt the ciphertext corresponding to the current bit
                if jth == 0:
                    cipher = msg[0]
                else:
                    cipher = msg[1]
                decrypted_mask = k_pair.decrypt(cipher_data)
                # (6) update Alice's overall mask by bitwise XOR ('^=')
                if j == 0:
                    overall_mask = decrypted_mask
                else:
                    overall_mask ^= decrypted_mask


                if j == item_bit_length-1:
                    msg = end_a.recv()
                    ### Todo: 
                    # (7) if it's the last bit, check if Alice's and Bob's overall masks agree
                    # add the item to the intersection if yes
                    if overall_mask == msg:
                        intersection.add(item)
                    
    # indicate that the protocol is over 
    end_a.send('done!')
    print('Alice and Bob\'s intersection is:', intersection)


##########################################################################################


# Bob's process
def Bob(end_b):

    # set of items held by Bob
    item_set = [14, 23, 2, 24, 7, 5, 17, 20]
    
    while True:
          
        # receive Alice's request
        msg = end_b.recv()

        # receive the signal that the protocol is over
        if msg == 'done!':
            break
          
        ### Todo:
        # (1) retrieve fields from the message
        index, j, jth, (pubkey1, pubkey2) = msg
        item = item_set[index]
        # (2) identify the index of the item and the bit of the item Alice is checking against
        #     Note: both should be included in the message
        item_bit = (item >> (item_bit_length - j - 1)) & 1
        
        # (3) reset bob's overall mask if Alice is checking a new item (the first bit)
        if j == 0:
            overall_mask = 0
        # (4) generate two masks for this bit (using 'getrandbits' and 'mask_bit_length' above)
        mask0 = getrandbits(mask_bit_length)
        mask1 = getrandbits(mask_bit_length)
        # (5) update Bob's overall mask by bitwise XOR ('^=')  
        if item_bit == 0:
            overall_mask ^= mask0
        else:
            overall_mask ^= mask1
        # (6) encrypt the two masks using the public keys received from Alice
        #     Note: you need to construct two ElGamal objects, as you receive two sets of public keys
        elgamal1 = Elgamal()
        elgamal1.set_publickey(pubkey1)
        cipher0 = pubkey1.encrypt(mask0, getrandbits(key_length))[0]
        elgamal2 = Elgamal()
        elgamal2.set_publickey(pubkey2)
        cipher1 = elgamal2.encrypt(mask1, getrandbits(key_length))[0]
        # (7) construct a message that consists of the encrypted masks
        msg = (cipher0, cipher1)
        # send the message back to Alice    
        end_b.send(msg)
            
        # send Bob's overall mask if it is the last bit      
        if j == item_bit_length - 1:
            ### Todo:
            # (8) if it's the last bit, construct a message that consists of Bob's overall mask
            msg = overall_mask
            end_b.send(msg)
          
##########################################################################################

if __name__ == "__main__":

    end_a, end_b = Pipe()
    
    # start Alice's process
    alice_p = Process(target=Alice, args=(end_a,))
    alice_p.start()

    # start Bob's process
    Bob(end_b)

    # wait for Alice's process to end
    alice_p.join()
