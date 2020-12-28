from Crypto.Cipher import AES

BLOCK_SIZE = 16


# Custom decryption of CBC using ECB decryption.
def cbc_custom_decrypt(k, n, cipher):
    IV = cipher[:BLOCK_SIZE]
    blocks = cipher[BLOCK_SIZE:]
    plain_text = bytearray(0)
    for i in range(n):
        obj = AES.new(k, AES.MODE_ECB)
        # base case: xor the IV with the next decrypted block.
        if i == 0:
            plain_text += xor_bytes(IV, obj.decrypt(blocks[:BLOCK_SIZE]))
        # general case: xor the previous cipher block with the current decrypted block.
        else:
            plain_text += xor_bytes(blocks[BLOCK_SIZE * (i - 1):BLOCK_SIZE * i],
                                    obj.decrypt(blocks[BLOCK_SIZE * i:BLOCK_SIZE * (i + 1)]))

    return bytes(plain_text[:BLOCK_SIZE * n])


# Fix the cipher block where the bit was flipped, return the original block.
def cbc_flip_fix(k, n, cipher):
    IV = cipher[:BLOCK_SIZE]
    cipher_blocks = bytearray(cipher[BLOCK_SIZE:])
    decrypted = cbc_custom_decrypt(k, n, cipher)
    # find the block where the bit was flipped.
    block_idx = find_corrupted_block(decrypted)
    # find the byte where the bit was flipped, and it's bitmask.
    i, mask = find_corrupted_byte(decrypted[BLOCK_SIZE * (block_idx + 1):BLOCK_SIZE * (block_idx + 2)])
    byte_idx = BLOCK_SIZE * block_idx + i
    # flip back the bit using the mask.
    cipher_blocks[byte_idx:byte_idx + 1] = xor_bytes(cipher_blocks[byte_idx:byte_idx + 1], mask)
    # decrypt the cipher again and return the fixed block.
    decrypted_fixed = cbc_custom_decrypt(k, n, IV + cipher_blocks)
    return decrypted_fixed[BLOCK_SIZE * block_idx:BLOCK_SIZE * (block_idx + 1)]


# Find the index of the block that was corrupted after the decryption.
def find_corrupted_block(blocks):
    for i in range(len(blocks)):
        if i != len(blocks) - 1 and blocks[i] != blocks[i + 1] and (i + 1) % BLOCK_SIZE != 0:
            return int(i / BLOCK_SIZE)


# Find the byte where the bit was flipped inside the block, return it's index and a bitmask of the flipped bit.
def find_corrupted_byte(block):
    unchanged_byte = find_frequent_byte(block)
    for i in range(len(block)):
        if block[i:i + 1] != unchanged_byte:
            mask = xor_bytes(unchanged_byte, block[i:i + 1])
            return i, mask


# Find the most frequent byte inside a block.
def find_frequent_byte(block):
    bytes_dict = {}
    for i in range(len(block)):
        byte = block[i:i + 1].hex()
        if byte in bytes_dict:
            bytes_dict[byte] += 1
        else:
            bytes_dict[byte] = 1
    frequent_byte = [max(bytes_dict, key=bytes_dict.get)][0]
    return bytes.fromhex(frequent_byte)


# XOR two bytes by their elements.
def xor_bytes(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])