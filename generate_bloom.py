import secp256k1
from datetime import datetime
import time
import os
import sys
import multiprocessing as mp

def bloom_create1(block_width, puzzle_point):
    G = secp256k1.scalar_multiplication(1)
    _elem = int(1.4 * (2**block_width))
    _fp = 0.000001
    secp256k1.init_bloom(0, _elem, _fp)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Creating bloomfile1')
    P = puzzle_point
    for i in range(2**block_width):
        secp256k1.bloom_add_bytes(0, P)
        P = secp256k1.add_points(P, G)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Writing Bloomfilter to bloom1.bf')
    secp256k1.bloom_save(0, 'bloom1.bf')

def bloom_create2(block_width, puzzle_point_05):
    G = secp256k1.scalar_multiplication(1)
    _elem = int(1.4 * (2**block_width))
    _fp = 0.000001
    secp256k1.init_bloom(1, _elem, _fp)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Creating bloomfile2')
    P = puzzle_point_05
    for i in range(2**block_width):
        secp256k1.bloom_add_bytes(1, P)
        P = secp256k1.add_points(P, G)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Writing Bloomfilter to bloom2.bf')
    secp256k1.bloom_save(1, 'bloom2.bf')    

def main(block_width, puzzle_point, puzzle_point_05, start_time):
    p1 = mp.Process(target=bloom_create1, args=(block_width, puzzle_point))
    p2 = mp.Process(target=bloom_create2, args=(block_width, puzzle_point_05))
    p1.start()
    p2.start()
    p1.join()
    p2.join()
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')
    

#==============================================================================
if __name__ == '__main__':

    try:
        os.remove("settings1.txt")
        os.remove("settings2.txt")
        os.remove("bloom1.bf")
        os.remove("bloom2.bf")
    except OSError:
        pass
    
    P_table = []
    pk = 1
    for i in range(256):
        P_table.append(secp256k1.scalar_multiplication(pk))
        pk *= 2
    print(f"[{datetime.now().strftime("%H:%M:%S")}] P_table generated")
    
    settingsFile = 'settings.txt'
    settings = open(settingsFile, 'r')
    start_range = int(settings.readline().strip())
    end_range   = int(settings.readline().strip())
    block_width = int(settings.readline().strip())
    search_pub = settings.readline().strip()
    settings.close()

    print(f"[{datetime.now().strftime("%H:%M:%S")}] Range start: {start_range} bits")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Range end  : {end_range} bits")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Block width: 2^{block_width}")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Search pub : {search_pub}")
            
    start_point = P_table[start_range]
    end_point   = P_table[end_range]
    point_05 = secp256k1.scalar_multiplication(57896044618658097711785492504343953926418782139537452191302581570759080747169)
    
    puzzle_point = secp256k1.publickey_to_point(search_pub)
    puzzle_point_05 = secp256k1.add_points(puzzle_point, point_05)
    puzzle_point_divide2 = secp256k1.point_multiplication(puzzle_point, 57896044618658097711785492504343953926418782139537452191302581570759080747169)
    
    first_point  = P_table[start_range - 1]
    second_point = P_table[start_range - 2]
    
    P1 = secp256k1.subtract_points(puzzle_point_divide2, first_point)
    P2 = secp256k1.subtract_points(puzzle_point_divide2, second_point)
    Q1 = secp256k1.add_points(P1, P2)
    Q2 = secp256k1.add_points(puzzle_point_divide2, Q1)
    
    f1 = open('settings1.txt', "w")
    f1.write(f"{secp256k1.point_to_cpub(Q2)}\n")
    f1.write(f"0\n")
    f1.close()
    f2 = open('settings2.txt', "w")
    f2.write(f"{secp256k1.point_to_cpub(Q2)}\n")
    f2.write(f"0\n")
    f2.close()
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Settings written to file")
    
    start_time = time.time()
    
    main(block_width, puzzle_point, puzzle_point_05, start_time)
