# requires python3.13t(NoGIL)
# python3.13t -Xgil=0 point_search_threading.py
from datetime import datetime
import secp256k1
import sys
import time
import math
import multiprocessing as mp
import threading as th
import os

def break_down_to_pow10(num):
    nums = []
    num_len = len(str(num)) - 1
    for pw in reversed(range(num_len)):
        nums.append(pow(10, pw))
    return nums

def addition_search():
    save_counter = 0
    settingsFile = 'settings1.txt'
    settings = open(settingsFile, 'r')
    starting_point = secp256k1.publickey_to_point(settings.readline().strip())
    stride_sum = int(settings.readline().strip())
    settings.close()
    stride = 2**block_width
    stride_point = secp256k1.scalar_multiplication(stride)
    while True:
        if secp256k1.bloom_check_bytes(0, starting_point):
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(0, P):
                    P = secp256k1.subtract_points(P, p)
                    count += 1
                privkey_num.append(pow10_nums[i] * (count - 1))
                P = secp256k1.add_points(P, p)
            steps = 0
            for i in privkey_num:
                steps += i
            privkey = pre_calc_sum - (stride_sum - steps)
            privkey *= 2
            if secp256k1.point_to_cpub(secp256k1.scalar_multiplication(privkey)) == search_pub:
                print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom1.bf (Even Point) [Lower Range Half]')
                queue.put_nowait(privkey)
                return
            
        if secp256k1.bloom_check_bytes(1, starting_point):
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(1, P):
                    P = secp256k1.subtract_points(P, p)
                    count += 1
                privkey_num.append(pow10_nums[i] * (count - 1))
                P = secp256k1.add_points(P, p)                
            steps = 0
            for i in privkey_num:
                steps += i
            privkey = pre_calc_sum - (stride_sum - steps)
            privkey = (privkey * 2) + 1            
            if secp256k1.point_to_cpub(secp256k1.scalar_multiplication(privkey)) == search_pub:
                print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom2.bf (Odd Point) [Lower Range Half]')
                queue.put_nowait(privkey)
                return
                
        starting_point = secp256k1.add_points(starting_point, stride_point)
        stride_sum += stride
        save_counter += 1

        if save_counter % 18000000 == 0:
            cpub = secp256k1.point_to_cpub(starting_point)
            f = open(settingsFile, "w")
            f.write(f"{cpub}\n")
            f.write(f"{stride_sum}\n")
            f.close()
            save_counter = 0
            print(f'[{datetime.now().strftime("%H:%M:%S")}] Save Data written to {settingsFile}')
            
def subtraction_search():
    save_counter = 0
    settingsFile = 'settings2.txt'
    settings = open(settingsFile, 'r')
    starting_point = secp256k1.publickey_to_point(settings.readline().strip())
    stride_sum = int(settings.readline().strip())
    settings.close()
    stride = 2**block_width
    stride_point = secp256k1.scalar_multiplication(stride)
    while True:
        if secp256k1.bloom_check_bytes(0, starting_point):
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(0, P):
                    P = secp256k1.subtract_points(P, p)
                    count += 1
                privkey_num.append(pow10_nums[i] * (count - 1))
                P = secp256k1.add_points(P, p)
            steps = 0
            for i in privkey_num:
                steps += i
            privkey = pre_calc_sum + (stride_sum + steps)
            privkey *= 2
            if secp256k1.point_to_cpub(secp256k1.scalar_multiplication(privkey)) == search_pub:
                print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom1.bf (Even Point) [Higher Range Half]')
                queue.put_nowait(privkey)
                return
 
        if secp256k1.bloom_check_bytes(1, starting_point):
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(1, P):
                    P = secp256k1.subtract_points(P, p)
                    count += 1
                privkey_num.append(pow10_nums[i] * (count - 1))
                P = secp256k1.add_points(P, p)
            steps = 0
            for i in privkey_num:
                steps += i
            privkey = pre_calc_sum + (stride_sum + steps)
            privkey = (privkey * 2) + 1
            if secp256k1.point_to_cpub(secp256k1.scalar_multiplication(privkey)) == search_pub:
                print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom2.bf (Odd Point) [Higher Range Half]')
                queue.put_nowait(privkey)
                return

        starting_point = secp256k1.subtract_points(starting_point, stride_point)
        stride_sum += stride
        save_counter += 1
        
        if save_counter % 18000000 == 0:
            cpub = secp256k1.point_to_cpub(starting_point)
            f = open(settingsFile, "w")
            f.write(f"{cpub}\n")
            f.write(f"{stride_sum}\n")
            f.close()
            save_counter = 0
            print(f'[{datetime.now().strftime("%H:%M:%S")}] Save Data written to {settingsFile}')

def run_threads():
    
    t1 = th.Thread(target=addition_search, args=())
    t2 = th.Thread(target=subtraction_search, args=())
    t1.start()
    t2.start()
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Bloomfilters loaded')
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Search in progress...')
    data = queue.get()
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Privatekey: {data}')
    f = open("found_key.txt", "a")
    f.write(f"{data}\n")
    f.close()
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')
    os._exit(0)

#============================================================================== 
if __name__ == '__main__':
    
    P_table = []
    pk = 1;
    for i in range(256):
        P_table.append(secp256k1.scalar_multiplication(pk))
        pk *= 2
                
    S_table = []
    pk = 1
    for k in range(256): 
        S_table.append(pk) 
        pk *= 2
            
    print(f"[{datetime.now().strftime("%H:%M:%S")}] S_table and P_table generated")
    
    settingsFile = 'settings.txt'
    settings = open(settingsFile, 'r')
    start_range = int(settings.readline().strip())
    end_range   = int(settings.readline().strip())
    block_width = int(settings.readline().strip())
    search_pub = settings.readline().strip()
    settings.close()
    
    first_scalar  = S_table[start_range - 1]
    second_scalar = S_table[start_range - 2]
    pre_calc_sum = first_scalar + second_scalar
    
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Range start: {start_range} bits")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Range end  : {end_range} bits")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Block width: 2^{block_width}")
    print(f"[{datetime.now().strftime("%H:%M:%S")}] Search pub : {search_pub}")
    
    pow10_nums = break_down_to_pow10(2**block_width)
    pow10_points = []
    for num in pow10_nums:
        pow10_points.append(secp256k1.scalar_multiplication(num))
    
    queue = mp.Queue()
    start_time = time.time()
    
    secp256k1.bloom_load(0, 'bloom1.bf')
    secp256k1.bloom_load(1, 'bloom2.bf')
    
    run_threads()
