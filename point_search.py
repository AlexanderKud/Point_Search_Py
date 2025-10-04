from datetime import datetime
import secp256k1
import sys
import time
import math
import multiprocessing as mp

def break_down_to_pow10(num):
    nums = []
    num_len = len(str(num)) - 1
    for pw in reversed(range(num_len)):
        nums.append(pow(10, pw))
    return nums

def addition_search(block_width, pre_calc_sum, search_pub, queue, pow10_nums, pow10_points):
    save_counter = 0
    settingsFile = 'settings1.txt'
    settings = open(settingsFile, 'r')
    starting_point = secp256k1.publickey_to_point(settings.readline().strip())
    stride_sum = int(settings.readline().strip())
    settings.close()
    stride = 2**block_width
    stride_point = secp256k1.scalar_multiplication(stride)
    secp256k1.bloom_load(0, 'bloom1.bf')
    secp256k1.bloom_load(1, 'bloom2.bf')
    while True:
        if secp256k1.bloom_check_bytes(0, starting_point[1:33]):
            print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom1.bf (Even Point) [Lower Range Half]')            
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(0, P[1:33]):
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
                queue.put_nowait(privkey)
                return
            print(f'[{datetime.now().strftime("%H:%M:%S")}] False Positive')
                
            
        if secp256k1.bloom_check_bytes(1, starting_point[1:33]):
            print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom2.bf (Odd Point) [Lower Range Half]')
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(1, P[1:33]):
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
                queue.put_nowait(privkey)
                return
            print(f'[{datetime.now().strftime("%H:%M:%S")}] False Positive')
                
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
            
def subtraction_search(block_width, pre_calc_sum, search_pub, queue, pow10_nums, pow10_points):
    save_counter = 0
    settingsFile = 'settings2.txt'
    settings = open(settingsFile, 'r')
    starting_point = secp256k1.publickey_to_point(settings.readline().strip())
    stride_sum = int(settings.readline().strip())
    settings.close()
    stride = 2**block_width
    stride_point = secp256k1.scalar_multiplication(stride)
    secp256k1.bloom_load(0, 'bloom1.bf')
    secp256k1.bloom_load(1, 'bloom2.bf')
    while True:
        if secp256k1.bloom_check_bytes(0, starting_point[1:33]):
            print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom1.bf (Even Point) [Higher Range Half]')
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(0, P[1:33]):
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
                queue.put_nowait(privkey)
                return
            print(f'[{datetime.now().strftime("%H:%M:%S")}] False Positive')
 
        if secp256k1.bloom_check_bytes(1, starting_point[1:33]):
            print(f'[{datetime.now().strftime("%H:%M:%S")}] BloomFilter Hit bloom2.bf (Odd Point) [Higher Range Half]')
            P = starting_point
            privkey_num = []
            for i,p in enumerate(pow10_points):
                count = 0
                while secp256k1.bloom_check_bytes(1, P[1:33]):
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
                queue.put_nowait(privkey)
                return
            print(f'[{datetime.now().strftime("%H:%M:%S")}] False Positive')

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

def main(block_width, pre_calc_sum, search_pub, queue, start_time):
    
    pow10_nums = break_down_to_pow10(2**block_width)
    pow10_points = []
    for num in pow10_nums:
        pow10_points.append(secp256k1.scalar_multiplication(num))
    
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Search in progress')
        
    p1 = mp.Process(target=addition_search, args=(block_width, pre_calc_sum, search_pub, queue, pow10_nums, pow10_points))
    p2 = mp.Process(target=subtraction_search, args=(block_width, pre_calc_sum, search_pub, queue, pow10_nums, pow10_points))
    p1.start()
    p2.start()
    data = queue.get()
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Privatekey: {data}')
    f = open("found_key.txt", "a")
    f.write(f"{data}\n")
    f.close()
    active = mp.active_children()
    for child in active:
        child.kill()
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f'[{datetime.now().strftime("%H:%M:%S")}] Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')


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
    
    queue = mp.Queue()
    start_time = time.time()
    
    main(block_width, pre_calc_sum, search_pub, queue, start_time)
