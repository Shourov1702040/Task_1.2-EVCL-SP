import random, os, sys, hashlib, math ,pickle, string, time, zlib, base64, time, re, csv, fe_reconstruct
from collections import deque, defaultdict
from typing import List, Tuple, Dict, Any, Union
from blake3 import blake3
import zstandard as zstd


# _________________________________________ Data Load  __________________________________________
def load_replicas_from_dir(save_dir, block_size_KB):
    block_size = block_size_KB * 1024# KB → bytes
    replicas_lst = []
    dir_lst = list(os.listdir(save_dir))
    dir_lst.sort(key=lambda x: int(x.split('_')[1].split('.')[0]))
    for file_name in dir_lst:
        if file_name.endswith(".txt"):
            file_path = os.path.join(save_dir, file_name)

            with open(file_path, "rb") as f:
                chunks = pickle.load(f)  
            replica_data = bytearray().join(chunks)

            blocks = [replica_data[i:i+block_size] for i in range(0, len(replica_data), block_size)]

            replicas_lst.append(blocks)
    return replicas_lst

def load_replicas_from_dir_ES(save_dir, Replica_ids, block_size_KB):
    block_size = block_size_KB * 1024  # MB → bytes
    F_LIST = []
    for replica_id in Replica_ids:
        file_number = replica_id.split('-')[1]
        file_name = f'replica_{file_number}.txt'
        F_LIST.append(file_name)

    replicas_lst = []
    for file_name in F_LIST: # 💡 This line is changed
        file_path = os.path.join(save_dir, file_name)
        try:
            if os.path.exists(file_path) and file_name.endswith(".txt"):
                with open(file_path, "rb") as f:
                    chunks = pickle.load(f)
                replica_data = bytearray().join(chunks)

                blocks = [replica_data[i:i+block_size] for i in range(0, len(replica_data), block_size)]

                replicas_lst.append(blocks)
        except (IndexError, ValueError):
            print(f"Warning: Invalid replica ID format '{replica_id}'. Skipping.")

    return replicas_lst


# def Modify_data(Data_replicas, Replica_no, b_no):
#     r_no = int(Replica_no.split('-')[1])

#     d_block = Data_replicas[r_no][b_no]
#     d_block[90:92] = b"#!!"

#     Data_replicas[r_no][b_no] = d_block

#     return Data_replicas


def index_alloc(loc_index,  T_es, Total_data, N_r):
    with open(loc_index, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header row
        header = [f'Edge-Server-{i+1}' for i in range(T_es)]
        writer.writerow(header)
        
        # Generate unique R values for each column and sort them
        all_r_values = [f'R-{i+1}' for i in range(Total_data)]
        
        # For each column, assign unique R values and sort them
        columns_data = []
        for i in range(Total_data):
            # Shuffle and take first N_r values for this column, then sort
            shuffled = all_r_values.copy()
            random.shuffle(shuffled)
            column_values = shuffled[:N_r]
            # Sort by the number after "R-"
            column_values.sort(key=lambda x: int(x.split('-')[1]))
            columns_data.append(column_values)
        
        # Write rows by transposing the columns data
        for row_idx in range(N_r):
            row = [columns_data[col_idx][row_idx] for col_idx in range(Total_data)]
            writer.writerow(row)

def csv_to_edge_info(csv_filename, e_id = ''):
    edge_info = {}
    
    with open(csv_filename, 'r') as f:
        reader = csv.reader(f)
        
        # Read header row to get column names (Edge-Servers)
        headers = next(reader)
        
        # Initialize empty lists for each Edge-Server
        for header in headers:
            edge_info[header] = []
        
        # Read data rows and populate the lists
        for row in reader:
            for i, r_value in enumerate(row):
                edge_info[headers[i]].append(r_value)
    if e_id:
        return edge_info[e_id]
    else:
        return edge_info


def Modify_data_block_hash(hash_val):
    chars = list(hash_val)
    n = len(chars)
    for i in range(n-1, 0, -1):
        j = random.randint(0, i)
        chars[i], chars[j] = chars[j], chars[i]
    return ''.join(chars)

# ________________________________________ Hashing Data __________________________________________
def deterministic_shuffle(lst, shuffle_key: int):
    def shuffle_score(item):
        combined = f"{str(item)}_{shuffle_key}".encode()
        return hashlib.sha256(combined).hexdigest()
    
    return sorted(lst, key=shuffle_score)

def hash_data_SHA_3(data, sec_code):
    """Hashes data using SHA3-256 with security code concatenation."""
    if isinstance(data, str):
        data = data.encode()
    # Convert sec_code to bytes if it isn't already
    if isinstance(sec_code, str):
        sec_code = sec_code.encode()
    data_with_code = data + sec_code
    return hashlib.sha3_256(data_with_code).hexdigest()

def string_SHA_3(data):
    if isinstance(data, str):
        data = data.encode()

    return hashlib.sha3_256(data).hexdigest()

def hash_data_black_3(data, sec_code):
    """Hashes data using BLAKE3 with security code concatenation."""
    if isinstance(data, str):
        data = data.encode()
    # Convert sec_code to bytes if it isn't already
    if isinstance(sec_code, str):
        sec_code = sec_code.encode()
    data_with_code = data + sec_code
    return blake3(data_with_code).hexdigest()

# ______________________________ Building MHT _____________________________________________
def generate_leaf_node(replica, replica_id, shuffle_key, sec_code, modify=True):
    data_list = deterministic_shuffle(replica, shuffle_key)
    node_counter = 0
    hashes = []
    current_level = []
    for i, item in enumerate(data_list):
        hash_i = hash_data_SHA_3(str(item), sec_code)
        if modify==True and i==1:
            hash_i = Modify_data_block_hash(hash_i)
        node = [f"{replica_id}-Node-{node_counter}", 0, i, True, hash_i]
        current_level.append(node)   # keep references so we can update in place on promotion
        hashes.append(hash_i)
        node_counter += 1
    # loc_key = Loc_key_gen(hashes)
    # hashes_raw = Loc_key_gen(hashes)
    return current_level, hashes

def resequence_nodes(data, prefix):
    resequenced = []
    for i, row in enumerate(data):
        new_row = [
            f"{prefix}-Node-{i}",  # new node id
            0,                # reset ln to 0
            i,                # reset pn to sequence number
            True,             # keep is_leaf value
            row[4]            # keep hash value
        ]
        resequenced.append(new_row)
    return resequenced

def resequence_nodes_ES(data, R_ids):
    resequenced = []
    for i, row in enumerate(data):
        new_row = [
            f"{prefix}-Node-{i}",  # new node id
            0,                # reset ln to 0
            i,                # reset pn to sequence number
            True,             # keep is_leaf value
            row[4]            # keep hash value
        ]
        resequenced.append(new_row)
    return resequenced

def build_OMHT(leaf_nodes, replica_id, shuffle_key, sec_code):
    nodes = leaf_nodes[:]        # copy list
    node_counter = len(leaf_nodes)   # next ID starts after the last leaf
    current_level = leaf_nodes
    ln = 1

    # Build upper levels
    while len(current_level) > 1:
        next_level = []
        pos = 0
        i = 0
        while i < len(current_level):
            group = current_level[i:i+3]

            if len(group) == 3 or len(group) == 2:
                # merge 2 or 3
                merged_hash = hash_data_black_3("".join(str(n[4]) for n in group), sec_code)
                new_node = [f"{replica_id}-Node-{node_counter}", ln, pos, False, merged_hash]
                nodes.append(new_node)
                next_level.append(new_node)
                node_counter += 1

            elif len(group) == 1:
                # Rule 4: promote single node (update only ln, pn)
                promoted = group[0]
                promoted[1] = ln  # ln
                promoted[2] = pos # pn
                # do NOT change is_leaf or h_ln_pn
                next_level.append(promoted)

            pos += 1
            i += 3

        current_level = next_level
        ln += 1

    # sort nodes by level and position
    return sorted(nodes, key=lambda n: (n[1], n[2]))






#_______________________________________ Proof generation _____________________________________________

def transform_list(data):
    result = []
    i = 0
    for row in data:
        r_num = int(row[0].split('-')[1]) 
        g_num = r_num - 1  
        new_row = [f'G-Node-{g_num}', 0, g_num, True, row[4]]
        result.append(new_row)
        i+=1
    return result

def _next_unique_id(existing_ids: set, base_name="Node") -> str:
    n = 1
    while f"{base_name}-{n}" in existing_ids:
        n += 1
    new_id = f"{base_name}-{n}"
    existing_ids.add(new_id)
    return new_id

def build_minimal_tree(G_leafs: List[List], A_info: List[List], sec_code: str) -> List[List]:

    nodes = [list(n) for n in (A_info or [])] 
    leaves = [list(n) for n in (G_leafs or [])]

    node_map = {}
    existing_ids = set()

    for n in nodes:
        node_map[(n[1], n[2])] = n
        existing_ids.add(n[0])
    for lf in leaves:
        
        if (lf[1], lf[2]) not in node_map:
            node_map[(lf[1], lf[2])] = lf
            existing_ids.add(lf[0])
        else:
            pass

    current_ln = 0
    if node_map:
        current_ln = min(ln for (ln, pn) in node_map.keys())

    while True:
        current_nodes = [node_map[(ln, pn)] for (ln, pn) in sorted(node_map.keys()) if ln == current_ln]
        if not current_nodes:
            higher_lns = sorted({ln for (ln, pn) in node_map.keys() if ln > current_ln})
            if not higher_lns:
                break
            current_ln = higher_lns[0]
            continue
        if len(current_nodes) == 1:
            break
        i = 0
        created_any_parent = False
        while i < len(current_nodes):
            group = current_nodes[i:i+3]
            group_size = len(group)
            first_child_pn = group[0][2]
            parent_ln = current_ln + 1
            parent_pn = first_child_pn // 3  

            if (parent_ln, parent_pn) in node_map:
                parent_node = node_map[(parent_ln, parent_pn)]
                i += group_size
                continue

            if group_size >= 2:
                concat_children_hashes = "".join(str(ch[4]) for ch in group)
                merged_hash = hash_data_black_3(concat_children_hashes, sec_code)
                new_id = _next_unique_id(existing_ids, base_name="Node")
                parent_node = [new_id, parent_ln, parent_pn, False, merged_hash]
                node_map[(parent_ln, parent_pn)] = parent_node
                created_any_parent = True
                i += group_size

            else:
                child = group[0]
                old_coords = (child[1], child[2])
                child[1] = parent_ln
                child[2] = parent_pn

                node_map.pop(old_coords, None)
                node_map[(parent_ln, parent_pn)] = child
                created_any_parent = True
                i += 1
        current_ln += 1
        if not created_any_parent:
            break
    final_nodes = list(node_map.values())
    final_nodes_sorted = sorted(final_nodes, key=lambda x: (x[1], x[2]))
    root = max(final_nodes_sorted, key=lambda n: n[1]) 
    return root

def PUF_derived_Replica_root(root, K_ES_HW):
    root_update = root
    root_update_value= string_SHA_3(root[-1]+K_ES_HW)
    root_update[-1] = root_update_value 

    return root_update

# ________________________________ Localization Key Generation ____________________________________

def Loc_key_gen(block_hashes, K_ES_HW, Replica_id):

    new_digest = []
    for old_h in block_hashes:
        new_d = string_SHA_3(old_h+K_ES_HW)
        new_digest.append(new_d)

    partial_hashes = [item[:8] for item in new_digest]
    Replica_id_hex = Replica_id.encode().hex().ljust(12, '0')

    block_binding = []

    for decimal_num in range(len(partial_hashes)):
        block_id = f"{decimal_num:03x}"
        block_b = Replica_id_hex + block_id + partial_hashes[decimal_num]

        block_binding.append(block_b)


    key = ''.join(block_binding)
    raw_bytes = bytes.fromhex(key)
    cctx = zstd.ZstdCompressor(level=22)  # max compression
    compressed = cctx.compress(raw_bytes)
    return base64.b85encode(compressed).decode()
    return key
