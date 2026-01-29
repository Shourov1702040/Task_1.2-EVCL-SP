import random, os, sys, hashlib, math ,pickle, string, time, zlib, base64, time, re, csv
from collections import deque, defaultdict
from typing import List, Tuple, Dict, Any, Union
from blake3 import blake3
import zstandard as zstd


# _____________________________________ Data generation  _____________________________________
def generate_replicas(block_size_KB, num_blocks, num_replicas, save_dir, use_random_data=True):
    os.makedirs(save_dir, exist_ok=True)
    replica_files = []
    block_size = (block_size_KB * 1024)  # KB → bytes

    for r in range(1, num_replicas + 1):
        chunks = []
        for i in range(num_blocks):
            if use_random_data:
                chunk = os.urandom(block_size)
            else:
                pattern = b"Kademlia-64KB-Chunk-Pattern" + os.urandom(16)
                base_chunk = (pattern * (block_size // len(pattern) + 1))[:block_size]
                chunk = base_chunk + str(i).encode()
            chunks.append(chunk)

        file_path = os.path.join(save_dir, f"replica_{r}.txt")
        with open(file_path, "wb") as f:
            # Use pickle to dump list of chunks
            pickle.dump(chunks, f, protocol=0)  # ASCII protocol
        replica_files.append(file_path)
    # return replica_files

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
    loc_key = Loc_key_gen(hashes)
    return current_level, loc_key

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



# _________________________________ Challenge Generation ___________________________________________

def generate_edge_dict(total_clients, total_data, data_scale):
    edge_server_ids = [f"Edge-Server-{i}" for i in range(1, total_clients+1)]

    edge_dict = {}
    for cid in edge_server_ids:
        nums = sorted(random.sample(range(1, total_data+1), data_scale))  # 4 unique numbers from 0..N
        nums = [f"R-{n}" for n in nums] 
        edge_dict[cid] = nums

    return edge_dict

def Generate_Additional_info(global_tree, edge_replicas):
    # Build lookup: id -> node
    id_map = {n[0]: n for n in global_tree}

    # Map replica IDs (R-1, R-2, ...) -> leaf IDs (G-Node-x)
    mapped = {}
    for rid in edge_replicas:
        num = int(re.search(r'(\d+)$', rid).group(1)) - 1
        leaf_id = f"G-Node-{num}"
        if leaf_id in id_map:
            mapped[rid] = leaf_id

    required_leaves = set(mapped.values())

    # Group nodes by level
    level_nodes = defaultdict(list)
    for n in global_tree:
        level_nodes[n[1]].append(n)

    max_level = max(level_nodes.keys())

    # Build child relationships
    children_map = defaultdict(list)
    for n in global_tree:
        lvl, pos = n[1], n[2]
        if lvl < max_level:
            parent_pos = pos // 3
            parent_lvl = lvl + 1
            for parent in level_nodes.get(parent_lvl, []):
                if parent[2] == parent_pos:
                    children_map[parent[0]].append(n[0])
                    break

    # Compute descendant leaves
    descendant_map = {}
    def get_descendants(node_id):
        node = id_map[node_id]
        if node[3]:  # is_leaf
            descendant_map[node_id] = {node_id}
            return {node_id}
        if node_id in descendant_map:
            return descendant_map[node_id]
        desc = set()
        for child in children_map.get(node_id, []):
            desc |= get_descendants(child)
        descendant_map[node_id] = desc
        return desc

    for nid in id_map:
        get_descendants(nid)

    # Find lowest covering parent
    candidates = []
    for nid, node in id_map.items():
        if not node[3]:  # internal only
            if required_leaves.issubset(descendant_map[nid]):
                candidates.append(node)

    if not candidates:
        return None

    covering = min(candidates, key=lambda n: n[1])

    # -------- NEW: find additional required nodes --------
    additional_nodes = set()

    def find_additional(node_id):
        """Check what nodes we must include under this parent."""
        node = id_map[node_id]
        if node[3]:  # leaf
            if node_id not in required_leaves:
                additional_nodes.add(node_id)
            return

        children = children_map.get(node_id, [])
        for child in children:
            child_leaves = descendant_map[child]
            if child_leaves & required_leaves:  
                # Child has required leaves
                if not id_map[child][3]:  # internal
                    find_additional(child)
                elif child not in required_leaves:  # leaf not in required list
                    additional_nodes.add(child)
            else:
                # Child has no required leaves -> include it directly
                additional_nodes.add(child)

    find_additional(covering[0])
    additionals_nodes = sorted(additional_nodes, key=lambda x: int(x.split('-')[-1]))
    proof_root = covering
    
    return proof_root,  additionals_nodes

def generate_challenge(edge_info, Data_replicas):
    replica_ids = [f"R-{i}" for i in range(1, len(Data_replicas)+1)]
    ES_challenges = {}
    ES_proofs = {} 

    # shuffle_key = random.randint(0, 10)
    # sec_code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    shuffle_key = 3
    sec_code = "knRpR3Yvf5Seq2Sz"

    Trees = []
    Roots = []
    G_leafs = []
    G_Tree = []

    block_loc_key = {}

    for i in range(len(Data_replicas)):
        leafs, loc_key = generate_leaf_node(Data_replicas[i], replica_ids[i], shuffle_key, sec_code, False)
        tree = build_OMHT(leafs, replica_ids[i], shuffle_key, sec_code)
        Trees.append(tree)
        block_loc_key[f"R-{i+1}"] = loc_key
        Roots.append(tree[-1])

    G_leafs = resequence_nodes(Roots, "G")
    G_Tree = build_OMHT(G_leafs, "G", shuffle_key, sec_code)
    challenge_all =[]
    proof_all = {}
    loc_key_all = {}

    for e_id, replicas in edge_info.items():
        Specific_List = replicas
        proof_root, additional_nodes_ids = Generate_Additional_info(G_Tree, Specific_List)
        additional_nodes = [n for n in G_Tree if n[0] in additional_nodes_ids]
        loc_keys = {key: block_loc_key[key] for key in Specific_List if key in block_loc_key}

        chal = [e_id, shuffle_key, sec_code, additional_nodes]
        challenge_all.append(chal)

        proof_all[e_id] = proof_root
        loc_key_all[e_id] = loc_keys
    
    return challenge_all, proof_all, loc_key_all


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


# ________________________________ Localization Key Generation ____________________________________

def Loc_key_gen(list_B_added):
    # Use first 8 hex chars from each pre-hashed item
    partial_hashes = [item[:8] for item in list_B_added]
    key = ''.join(partial_hashes)
    raw_bytes = bytes.fromhex(key)
    cctx = zstd.ZstdCompressor(level=22)  # max compression
    compressed = cctx.compress(raw_bytes)
    return base64.b85encode(compressed).decode()
    return key

# _________________________________ Corruption Localization _______________________________________

def Detection_function_from_dicts(dict_A, dict_B):
    dctx = zstd.ZstdDecompressor()
    detected_all = {}

    for replica_id in dict_A:
        key_A = dict_A[replica_id]
        key_B = dict_B.get(replica_id)

        if key_B is None:
            continue  
        if key_A == key_B:
            continue
        decompressed_A = dctx.decompress(base64.b85decode(key_A.encode())).hex()
        decompressed_B = dctx.decompress(base64.b85decode(key_B.encode())).hex()
        chunks_A = [decompressed_A[i*8:(i+1)*8] for i in range(len(decompressed_A)//8)]
        chunks_B = [decompressed_B[i*8:(i+1)*8] for i in range(len(decompressed_B)//8)]

        corrupted_indices = []

        def detect_range(start, end):
            if start > end:
                return
            if chunks_A[start:end+1] == chunks_B[start:end+1]:
                return
            if start == end:
                corrupted_indices.append(start)
                return
            mid = (start + end) // 2
            detect_range(start, mid)
            detect_range(mid+1, end)

        detect_range(0, len(chunks_A)-1)
        detected_all[replica_id] = corrupted_indices

    return detected_all


def Detection_fucntion(list_A, key):
    compressed = base64.b85decode(key.encode())
    dctx = zstd.ZstdDecompressor()
    decompressed = dctx.decompress(compressed)
    key_2 = decompressed.hex()

    detected = []
    for i, item in enumerate(list_A):
        expected_hash = key_2[i*8:(i+1)*8]
        if item[:8] != expected_hash:
            detected.append(i)
    return detected