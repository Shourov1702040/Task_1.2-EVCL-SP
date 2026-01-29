import socket, threading, sys, pickle, random, string, time, os
import Functionalities

connected_clients = {}
connected_clients_lock = threading.Lock()
running = True

i_Iter = 1

#_________________________Operations of EDI operations_____________________________#

block_size = 512  # in KB
replica_scale = 8     
Total_data = 10    # In CS
data_scale = 5     # In ES
sample_scale = 32

total_clients = 10

csv_filename = "C:/My Drive/PHD Works/Task 1/Experiments RM-1/E2VL/edge_data.csv"
Functionalities.index_alloc(csv_filename, total_clients, Total_data, data_scale)
edge_info = Functionalities.csv_to_edge_info(csv_filename)

data_loc = "C:/My Drive/PHD Works/Task 1/Experiments RM-1/replicas"
Functionalities.generate_replicas(block_size, replica_scale, Total_data, data_loc, use_random_data=True)

time_all = []

challenge_all_per_edge = {}
Data_replicas = Functionalities.load_replicas_from_dir(data_loc, block_size)

challenges, proof_all, loc_key_all = [], {}, {}

#_____________________ Internal Functions of Cloud server __________________________#

def generate_messages_for_edges():
    """Create a specific list message for each edge server"""
    global challenges, proof_all, loc_key_all
    start_time_GC = time.time()
    challenges, proof_all, loc_key_all = Functionalities.generate_challenge(edge_info, Data_replicas)
    time_all.append(time.time() - start_time_GC)

    for i in range(len([*edge_info])):
        client_id = [*edge_info][i]
        nonce = ''.join(random.choices('0123456789abcdef', k=16))
        ra = random.randint(1, 10)
        cha = challenges[i]
        challenge_all_per_edge[client_id] = cha

def send_message_to_client(target_client_id, message_list):
    """Send a pickled list to a client"""
    with connected_clients_lock:
        if target_client_id in connected_clients:
            client_info = connected_clients[target_client_id]
            try:
                serialized_msg = pickle.dumps(message_list)
                client_info['socket'].sendall(serialized_msg)
            except Exception as e:
                print(f"Error sending to [{target_client_id}]: {e}")
                remove_client(target_client_id)
        else:
            print(f"Client '{target_client_id}' not connected.")

def remove_client(client_id_to_remove):
    with connected_clients_lock:
        if client_id_to_remove in connected_clients:
            try:
                connected_clients[client_id_to_remove]['socket'].close()
            except Exception:
                pass
            del connected_clients[client_id_to_remove]
            print(f"[{client_id_to_remove}] removed.")

def handle_edge_server(edge_server_socket, edge_server_address):
    current_client_id = f"Unknown Client ({edge_server_address[1]})"
    try:
        data = edge_server_socket.recv(1024)
        if not data:
            return

        initial_message_from_client = data.decode()
        if ':' in initial_message_from_client:
            parts = initial_message_from_client.split(':', 1)
            current_client_id = parts[0].strip()

        with connected_clients_lock:
            connected_clients[current_client_id] = {
                'socket': edge_server_socket,
                'address': edge_server_address
            }

        while True:
            data = edge_server_socket.recv(4096)
            if not data:
                break
            try:
                start_time_Verification = time.time()
                Response_edge = pickle.loads(data)

                E_id = Response_edge[0]
                proof_root_node = Response_edge[1]
                Loc_key_ES = Response_edge[2]
                Original_proof_root_node = proof_all[E_id]
                Original_Loc_key_ES = loc_key_all[E_id]

                if Original_proof_root_node[4] == proof_root_node[4]:
                    print(f"{E_id}'s data is integral")
                else:
                    print(f"{E_id}'s data is not integral")
                    loc_result = Functionalities.Detection_function_from_dicts(
                        Original_Loc_key_ES, Loc_key_ES
                    )
                    print(f"Corrupted data replica and block: {loc_result}")
                time_all.append(time.time() - start_time_Verification)
                print(f"Time of Challenge generation, message send and verification: {time_all}\n")
            except Exception as e:
                print(f"Error decoding client message from {current_client_id}: {e}")
                continue

    except Exception as e:
        print(f"Error with {current_client_id}: {e}")
    finally:
        remove_client(current_client_id)

#_____________________ Auto execution for n_iter times __________________________#

iteration_counter = 0
auto_running = False
n_iter = 10  # << Set total number of iterations you want
interval_sec = 4

def box_animation(duration=2.5, delay=0.0225):
    """Moving black box animation through 30 white boxes."""
    end_time = time.time() + duration
    white_box = "█"
    black_box = "░"
    N_cycle = 25

    global i_Iter
    print(f"EDI verification round: {i_Iter}")
    i_Iter+=1

    while time.time() < end_time:
        for i in range(N_cycle):
            if time.time() >= end_time:
                break
            boxes = [white_box] * N_cycle
            boxes[i] = black_box
            print(f"\r Verifying Edge Data Integrity {''.join(boxes)}", end="", flush=True)
            time.sleep(delay)
        for i in range(N_cycle-2, 0, -1):
            if time.time() >= end_time:
                break
            boxes = [white_box] * N_cycle
            boxes[i] = black_box
            print(f"\r Verifying Edge Data Integrity {''.join(boxes)}", end="", flush=True)
            time.sleep(delay)
    print("\r Verification Done! " + " " * 15)

def auto_execute():
    """Automatically regenerate challenges and send to all clients for n_iter times."""
    global iteration_counter, auto_running
    if not running or not auto_running or iteration_counter >= n_iter:
        auto_running = False
        # print(f"\n[AutoMode] Completed all {n_iter} iterations.")
        return

    iteration_counter += 1
    print(f"\nIteration #{iteration_counter}", end=' ')
    box_animation(duration=2.5)

    try:
        generate_messages_for_edges()
        for client_id in list(connected_clients.keys()):
            if client_id in challenge_all_per_edge:
                start_time_MSend = time.time()
                send_message_to_client(client_id, challenge_all_per_edge[client_id])
                time_all.append(time.time() - start_time_MSend)
            else:
                print(f"No message available for {client_id}")
    except Exception as e:
        print(f"[AutoMode] Error during cycle #{iteration_counter}: {e}")

    if iteration_counter < n_iter:
        threading.Timer(interval_sec, auto_execute).start()
    else:
        auto_running = False
        print(f"\n[AutoMode] Finished all {n_iter} iterations.")

#_____________________ Command handler (manual control) __________________________#

def server_command_handler():
    global running, auto_running
    print("\nCloud_server Command Interface:")
    print("Commands: 'send', 'list', 'exit'")

    while running:
        try:
            command_line = input("Cloud_server Command: ").strip().lower()

            if command_line == 'exit':
                running = False
                auto_running = False
                break

            elif command_line == 'list':
                with connected_clients_lock:
                    if not connected_clients:
                        print("No active Edge servers.")
                    else:
                        print("--- Connected Edge Servers ---")
                        for client_id in connected_clients:
                            addr = connected_clients[client_id]['address']
                            print(f"- {client_id} (Address: {addr[0]}:{addr[1]})")

            elif command_line == 'send':
                if not connected_clients:
                    print("[AutoMode] No connected Edge servers to send data.")
                    continue
                if not auto_running:
                    print(f"[AutoMode] Starting automatic message sending every {interval_sec} seconds for {n_iter} iterations...")
                    auto_running = True
                    threading.Timer(1, auto_execute).start()
                else:
                    print("[AutoMode] Already running auto-send loop.")

            else:
                print("Unknown command.")
                print("Valid Commands: 'send', 'list', 'exit'")

        except EOFError:
            running = False
            auto_running = False
            break
        except Exception as e:
            print(f"Command handler error: {e}")

#_____________________________________ Main Cloud_server Setup _______________________________________#

Cloud_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Cloud_server.bind(('0.0.0.0', 12345))
Cloud_server.listen(5)
print("Cloud_server listening on port 12345...")

command_thread = threading.Thread(target=server_command_handler, daemon=True)
command_thread.start()

while running:
    try:
        Cloud_server.settimeout(1.0)
        edge_server_socket, edge_server_address = Cloud_server.accept()
        Cloud_server.settimeout(None)
        client_thread = threading.Thread(target=handle_edge_server, args=(edge_server_socket, edge_server_address), daemon=True)
        client_thread.start()

    except socket.timeout:
        continue
    except KeyboardInterrupt:
        running = False
        Cloud_server.close()
        break
    except Exception as e:
        print(f"Accept error: {e}")

with connected_clients_lock:
    for client_id in list(connected_clients.keys()):
        remove_client(client_id)

Cloud_server.close()
print("Cloud_server shut down.")
