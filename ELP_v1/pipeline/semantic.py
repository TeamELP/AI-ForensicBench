import json
from collections import defaultdict, deque

# =========================================================
# INPUT / OUTPUT
# =========================================================

INPUT_FILE = "event_graph.json"
OUTPUT_FILE = "semantic_activities.json"

# =========================================================
# SETTINGS
# =========================================================

# 사용할 relation
VALID_RELATIONS = {
    "process_lineage",
    "shared_file",
    "shared_ip",
    "same_pid",

    # 추가 가능성 대비
    "shared_service"
}

# 제거할 noise event
NOISE_EVENT_TYPES = {
    "handle_close"
}

# =========================================================
# semantic activity 핵심 이벤트
# =========================================================

ANCHOR_EVENT_TYPES = {

    # process
    "process_create",
    "process_access",

    # network
    "network_connection",
    "dns_query",

    # shell
    "powershell_execution",
    "shell_execution",

    # file
    "file_create",
    "file_delete",
    "file_stream_create",

    # =====================================================
    # system event 추가
    # =====================================================

    "service_state_change",
    "service_config_change",
    "driver_load",
    "device_connect",
    "device_disconnect"
}

# singleton 제거
MIN_DEGREE = 1

# 최소 cluster 크기
MIN_CLUSTER_SIZE = 2

# anchor 없는 cluster 허용 최소 크기
MIN_NON_ANCHOR_CLUSTER_SIZE = 4

# =========================================================
# LOAD GRAPH
# =========================================================

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    graph = json.load(f)

nodes = graph["nodes"]
edges = graph["edges"]

print(f"[+] Loaded nodes: {len(nodes)}")
print(f"[+] Loaded edges: {len(edges)}")

# =========================================================
# NODE MAP
# =========================================================

node_map = {}

for node in nodes:

    event_id = node["event_id"]

    etype = node.get("event_type")

    # noise 제거
    if etype in NOISE_EVENT_TYPES:
        continue

    node_map[event_id] = node

print(f"[+] Nodes after noise filtering: {len(node_map)}")

# =========================================================
# GRAPH BUILD
# =========================================================

adj = defaultdict(list)

used_edges = 0

for edge in edges:

    relation = edge.get("relation")

    if relation not in VALID_RELATIONS:
        continue

    src = edge["src"]
    dst = edge["dst"]

    # fake node 제외
    if src not in node_map or dst not in node_map:
        continue

    adj[src].append(dst)
    adj[dst].append(src)

    used_edges += 1

print(f"[+] Used edges: {used_edges}")

# =========================================================
# LOW DEGREE PRUNING
# =========================================================

valid_nodes = set()

for event_id in node_map:

    degree = len(adj[event_id])

    if degree >= MIN_DEGREE:
        valid_nodes.add(event_id)

print(f"[+] Nodes after degree pruning: {len(valid_nodes)}")

# =========================================================
# CONNECTED COMPONENTS
# =========================================================

visited = set()
clusters = []

for event_id in valid_nodes:

    if event_id in visited:
        continue

    queue = deque([event_id])
    visited.add(event_id)

    cluster = []

    while queue:

        current = queue.popleft()
        cluster.append(current)

        for neighbor in adj[current]:

            if neighbor not in valid_nodes:
                continue

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    if len(cluster) >= MIN_CLUSTER_SIZE:
        clusters.append(cluster)

print(f"[+] Raw clusters: {len(clusters)}")

# =========================================================
# BUILD CLUSTER OUTPUT
# =========================================================

activities = []

for idx, cluster in enumerate(clusters):

    cluster_nodes = []

    for eid in cluster:

        if eid in node_map:
            cluster_nodes.append(node_map[eid])

    if len(cluster_nodes) == 0:
        continue

    # =====================================================
    # anchor 검사
    # =====================================================

    anchor_found = False

    for event in cluster_nodes:

        etype = event.get("event_type")

        if etype in ANCHOR_EVENT_TYPES:
            anchor_found = True
            break

    # =====================================================
    # anchor 없는 작은 cluster 제거
    # =====================================================

    if not anchor_found:

        if len(cluster_nodes) < MIN_NON_ANCHOR_CLUSTER_SIZE:
            continue

    # =====================================================
    # 정보 수집
    # =====================================================

    event_types = set()
    processes = set()
    files = set()
    ips = set()
    users = set()

    # =====================================================
    # system 관련 추가
    # =====================================================

    services = set()
    devices = set()

    timestamps = []

    for event in cluster_nodes:

        etype = event.get("event_type")

        if etype:
            event_types.add(etype)

        # =================================================
        # process
        # =================================================

        pname = event.get("process_name")

        if pname:
            processes.add(pname)

        # =================================================
        # file
        # =================================================

        fpath = event.get("file_path")

        if fpath:
            files.add(fpath)

        # =================================================
        # network
        # =================================================

        ip = event.get("destination_ip")

        if ip:
            ips.add(ip)

        # =================================================
        # user
        # =================================================

        user = event.get("user")

        if user:
            users.add(user)

        # =================================================
        # service
        # =================================================

        service_name = event.get("service_name")

        if service_name:
            services.add(service_name)

        # =================================================
        # device
        # =================================================

        device_name = event.get("device_name")

        if device_name:
            devices.add(device_name)

        # =================================================
        # timestamp
        # =================================================

        ts = event.get("timestamp")

        if ts:
            timestamps.append(ts)

    # =====================================================
    # 시간 정렬
    # =====================================================

    timestamps_sorted = sorted(timestamps)

    start_time = timestamps_sorted[0]
    end_time = timestamps_sorted[-1]

    # =====================================================
    # OUTPUT
    # =====================================================

    activity = {

        "activity_id": len(activities) + 1,

        "events": sorted(cluster),

        "event_count": len(cluster),

        "event_types": sorted(list(event_types)),

        "processes": sorted(list(processes)),

        "files": sorted(list(files)),

        "ips": sorted(list(ips)),

        "users": sorted(list(users)),

        # =================================================
        # system 정보 추가
        # =================================================

        "services": sorted(list(services)),

        "devices": sorted(list(devices)),

        "start_time": start_time,

        "end_time": end_time
    }

    activities.append(activity)

print(f"[+] Total semantic activities: {len(activities)}")

# =========================================================
# SAVE
# =========================================================

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(activities, f, indent=2, ensure_ascii=False)

print(f"[+] Saved semantic activities to: {OUTPUT_FILE}")