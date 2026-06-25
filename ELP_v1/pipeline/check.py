import json

with open('semantic_activities.json', encoding='utf-8') as f:
    activities = json.load(f)

attack_clusters = []
for a in activities:
    processes = [p.lower() for p in a.get('processes', [])]
    types = a.get('event_types', [])
    if any(p in processes for p in ['powershell.exe', 'cmd.exe', 'msedge.exe']):
        attack_clusters.append(a)

attack_clusters.sort(key=lambda x: x['event_count'], reverse=True)

print(f'공격 관련 cluster: {len(attack_clusters)}개')
print()
for a in attack_clusters[:15]:
    print(f"id={a['activity_id']} | count={a['event_count']} | processes={a['processes']} | types={a['event_types']}") 