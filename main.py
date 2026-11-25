from src.inventory import load_config, load_inventory

config = load_config("config.json")
machines, anomalies = load_inventory(config["paths"]["inventory"])

print(f"Machines valides : {len(machines)}")
for machine in machines:
    print(f"  {machine['id']}  {machine['name']}  {machine['ip']}  {machine['environment']}")

print(f"\nAnomalies : {len(anomalies)}")
for anomaly in anomalies:
    print(f"  ligne {anomaly['line']} : {anomaly['reason']}")
