import yaml


def load_config(file_path):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)


config = load_config("config.yaml")
hosts_data = config["hosts"]

hosts = []
for host, details in hosts_data.items():
    if host != "base":
        hosts.append((host, details))

print(hosts)
