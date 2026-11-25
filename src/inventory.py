import ipaddress
import json

# Les champs qu'une machine doit obligatoirement avoir
REQUIRED_FIELDS = ["id", "name", "ip", "environment", "services"]

# Les champs qu'un service doit obligatoirement avoir
SERVICE_FIELDS = ["name", "port", "timeout"]


def read_json(path):
    """Lit un fichier JSON et renvoie son contenu."""
    try:
        # On ouvre le fichier et on transforme le JSON en données Python
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        # Le fichier n'existe pas : on donne un message clair
        raise FileNotFoundError(f"Fichier introuvable : {path}")
    except json.JSONDecodeError as e:
        # Le JSON est mal écrit (virgule oubliée, guillemet manquant...) : on dit à quelle ligne
        raise ValueError(f"{path} est mal écrit (ligne {e.lineno}) : {e.msg}")


def load_config(path):
    """Lit le fichier config.json et renvoie son contenu sous forme de dictionnaire."""
    return read_json(path)


def load_inventory(path):
    """Charge les machines et renvoie deux listes : les machines valides et les anomalies."""
    data = read_json(path)

    # Le fichier doit contenir une liste de machines, sinon on ne peut rien en faire
    if not isinstance(data, list):
        raise ValueError(f"{path} doit contenir une liste de machines")

    machines = []    # ici on range les machines valides
    anomalies = []   # ici on range les machines rejetées, avec la raison
    seen_ids = set() # ici on retient les id déjà vus, pour repérer les doublons

    # On passe sur chaque machine une par une, avec son numéro (1, 2, 3...)
    for position, machine in enumerate(data, start=1):
        error = check_machine(machine, seen_ids)

        if error:
            # La machine a un problème : on la met de côté avec la raison
            anomalies.append({"source": "inventory", "line": position, "reason": error})
        else:
            # La machine est bonne : on la garde et on retient son id
            machines.append(machine)
            seen_ids.add(machine["id"])

    return machines, anomalies


def check_machine(machine, seen_ids):
    """Renvoie la raison du rejet d'une machine, ou None si elle est valide."""
    # Si l'élément n'est même pas une machine (par exemple juste un texte), on le rejette
    if not isinstance(machine, dict):
        return "élément qui n'est pas une machine"

    # 1. Il ne doit manquer aucun champ
    for field in REQUIRED_FIELDS:
        if field not in machine:
            return f"{machine.get('id', '?')} : champ '{field}' manquant"

    # 2. L'id ne doit pas être déjà pris par une autre machine
    if machine["id"] in seen_ids:
        return f"{machine['id']} : identifiant déjà utilisé"

    # 3. L'adresse IP doit être une vraie IPv4 (ipaddress refuse par exemple 300.1.1.1)
    try:
        ipaddress.IPv4Address(machine["ip"])
    except ValueError:
        return f"{machine['id']} : adresse IP invalide ({machine['ip']})"

    # 4. Chaque service doit avoir ses champs et un port entre 1 et 65535
    for service in machine["services"]:
        for field in SERVICE_FIELDS:
            if field not in service:
                return f"{machine['id']} : champ '{field}' manquant dans un service"

        port = service["port"]
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return f"{machine['id']} : port invalide ({port})"

    # Aucun problème trouvé : la machine est valide
    return None
