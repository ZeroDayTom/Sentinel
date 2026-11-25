"""Lecture et analyse de journaux SSH simulés pour ASSR Sentinel.

Les fonctions publiques de ce module suivent le contrat commun du projet.
Les dates des événements sont des objets datetime pendant l'exécution.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import hashlib
import ipaddress
from pathlib import Path
import re


# Deux formats courants sont acceptés : date ISO avec année, ou format syslog
# sans année (ex. « Nov 25 10:01:02 »). Dans ce dernier cas, default_year sert.
_DATE_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
_EVENT_PATTERN = re.compile(
    r"sshd(?:\[\d+\])?:\s*(?P<action>Accepted|Failed)\s+password\s+"
    r"for\s+(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[^\s]+)",
    re.IGNORECASE,
)


def _parse_date(value, default_year):
    """Convertit une date ISO ou syslog en datetime."""
    if "-" in value:
        # fromisoformat accepte notamment le séparateur T et l'espace.
        return datetime.fromisoformat(value)
    return datetime.strptime(f"{default_year} {value}", "%Y %b %d %H:%M:%S")


def read_logs(paths, default_year):
    """Lit des fichiers SSH et renvoie (événements reconnus, lignes rejetées).

    Une ligne mal formée, un événement incomplet ou une adresse IP invalide
    augmente le compteur. Le traitement continue pour les lignes suivantes.
    """
    events = []
    unrecognized_count = 0

    # Accepter un chemin unique en plus de la liste définie dans config.json.
    if isinstance(paths, (str, Path)):
        paths = [paths]

    for path in paths:
        # L'erreur de fichier manquant remonte à main.py qui affichera le message.
        with Path(path).open("r", encoding="utf-8") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                date_match = _DATE_PATTERN.search(line)
                event_match = _EVENT_PATTERN.search(line)
                if not date_match or not event_match:
                    unrecognized_count += 1
                    continue

                try:
                    event_date = _parse_date(date_match.group("date"), default_year)
                    event_ip = str(ipaddress.ip_address(event_match.group("ip")))
                except (ValueError, TypeError):
                    # Une date invalide ou une IP qui n'est pas une adresse réelle
                    # rend cette ligne inexploitable, mais ne doit pas arrêter le fichier.
                    unrecognized_count += 1
                    continue

                action = event_match.group("action").lower()
                events.append(
                    {
                        "date": event_date,
                        "type": "SUCCESS" if action == "accepted" else "FAILURE",
                        "user": event_match.group("user"),
                        "ip": event_ip,
                        "file": str(path),
                        "line": line_number,
                    }
                )

    # Les fichiers peuvent être concaténés dans un ordre quelconque.
    events.sort(key=lambda event: event["date"])
    return events, unrecognized_count


def compute_stats(events):
    """Calcule les échecs par IP et utilisateur et les trois IP les plus actives."""
    by_ip = Counter()
    by_user = Counter()
    for event in events:
        if event["type"] == "FAILURE":
            by_ip[event["ip"]] += 1
            by_user[event["user"]] += 1

    # Le tri secondaire rend le résultat stable en cas d'égalité.
    top3 = sorted(by_ip.items(), key=lambda item: (-item[1], item[0]))[:3]
    return {
        "failures_by_ip": dict(by_ip),
        "failures_by_user": dict(by_user),
        "top3_ips": [{"ip": ip, "failures": count} for ip, count in top3],
    }


def _make_alert(rule, event, user, description):
    """Crée une alerte dont l'identifiant reste stable à la réanalyse."""
    identity = f"{rule}|{event['date'].isoformat()}|{event['ip']}|{user or ''}"
    alert_id = "ALR-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    return {
        "id": alert_id,
        "rule": rule,
        "date": event["date"],
        "ip": event["ip"],
        "user": user,
        # À faire valider par l'équipe : les documents ne fixent pas les gravités.
        "severity": "HIGH",
        "description": description,
    }


def detect(events, rules):
    """Applique R1 (échecs par IP) et R2 (échecs puis succès par compte/IP).

    R1 est déclenchée à partir du seuil configuré, pour chaque événement qui
    atteint ce seuil. R2 est évaluée au moment d'une réussite, avec les échecs
    antérieurs de la même IP et du même compte dans la fenêtre configurée.
    L'identifiant déterministe et le dictionnaire final éliminent les doublons
    produits par des événements répétitifs ou une réanalyse identique.
    """
    ordered_events = sorted(events, key=lambda event: event["date"])
    alerts_by_id = {}

    # Garder les échecs par IP permet de compter les essais récents pour R1.
    failures_by_ip = defaultdict(list)
    # R2 exige de distinguer à la fois le compte et l'adresse IP.
    failures_by_pair = defaultdict(list)

    r1 = rules["R1"]
    r2 = rules["R2"]
    r1_threshold = int(r1["max_failures"])
    r1_window = timedelta(minutes=float(r1["window_minutes"]))
    r2_threshold = int(r2["min_failures"])
    r2_window = timedelta(minutes=float(r2["window_minutes"]))

    for event in ordered_events:
        event_date = event["date"]
        ip = event["ip"]
        user = event["user"]

        if event["type"] == "FAILURE":
            # On ajoute d'abord cet échec, puis on supprime ceux sortis de la fenêtre.
            failures_by_ip[ip].append(event_date)
            failures_by_pair[(ip, user)].append(event_date)

            ip_cutoff = event_date - r1_window
            failures_by_ip[ip] = [date for date in failures_by_ip[ip] if date >= ip_cutoff]
            pair_cutoff = event_date - r2_window
            failures_by_pair[(ip, user)] = [
                date for date in failures_by_pair[(ip, user)] if date >= pair_cutoff
            ]

            if len(failures_by_ip[ip]) >= r1_threshold:
                alert = _make_alert(
                    "R1", event, None,
                    f"Au moins {r1_threshold} échecs depuis l’adresse IP {ip} "
                    f"en {r1_window.total_seconds() / 60:g} minutes.",
                )
                alerts_by_id[alert["id"]] = alert

        elif event["type"] == "SUCCESS":
            cutoff = event_date - r2_window
            recent_failures = [
                date for date in failures_by_pair[(ip, user)] if date >= cutoff
            ]
            if len(recent_failures) >= r2_threshold:
                alert = _make_alert(
                    "R2", event, user,
                    f"Connexion réussie pour {user} depuis {ip} après "
                    f"{len(recent_failures)} échecs en {r2_window.total_seconds() / 60:g} minutes.",
                )
                alerts_by_id[alert["id"]] = alert

    return sorted(alerts_by_id.values(), key=lambda alert: (alert["date"], alert["id"]))
