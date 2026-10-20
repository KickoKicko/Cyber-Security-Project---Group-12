"""
Live traffic classification demo.

Captures network traffic in fixed-length windows, extracts the same metadata
features used in training (sizes, directions, bursts, timings) and predicts
which application is being used. Payloads are never decrypted.

Usage:
    python live_demo.py            # listen on Wi-Fi (en0)  -> Scenario A
    python live_demo.py bridge100  # listen on hotspot      -> Scenario B
"""

import os
import sys
import subprocess
import tempfile
from collections import Counter
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'traffic_model.joblib')
INTERFACE = sys.argv[1] if len(sys.argv) > 1 else 'en0'


# ---------------------------------------------------------------------------
# Feature extraction: copied unchanged from the Colab notebook (steps 2 and 3)
# ---------------------------------------------------------------------------

def read_packets(pcap_path):
    """Read only packet METADATA: returns times, sizes and directions (+1 out, -1 in)."""
    cmd = ['tshark', '-r', pcap_path, '-T', 'fields',
           '-E', 'separator=\t', '-E', 'occurrence=f',
           '-e', 'frame.time_epoch', '-e', 'frame.len',
           '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'ip.dst', '-e', 'ipv6.dst']
    output = subprocess.run(cmd, capture_output=True, text=True).stdout

    times, sizes, srcs, dsts = [], [], [], []
    for line in output.splitlines():
        t, size, src4, src6, dst4, dst6 = line.split('\t')
        src, dst = src4 or src6, dst4 or dst6
        if not src or not dst:
            continue
        times.append(float(t))
        sizes.append(int(size))
        srcs.append(src)
        dsts.append(dst)

    if not times:
        return np.array([]), np.array([]), np.array([])

    client = Counter(srcs + dsts).most_common(1)[0][0]
    directions = [1 if s == client else -1 for s in srcs]
    order = np.argsort(times)
    return (np.array(times)[order], np.array(sizes)[order], np.array(directions)[order])


def stats(prefix, values):
    """Summarise a list of numbers with mean, standard deviation and maximum."""
    values = np.asarray(values, dtype=float)
    if len(values) == 0:
        return {f'{prefix}_mean': 0.0, f'{prefix}_std': 0.0, f'{prefix}_max': 0.0}
    return {f'{prefix}_mean': values.mean(),
            f'{prefix}_std':  values.std(),
            f'{prefix}_max':  values.max()}


def find_bursts(sizes, directions):
    """Total bytes of each run of consecutive same-direction packets."""
    bursts = {1: [], -1: []}
    current = sizes[0]
    for i in range(1, len(sizes)):
        if directions[i] == directions[i - 1]:
            current += sizes[i]
        else:
            bursts[directions[i - 1]].append(current)
            current = sizes[i]
    bursts[directions[-1]].append(current)
    return bursts[1], bursts[-1]


def extract_features(times, sizes, directions):
    """Turn a sequence of packets into one row of numeric features."""
    out_sizes = sizes[directions == 1]
    in_sizes  = sizes[directions == -1]
    gaps      = np.diff(times)
    duration  = times[-1] - times[0]
    out_bursts, in_bursts = find_bursts(sizes, directions)

    features = {
        'n_packets':       len(sizes),
        'duration':        duration,
        'packets_per_sec': len(sizes) / duration if duration > 0 else 0.0,
        'bytes_per_sec':   sizes.sum() / duration if duration > 0 else 0.0,
        'frac_outgoing':   len(out_sizes) / len(sizes),
        'in_out_bytes':    in_sizes.sum() / (out_sizes.sum() + 1),
        'n_bursts':        len(out_bursts) + len(in_bursts),
    }
    features.update(stats('size',      sizes))
    features.update(stats('out_size',  out_sizes))
    features.update(stats('in_size',   in_sizes))
    features.update(stats('gap',       gaps))
    features.update(stats('out_burst', out_bursts))
    features.update(stats('in_burst',  in_bursts))
    return features


# ---------------------------------------------------------------------------
# Live loop
# ---------------------------------------------------------------------------

def capture_window(seconds, path):
    """Record `seconds` of traffic on INTERFACE into a pcap file."""
    subprocess.run(['tshark', '-i', INTERFACE, '-a', f'duration:{seconds}',
                    '-w', path, '-q'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    bundle = joblib.load(MODEL_PATH)
    model, columns = bundle['model'], bundle['features']
    window, min_packets = bundle['window'], bundle['min_packets']

    print(f"Listening on '{INTERFACE}' in {window}-second windows. Press Ctrl+C to stop.\n")
    pcap_path = os.path.join(tempfile.gettempdir(), 'live_window.pcapng')

    while True:
        capture_window(window, pcap_path)
        times, sizes, directions = read_packets(pcap_path)
        clock = datetime.now().strftime('%H:%M:%S')

        if len(sizes) < min_packets:
            print(f"[{clock}] idle ({len(sizes)} packets)")
            continue

        row = pd.DataFrame([extract_features(times, sizes, directions)])[columns]
        probabilities = model.predict_proba(row)[0]
        ranking = sorted(zip(model.classes_, probabilities), key=lambda x: -x[1])

        best, confidence = ranking[0]
        runner_up, runner_conf = ranking[1]
        print(f"[{clock}] {best:<11} {confidence:4.0%}   "
              f"(next: {runner_up} {runner_conf:.0%}, {len(sizes)} packets)")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
