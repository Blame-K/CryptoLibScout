"""Export IDA-discovered function metadata for vSim.

This script is intended to run inside IDA with:
  idat -A -S"/path/to/ida_export_functions.py /path/to/out.pkl" /path/to/bin.i64

It avoids Hex-Rays decompiler APIs and exports only the metadata vSim needs for
function selection and callgraph lookup.
"""

from __future__ import annotations

import os
import pickle
import sys
from pathlib import Path

import idaapi
import idautils
import idc


def import_networkx():
    try:
        import networkx as nx

        return nx
    except ImportError:
        root = Path(__file__).resolve().parents[1]
        for site_packages in (root / ".vsim310-venv" / "lib").glob("python*/site-packages"):
            sys.path.insert(0, str(site_packages))
        import networkx as nx

        return nx


nx = import_networkx()


def get_idb_info() -> str:
    try:
        import ida_ida

        proc_name = ida_ida.inf_get_procname()
        if ida_ida.inf_is_64bit():
            bits = "64"
        elif getattr(ida_ida, "inf_is_32bit_exactly", lambda: False)():
            bits = "32"
        else:
            bits = "unknown"
        return f"{proc_name}{bits}"
    except Exception:
        pass

    get_inf_structure = getattr(idaapi, "get_inf_structure", None)
    if get_inf_structure is not None:
        info = get_inf_structure()
        if info.is_64bit():
            bits = "64"
        elif info.is_32bit():
            bits = "32"
        else:
            bits = "unknown"
        return f"{info.procName}{bits}"

    return "unknown"


def build_func_graph(func) -> nx.DiGraph:
    graph = nx.DiGraph()
    for block in idaapi.FlowChart(func):
        graph.add_node(block.start_ea, start=block.start_ea, end=block.end_ea)
        for succ in block.succs():
            graph.add_edge(block.start_ea, succ.start_ea)

    if graph.number_of_nodes() == 0:
        graph.add_node(func.start_ea, start=func.start_ea, end=func.end_ea)

    graph.graph["arch"] = get_idb_info()
    graph.graph["name"] = idaapi.get_func_name(func.start_ea)
    graph.graph["file"] = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    graph.graph["start_ea"] = func.start_ea
    graph.graph["end_ea"] = func.end_ea
    graph.graph["code_xref_to"] = set()
    graph.graph["xref_potential_strings"] = []
    graph.graph["str_xrefs"] = []
    return graph


def get_function_ranges(features: dict[int, nx.DiGraph]) -> list[tuple[int, int]]:
    return sorted((graph.graph["start_ea"], graph.graph["end_ea"]) for graph in features.values())


def find_function_start(ranges: list[tuple[int, int]], ea: int) -> int | None:
    left, right = 0, len(ranges)
    while left < right:
        mid = (left + right) // 2
        start, end = ranges[mid]
        if ea < start:
            right = mid
        elif ea >= end:
            left = mid + 1
        else:
            return start
    return None


def add_call_edges(features: dict[int, nx.DiGraph]) -> None:
    ranges = get_function_ranges(features)
    for target in features:
        for xref in idautils.CodeRefsTo(target, True):
            caller = find_function_start(ranges, xref)
            if caller is not None and caller in features:
                features[caller].graph["code_xref_to"].add(target)


def main() -> None:
    if len(idc.ARGV) < 2:
        print("usage: ida_export_functions.py <output.pkl>")
        idaapi.qexit(2)

    output_path = idc.ARGV[1]
    idaapi.auto_wait()

    features = {}
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if func is None:
            continue
        features[func_ea] = build_func_graph(func)

    add_call_edges(features)

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(features, f, protocol=4)

    print(f"dump {output_path}")
    print(f"functions {len(features)}")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
