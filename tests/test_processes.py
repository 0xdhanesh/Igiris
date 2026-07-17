from igiris.processes import ProcessSnapshot, file_paths_from_fd_targets, library_paths_from_maps, resolve_root


def test_resolve_root_stops_below_system_boundary():
    table = {
        900: ProcessSnapshot(900, 500, "curl", "/usr/bin/curl", "curl x", "u"),
        500: ProcessSnapshot(500, 100, "bash", "/usr/bin/bash", "bash", "u"),
        100: ProcessSnapshot(100, 1, "sshd", "/usr/sbin/sshd", "sshd", "root"),
        1: ProcessSnapshot(1, 0, "systemd", "/usr/lib/systemd/systemd", "systemd", "root"),
    }
    assert resolve_root(900, table) == 500


def test_resolve_root_keeps_meaningful_desktop_parent():
    table = {
        300: ProcessSnapshot(300, 200, "chrome", "/opt/chrome", "chrome", "u"),
        200: ProcessSnapshot(200, 1, "gnome-shell", "/usr/bin/gnome-shell", "gnome-shell", "u"),
    }
    assert resolve_root(300, table) == 300


def test_library_paths_from_proc_maps_are_deduplicated_and_path_only():
    maps = """7f00 r-xp 0000 00:00 0 /usr/lib/aarch64-linux-gnu/libssl.so.3
7f01 r--p 0000 00:00 0 /usr/lib/aarch64-linux-gnu/libssl.so.3
7f02 r-xp 0000 00:00 0 /usr/bin/python3.11
7f03 r-xp 0000 00:00 0 [vdso]
7f04 r-xp 0000 00:00 0 /tmp/plugin.so (deleted)
"""
    assert library_paths_from_maps(maps) == {
        "/tmp/plugin.so",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    }


def test_open_file_targets_exclude_non_file_descriptors_and_libraries():
    targets = [
        "/etc/resolv.conf",
        "/tmp/data.txt (deleted)",
        "/usr/lib/libcrypto.so.3",
        "socket:[123]",
        "pipe:[456]",
        "anon_inode:[eventpoll]",
    ]
    assert file_paths_from_fd_targets(targets) == {"/etc/resolv.conf", "/tmp/data.txt"}
