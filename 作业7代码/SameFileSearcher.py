import subprocess
from hashlib import sha256

from tqdm import tqdm

hashmap = {}


def index_all_files() -> list[str]:
    """
    遍历指定目录及其子目录，索引所有文件的路径

    return(list[str]): 包含所有文件路径的列表
    """
    EXCLUDE_DIRS = [
        ".git",
        ".vscode",
        ".venv",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
        "Music",
        "Pictures",
        "Desktop",
        "Library",
        "Movies",
        "Documents",
        "Downloads",
        "Public",
        "Applications",
        "Sites",
        ".homebrew",
        ".cache",
        ".config",
        ".Trash",
        "Git",
        ".oh-my-zsh",
        ".npm",
        ".cargo",
        ".gradle",
        ".rustup",
        ".orbstack",
        "powerlevel10k",
        "yakit-projects",
        ".codex",
        ".claude",
        "EShore",
        ".abdm",
        ".lemminx",
        ".cc-switch",
        ".local",
        ".nvm",
        "Workspace",
        ".bun",
        ".dsh",
        ".docker",
        ".wakatime",
        ".vscode-shared",
        ".dotnet",
        "Extensions",
        ".gemini",
        ".gnupg",
        ".copilot",
        ".bytertc",
        ".openjfx",
        ".android",
        ".omp",
        ".john",
        ".vibe-island",
        ".ollama",
        ".zsh_sessions",
    ]
    arguments = [
        "find",
        "/Users/GamerNoTitle",
    ]
    for dir in EXCLUDE_DIRS:
        arguments.extend(["(", "-type", "d", "-name", dir, "-prune", ")", "-o"])
    arguments.extend(["-type", "f", "-print"])
    filelist = subprocess.check_output(arguments).decode().splitlines()
    return filelist


if __name__ == "__main__":
    print("学号: 3124004333")
    all_files = index_all_files()
    print(f"[*] Found {len(all_files)} files in total.")
    for file in tqdm(all_files, desc="[*] Processing files", unit="file"):
        try:
            with open(file, "rb") as f:
                content = f.read()
                hash = sha256(content).hexdigest()
                if hash in hashmap:
                    hashmap[hash].append(file)
                else:
                    hashmap[hash] = [file]
        except OSError as e:
            print(f"[!] Error reading file {file}: {e}. Skipping.")
    for hash, files in hashmap.items():
        if len(files) > 1:
            print(f"[*] Found {len(files)} files with the same hash {hash}:")
            for file in files:
                print(f"    > {file}")
    with open("作业7代码/same_hash_files.txt", "w") as f:
        for hash, files in hashmap.items():
            if len(files) > 1:
                f.write(f"Hash: {hash}\n")
                for file in files:
                    f.write(f"    > {file}\n")
                f.write("\n")
