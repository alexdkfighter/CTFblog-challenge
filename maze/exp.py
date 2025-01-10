from pwn import *
#context(arch = 'amd64', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux')
p = process('./Maze_Rust')
#p = remote("10.252.113.234",13146)
elf = ELF('./Maze_Rust')
#libc = ELF('./libc.so.6')

p.sendlineafter(b'3: Handle The Maze', b'3')
p.recvline()

maze = []
while True:
    line = p.recvline().decode().strip()
    if "quit" in line:
        break
    maze.append(line)

DIRECTIONS = [(-1, 0, 'W'), (1, 0, 'S'), (0, -1, 'A'), (0, 1, 'D')]

def find_positions(maze):
    start = end = None
    for i, row in enumerate(maze):
        if 'P' in row:
            start = (i, row.index('P'))
        if 'G' in row:
            end = (i, row.index('G'))
    return start, end

def can_move(maze, x, y):
    return 0 <= x < len(maze) and 0 <= y < len(maze[0]) and maze[x][y] in ' PG'

#深度优先算法求解迷宫
def dfs(maze, x, y, end, path, visited, direction_path):
    if (x, y) == end:
        return True

    visited.add((x, y))

    for dx, dy, direction in DIRECTIONS:
        nx, ny = x + dx, y + dy
        if can_move(maze, nx, ny) and (nx, ny) not in visited:
            path.append((nx, ny))
            direction_path.append(direction)
            if dfs(maze, nx, ny, end, path, visited, direction_path):
                return True
            path.pop()
            direction_path.pop()

    return False

def solve_maze(maze):
    start, end = find_positions(maze)
    path = [start]
    direction_path = []
    visited = set()
    if dfs(maze, start[0], start[1], end, path, visited, direction_path):
        return direction_path
    else:
        return None

path = solve_maze(maze)
path_ = "".join(path).lower()
p.sendline(path_)

p.interactive()
