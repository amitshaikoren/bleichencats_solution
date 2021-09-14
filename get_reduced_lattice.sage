import re

mat = []
file = open("lattice.txt", 'r')
lines = file.readlines()
dim = len(lines)
file.close()
for line in lines[:len(lines) - 1]:
    line = line[1: len(line) - 2]
    vector = [int(s) for s in line.split(',')]
    mat.append(vector)

line = re.split(",", lines[len(lines) - 1][2:-2])
vector = []
for num in line[:len(line) - 1]:
    vector.append(int(num))

vector.append(mat[1][0] * (dim-3) / (dim-2))
mat.append(vector)
dim = len(lines)
lattice = matrix(QQ, mat)
reduced = lattice.LLL()
file = open("reduced_lattice.txt", 'w')
for i in range(len(mat)):
    for j in range(len(mat) - 1):
        file.write(str(reduced[i,j]) + " ")
    file.write("\n")
file.close()
