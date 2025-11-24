def extract(path):

    with open(path, "rb")as file:
        code = file.read()

    return code

print(extract("../examples/example1"))