# Code from the Fuzzing Book
def triangle(a, b, c):
    if a == b:
        if b == c:
            return 'equilateral'
        else:
            return 'isosceles #1'
    else:
        if b == c:
            return 'isosceles #2'
        else:
            if a == c:
                return 'isosceles #3'
            else:
                return 'scalene'