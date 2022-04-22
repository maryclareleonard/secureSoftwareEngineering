def twice(v):
   return 2 * v

def test(x, y):
   z = twice(y)
   if x == z:
      if x > y + 10:
         print("ERROR")