import sys
import inspect
from compare import compare
from random import randrange

def get_code(function_code, lineno):
	source_lines, starting_line_no = inspect.getsourcelines(function_code)
	return source_lines[lineno - starting_line_no].rstrip()


# How many lines tracked so far
visited_lines = set()
# Total lines in the function
total_lines = len(inspect.getsourcelines(compare)[0])

def analyze(frame, event, arg):
	function_code = frame.f_code   			
	function_name = function_code.co_name 
	lineno = frame.f_lineno
	codeline = get_code(function_code, lineno)
	variable_values = ", ".join([f"{name}={frame.f_locals[name]}" for name in frame.f_locals])
	print(f"{function_name}:{lineno} {codeline} ({variable_values})")

	# marks current line as visited
	visited_lines.add(lineno) 
	# returns the function itself to track the new scope
	return analyze

def main():
    max_attempts = 100
    num_attempts = 0
    while True:
        a = randrange(1, 5)
        b = randrange(1, 5)
		
        if len(visited_lines) < total_lines - 1:
            sys.settrace(analyze)
            t = compare(a, b)
            print(f"compare({a}, {b}) = {repr(t)}")
            sys.settrace(None)
        else:
            print("Achieved Desired Coverage")
            break
		
		# breaks out of the loop if we have attempted enough and still couldn't cover everything
        num_attempts += 1
        if num_attempts > max_attempts: 
            break
    
    #Print Results:
    print("Results:\n")
    print( len(visited_lines), "paths checked of", total_lines, "Total Paths\n")
    print("Branch Coverage=","{0:.0%}".format((len(visited_lines))/total_lines),"\n")
if __name__ == '__main__':
	main()