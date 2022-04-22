import inspect
import ast
import sys
import z3
from twice import test 

def get_code(function_code, lineno):
	source_lines, starting_line_no = inspect.getsourcelines(function_code)
	return source_lines[lineno - starting_line_no].rstrip()

def collect_path_conditions(numOfPaths, tree):
    paths = []

    def traverse_if_children(children, context, cond):
        old_paths = len(paths)
        for child in children:
            traverse(child, context + [cond])
        if len(paths) == old_paths:
            paths.append(context + [cond])

    def traverse(node, context):
        if isinstance(node, ast.If):    
            cond = ast.unparse(node.test).strip()
            not_cond = "z3.Not(" + cond + ")"
            
            traverse_if_children(node.body, context, cond)          #paths appended for children of body
            traverse_if_children(node.orelse, context, not_cond)    #paths appended for children of rest

        else:   
            for child in ast.iter_child_nodes(node): 
                traverse(child, context) #each child of root node gets traverse called on it
    
    traverse(tree, [])
    
    #count the total number of paths
    for path in paths:
        numOfPaths = numOfPaths + 1 

    return ["z3.And(" + ", ".join(path) + ")" for path in paths]

def analyze(frame, event, arg):
	function_code = frame.f_code   			
	function_name = function_code.co_name 
	
	if function_name in("test", "twice"):
		lineno = frame.f_lineno
		codeline = get_code(function_code, lineno)
		variable_values = ", ".join([f"{name}={frame.f_locals[name]}" for name in frame.f_locals])
		print(f"{function_name}:{lineno} {codeline} ({variable_values})")

	# returns the function itself to track the new scope
	return analyze

def main():
    #variables to check paths 
    numOfPaths = 0 
    numOfPathsChecked = 0
    
    test_source = inspect.getsource(test)
    test_ast = ast.parse(test_source)
    path_conditions = collect_path_conditions(numOfPaths, test_ast) #holds all the paths
	

    for condition in path_conditions:
        print("PATH = ", condition)
        s = z3.Solver()
        x = z3.Int("x")
        y = z3.Int("y")
        z = 2*y # workaround for now
        status = eval(f"s.check({condition})")
        numOfPathsChecked = numOfPathsChecked + 1       #count number of paths checked
        if status == z3.sat:
            solution = s.model()
            input_x = solution[x]
            input_y = solution[y]
			
            sys.settrace(analyze)
            test(input_x, input_y)
            sys.settrace(None)

    #Print Results:
    print("Results:\n")
    print("%d Paths Checked of %d Total Paths\n", numOfPathsChecked, numOfPaths)

		
		

if __name__ == '__main__':
	main()