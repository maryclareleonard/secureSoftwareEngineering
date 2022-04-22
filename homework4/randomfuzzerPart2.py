import sys
import inspect
import ast
import z3
from twice import test
from triangle import triangle

def get_code(function_code, lineno):
	source_lines, starting_line_no = inspect.getsourcelines(function_code)
	return source_lines[lineno - starting_line_no].rstrip()

#symbolic fuzzer - generate inputs based on symbolic execution
def collect_path_conditions(tree):
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

			traverse_if_children(node.body, context, cond)
			traverse_if_children(node.orelse, context, not_cond)

		else:
			for child in ast.iter_child_nodes(node):
				traverse(child, context)

	traverse(tree, [])

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
    test_source = inspect.getsource(triangle) #test source is triangle.py triangle function
    test_ast = ast.parse(test_source)
    path_conditions = collect_path_conditions(test_ast)
    generated_inputs = []  
    for condition in path_conditions:
        print("PATH = ", condition)
        s = z3.Solver()
        a = z3.Int("a")
        b = z3.Int("b")
        c = z3.Int("c")
        status = eval(f"s.check({condition})")
        if status == z3.sat:
            solution = s.model()
            input_a = solution[a]
            input_b = solution[b]
            input_c = solution[c] 
            generated_inputs.append( (input_a, input_b, input_c))

    for inp in generated_inputs:
        a, b, c = inp
        sys.settrace(analyze)
        triangle(a,b,c)
        sys.settrace(None)
    
if __name__ == '__main__':
	main()