import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]

  base = 0x8048000
  project = angr.Project(path_to_binary, load_options={ 
    'main_opts' : { 
      'custom_base_addr' : base 
    } 
  })

  buffer_ptr = claripy.BVV(0x77777777, 32)
  buffer_size = claripy.BVV(8, 32)

  validate_function_address = base + 0x674
  initial_state = project.factory.call_state(validate_function_address, buffer_ptr, buffer_size)

  password = claripy.BVS('password', 64)
  initial_state.memory.store(buffer_ptr, password)
  
  simulation = project.factory.simgr(initial_state)

  success_address = base + 0x720
  simulation.explore(find=success_address)

  if simulation.found:
    solution_state = simulation.found[0]

    solution_state.add_constraints(solution_state.regs.eax != 0)
    solution = solution_state.solver.eval(password, cast_to=bytes)
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
