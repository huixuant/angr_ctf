import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048905
  initial_state = project.factory.blank_state(addr=start_address)

  filename = "INYXFAJA.txt" 
  symbolic_file_size_bytes = 0x40

  password = claripy.BVS('password', symbolic_file_size_bytes * 8)
  
  file_options = 'r'
  password_file = angr.storage.SimFile(filename, content=password, size=symbolic_file_size_bytes)
  initial_state.fs.insert('INYXFAJA.txt', password_file)

  symbolic_filesystem = {
    filename : password_file
  }
  initial_state.posix.fs = symbolic_filesystem

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if (b"Good Job." in stdout_output):
        return True
    else:
        return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if (b"Try again." in stdout_output):
        return True
    else:
        return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.solver.eval(password,cast_to=bytes)

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
