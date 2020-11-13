import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x80486B2
  initial_state = project.factory.blank_state(addr=start_address)

  initial_state.regs.ebp = initial_state.regs.esp

  password0 = claripy.BVS('password0', 32)
  password1 = claripy.BVS('password1', 32)

  padding_length_in_bytes = 8 
  initial_state.regs.esp -= padding_length_in_bytes

  initial_state.stack_push(password0)
  initial_state.stack_push(password1)  

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if (b'Good Job.' in stdout_output):
        return True
    else: 
        return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if (b'Try again.' in stdout_output):
        return True
    else: 
        return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0)
    solution1 = solution_state.solver.eval(password1)

    solution = "{0} {1}".format(solution0, solution1)
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
