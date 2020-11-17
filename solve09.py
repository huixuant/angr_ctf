import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()
  
  check_equals_called_address = 0x80486CE
  instruction_to_skip_length = 5

  @project.hook(check_equals_called_address, length=instruction_to_skip_length)
  def skip_check_equals_(state):
    user_input_buffer_address = 0x804A054
    user_input_buffer_length = 16

    user_input_string = state.memory.load(
      user_input_buffer_address, 
      user_input_buffer_length
    )
    
    check_against_string = "OCBCCIVHEEABWMKF" 

    state.regs.eax = claripy.If(
      user_input_string == check_against_string, 
      claripy.BVV(1, 32), 
      claripy.BVV(0, 32)
    )

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
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
