import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementCheckEquals(angr.SimProcedure):
    def run(self, to_check, length):
      user_input_buffer_address = to_check
      user_input_buffer_length = length

      user_input_string = self.state.memory.load(
        user_input_buffer_address,
        user_input_buffer_length
      )

      check_against_string = "RAKIUGFVOCBBSYFN"
      
      return claripy.If(
               user_input_string == check_against_string, 
               claripy.BVV(1, 32), 
               claripy.BVV(0, 32)
             )

  check_equals_symbol = "check_equals_RAKIUGFVOCBBSYFN" 
  project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return (b"Good Job." in stdout_output)

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return (b"Try again." in stdout_output)

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
