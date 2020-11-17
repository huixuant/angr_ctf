import angr
import sys
import claripy

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
 
  project.hook(0x804FA80, angr.SIM_PROCEDURES['libc']['scanf']())
  project.hook(0x804FA20, angr.SIM_PROCEDURES['libc']['printf']())
  project.hook(0x8050360, angr.SIM_PROCEDURES['libc']['puts']())
  project.hook(0x8048CB0, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
 
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


