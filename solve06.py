import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x80486B3
  initial_state = project.factory.blank_state(addr=start_address)

  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)

  fake_heap_address0 = 0x12345678
  pointer_to_malloc_memory_address0 = 0x9A99034
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  
  fake_heap_address1 = 0X22345678
  pointer_to_malloc_memory_address1 = 0x9A9903C
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

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

    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution = "{0} {1}".format(solution0, solution1)

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
