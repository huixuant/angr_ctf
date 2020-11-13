import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048640
  initial_state = project.factory.blank_state(addr=start_address)

  password = claripy.BVS('password', 16 * 8)

  password_address = 0x804A050
  initial_state.memory.store(password_address, password)

  simulation = project.factory.simgr(initial_state)

  address_to_check_constraint = 0x8048580
  simulation.explore(find=address_to_check_constraint)

  if simulation.found:
    solution_state = simulation.found[0]

    constrained_parameter_address = 0x804A050
    constrained_parameter_size_bytes = 16
    constrained_parameter_bitvector = solution_state.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )

    constrained_parameter_desired_value = "MHZSCHXXYAGKKITH"
    constraint_expression = constrained_parameter_bitvector == constrained_parameter_desired_value
    solution_state.add_constraints(constraint_expression)
    solution = solution_state.solver.eval(password, cast_to=bytes)

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
