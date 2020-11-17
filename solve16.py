# Essentially, the program does the following:
#
# scanf("%d %20s", &key, user_input);
# ...
#   // if certain unknown conditions are true...
#   strncpy(random_buffer, user_input);
# ...
# if (strncmp(secure_buffer, reference_string)) {
#   // The secure_buffer does not equal the reference string.
#   puts("Try again.");
# } else {
#   // The two are equal.
#   puts("Good Job.");
# }
#
# If this program has no bugs in it, it would _always_ print "Try again." since
# user_input copies into random_buffer, not secure_buffer.
#
# The question is: can we find a buffer overflow that will allow us to overwrite
# the random_buffer pointer to point to secure_buffer? (Spoiler: we can, but we
# will need to use Angr.)
#
# We want to identify a place in the binary, when strncpy is called, when we can:
#  1) Control the source contents (not the source pointer!)
#     * This will allow us to write arbitrary data to the destination.
#  2) Control the destination pointer
#     * This will allow us to write to an arbitrary location.
# If we can meet both of those requirements, we can write arbitrary data to an
# arbitrary location. Finally, we need to constrain the source contents to be
# equal to the reference_string and the destination pointer to be equal to the
# secure_buffer.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):
    def run(self, format_string, scanf0_address, scanf1_address):
      scanf0 = claripy.BVS('scanf0', 32)
      scanf1 = claripy.BVS('scanf1', 20*8)

      for char in scanf1.chop(bits=8):
        self.state.add_constraints(char >= '\x30', char <= '\x7e')

      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1)

      self.state.globals['solutions'] = (scanf0, scanf1)

  scanf_symbol = "__isoc99_scanf" # :string
  project.hook_symbol(scanf_symbol, ReplacementScanf())


  def check_strncpy(state):
    # The stack will look as follows:
    # ...          ________________
    # esp + 15 -> /                \
    # esp + 14 -> |     param2     |
    # esp + 13 -> |      len       |
    # esp + 12 -> \________________/
    # esp + 11 -> /                \
    # esp + 10 -> |     param1     |
    #  esp + 9 -> |      src       |
    #  esp + 8 -> \________________/
    #  esp + 7 -> /                \
    #  esp + 6 -> |     param0     |
    #  esp + 5 -> |      dest      |
    #  esp + 4 -> \________________/
    #  esp + 3 -> /                \
    #  esp + 2 -> |     return     |
    #  esp + 1 -> |     address    |
    #      esp -> \________________/
    # (!)
    strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
    strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
    strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)

    src_contents = state.memory.load(strncpy_src, strncpy_len)

    if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
      password_string = "LBPNJSHS" 
      buffer_address = 0x4D494B48 

      does_src_hold_password = src_contents[-1:len(password_string)*8] == password_string
      does_dest_equal_buffer_address = strncpy_dest == buffer_address

      if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
        state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
        return True
      else:
        return False
    else: 
      return False

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    strncpy_address = 0x8048410
    if state.addr == strncpy_address:
      return check_strncpy(state)
    else:
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]
    (solution0, solution1) = solution_state.globals['solutions']
    solution = "{0} {1}".format(solution_state.solver.eval(solution0), solution_state.solver.eval(solution1, cast_to=bytes))
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
