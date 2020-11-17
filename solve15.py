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
        self.state.add_constraints(char >='\x30', char <= '\x7e')

      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1)

      self.state.globals['solution0'] = scanf0
      self.state.globals['solution1'] = scanf1

  scanf_symbol = "__isoc99_scanf"  
  project.hook_symbol(scanf_symbol, ReplacementScanf())


  def check_puts(state):
    puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)

    if state.solver.symbolic(puts_parameter):
      good_job_string_address = 0x4A474B4B 
      is_vulnerable_expression = puts_parameter == good_job_string_address

      copied_state = state.copy()
      copied_state.add_constraints(is_vulnerable_expression)
      
      if copied_state.satisfiable():
        state.add_constraints(is_vulnerable_expression)
        return True
      else:
        return False
    else: 
      return False

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    puts_address = 0x8048370
    if state.addr == puts_address:
      return check_puts(state)
    else:
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]

    stored_solutions0 = solution_state.solver.eval(solution_state.globals['solution0'])
    stored_solutions1 = solution_state.solver.eval(solution_state.globals['solution1'], cast_to=bytes)
    print("{0} {1}".format(stored_solutions0, stored_solutions1))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
