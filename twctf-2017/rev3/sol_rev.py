import angr

p = angr.Project ("rev3", load_options={'auto_load_libs':False})


state = p.factory.blank_state ()


pg = p.factory.path_group (state)

#ex = pg.explore (find = 0x0804867C, avoid = 0x0804868E)

#final = ex.found[0].state
explore = angr.surveyors.Explorer(p, find = 0x0804867C, avoid = 0x0804868E)

print explore.run().found[0].state.posix.dumps (0)
