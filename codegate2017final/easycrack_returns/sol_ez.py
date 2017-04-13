from pwn import *
import requests
import angr

import claripy


def solve(i):
  name = "prob" + str(i)


  cmd_obj = "objdump -d " + name + " | grep puts@plt\\> | grep call"

  popen1 = subprocess.Popen (cmd_obj, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  (stdoutdata, stderrdata) = popen1.communicate ()

  data = stdoutdata.split ("\n")
  target_tmp = data[0].split (":")[0]
  target_addr = int (target_tmp, 16)
  avoid_addr = int (data[1].split (":")[0], 16)

  cmd_obj = "objdump -d " + name + " | grep " + target_tmp + " -B 5"
  popen2 = subprocess.Popen (cmd_obj, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  (stdoutdata, stderrdata) = popen2.communicate ()

  data = stdoutdata.split ("\n")
  mem_addr = data[0].split ("$")[1].split (",")[0]
  mem_addr = int (mem_addr, 16)


  start_addr = int (data[0].split (":")[0], 16)

  p = angr.Project (name, load_options={'auto_load_libs': False})
  state = p.factory.blank_state (addr = start_addr)

  state.memory.store (mem_addr, state.se.BVS ('buf', 8 * 98))

  pg = p.factory.path_group (state)

  ex = pg.explore (find = target_addr, avoid = avoid_addr)
  final = ex.found[0].state

  pay = final.se.any_str (final.memory.load (mem_addr, 98))
  return pay 


f = open ("answer", "w")
for i in xrange(1,300):
  
  print "Now solve ", i
  ans = solve (i).replace ("\x00", "")
  print i,ans
  f.write (str(i) +" answer: "+ans + "\n")

f.close ()
