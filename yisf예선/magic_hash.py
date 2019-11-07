import md5
import string
import sys

def do_0e_check(inhash):
   if inhash[:2] == '0e':
      print 'hash %s begins with 0e' % inhash
      if all([char in string.digits for char in inhash[2:]]):
         return True
   return False

i = int(sys.argv[1])
answer = 0

print "Starting cracking process..."

while True:
   hashcandidate = md5.new(str(i)+'S@L7').hexdigest()
   if do_0e_check(hashcandidate):
      break
   else:
      i += 1
      if i % 100000 == 0:
         sys.stdout.write("\rCurrent i value: %s" % i)
         sys.stdout.flush()

print "Answer found: md5(%s+'S@L7') matches" % (i)