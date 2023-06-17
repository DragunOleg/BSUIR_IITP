import time
D=KeyboardInterrupt
v=BaseException
V=print
o=None
N=False
U=True
E=len
a=time.sleep
def x(u):
 try:
  a(1.5)
 except D:
  raise v("Interrupted by user")
 V("Next package. {}".format(u))
class G:
 def __init__(n,L,z,s):
  n.version=4
  n.ihl=5
  n.dscp=o
  n.ecn=o
  n.total_length=576 
  n.id=o
  n.flags=o
  n.fragment_offset=o
  n.ttl=15 
  n.protocol=6 
  n.checksum=o 
  n.source_ip=L
  n.destination_ip=z
  n.payload=s
class j:
 def __init__(n,J,g,ip):
  n.ip=ip
  n.source_port=J
  n.destination_port=g
  n.sequence=0
  n.acknowledgment=0
  n.offset=20 
  n.ns=o
  n.cwr=o
  n.ece=o
  n.urg=o
  n.ack=N
  n.psh=o
  n.rst=N
  n.syn=N
  n.fin=N
  n.window_size=o
  n.checksum=0
  n.urgent=o
 def __str__(n):
  return 'Source {}:{}, Destination {}:{}, Seq: {}, Ack: {} Payload: "{}"'.format(n.ip.source_ip,n.source_port,n.ip.destination_ip,n.destination_port,n.sequence,n.acknowledgment,n.ip.payload)
class f:
 def __init__(n,S,d):
  n.members=S
  n.middlewares=d
  n.closed=N
  n.connected=N
 def __find_receiver(n,u):
  for I in n.members:
   if(I.ip_address==u.ip.destination_ip and I.tcp_port==u.destination_port):
    return I
 def A(n,u):
  n.connected=U
  n.b(u)
 def b(n,u):
  if not n.connected or n.closed:
   return
  x(u)
  for l in n.middlewares:
   u=l.K(u)
  if u.rst:
   V('Tcp was reset by rst flag')
   n.t()
   return
  u.ip.ttl-=1
  if u.ip.ttl<=0:
   V('Package ttl is expired')
   n.t()
   return
  w=n.__find_receiver(u)
  if w is o:
   V('Unknown destination {}:{}'.format(u.ip.destination_ip,u.destination_port))
   n.t()
   return
  u=w.q(u)
  if u is o:
   V('One of members stop sending requests')
   n.t()
  else:
   n.b(u)
 def t(n):
  n.closed=U
  V('Connection is closed')
class W:
 def __init__(n,T,k):
  n.ip_address=T
  n.tcp_port=k
  n.caller=N
 def M(n,r):
  n.caller=U
  R=r.members[1]
  u=n.__build_package(R,n.__generate_payload())
  r.A(u)
 def __build_package(n,w,s):
  ip=G(n.ip_address,w.ip_address,"")
  X=j(n.tcp_port,w.tcp_port,ip)
  X.sequence=0
  X.syn=U
  return X
 def p(n,u,s):
  ip=G(u.ip.destination_ip,u.ip.source_ip,"")
  X=j(u.destination_port,u.source_port,ip)
  if u.syn and u.ack:
   X.sequence=u.acknowledgment
   X.acknowledgment=u.sequence+1
   X.ack=U
   return X
  if u.syn:
   X.sequence=0
   X.acknowledgment=u.sequence+1
   X.syn=U
   X.ack=U
   return X
  if u.ack:
   X.sequence=u.acknowledgment
   X.acknowledgment=E(s)
   X.ip.payload="Dummy package"
   return X
  X.ip.payload=s
  if n.caller:
   X.sequence=u.acknowledgment
   X.acknowledgment=u.sequence+E(s)
  else:
   X.sequence=u.acknowledgment
   X.acknowledgment=u.sequence
  return X
 def __generate_payload(n):
  return "A payload for member with address {}:{}".format(n.ip_address,n.tcp_port)
 def q(n,u):
  Y=n.p(u,n.__generate_payload())
  return Y
class h(W):
 def __init__(n,T,k):
  n.ip_address=T
  n.tcp_port=k
  n.caller=N
 def q(n,u):
  Y=n.p(u,"Hacker server payload")
  return Y
class B:
 def __init__(n):
  n.call_number=0
 def K(n,u):
  n.call_number+=1
  if n.call_number==5:
   u.rst=U
  return u
class P:
 def __init__(n):
  n.call_number=0
 def K(n,u):
  n.call_number+=1
  if n.call_number==5:
   u.rst=N
  return u
class F:
 def __init__(n,T,k):
  n.ip_address=T
  n.tcp_port=k
  n.call_number=0
 def K(n,u):
  n.call_number+=1
  if n.call_number==5:
   u.ip.destination_ip=n.ip_address
   u.destination_port=n.tcp_port
  return u
class O:
 def __init__(n):
  n.call_number=0
 def K(n,u):
  n.call_number+=1
  if n.call_number>=5:
   u.ip.payload="Connection hijacked"
   t=u.sequence
   u.sequence=u.acknowledgment
   u.acknowledgment=t+E(u.ip.payload)
   u.ip.destination_ip=u.ip.source_ip
   u.destination_port=u.source_port
   x(u)
  return u
def e():
 H=W(123,1)
 m=W(321,3)
 C=h(231,2)
 Q=P()
 y=F(231,2)
 i=B()
 c=O()
 r=f([H,m,C],[c])
 H.M(r)
e()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

