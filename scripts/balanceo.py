# -*- encoding: utf-8 -*-

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.packet.icmp import TYPE_ECHO_REQUEST
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ethernet import ETHER_ANY
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time

log = core.getLogger()
_flood_delay = 0

class LearningSwitch (object):

  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #Tablas de aprendizaje, round_robin balanceado y proxy:
    self.round_robin = 0
    self.max_srvs = 4
    self.frst_prt = 2

    self.rrweb = 0
    self.web = [1, 1, 2, 3]
    self.rrwebs = 0
    self.webs = [2, 3]
    self.rrssh = 0
    self.ssh = [2, 4, 4, 4, 4]
    self.rricmp = 0
    self.icmp = [1, 1, 2, 3]

    self.macToSrvWeb = {}
    self.macToSrvWebS = {}
    self.macToSrvSsh = {}
    self.macToSrvICMP = {}

  #Funciones para round robin con pesos:
  def roundRobin(self):
    rr = (self.round_robin%self.max_srvs) + self.frst_prt
    self.round_robin+=1
    return rr

  def rr_web(self):
    rr = self.rrweb % len(self.web)
    self.rrweb+=1
    return self.web[rr]

  def rr_webS(self):
    rr = self.rrwebs % len(self.webs)
    self.rrwebs+=1
    return self.webs[rr]

  def rr_icmp(self):
    rr = self.rricmp % len(self.icmp)
    self.rricmp+=1
    return self.icmp[rr]

  def rr_ssh(self):
    rr = self.rrssh % len(self.ssh)
    self.rrssh+=1
    return self.ssh[rr]

  #Evento de nuevo paquete:
  def _handle_PacketIn (self, event):

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    """
    Idea:   Si es ARP REQUEST:
                Reenviar a cualquiera, pero NO CREAR FLUJO, sólo reenviar, me sirve round-robin para resto de conexiones NO CONSIDERADAS, de modo que el round-robin resuelve la MAC para la caché del cliente.
            Si es TCP:
                Si es a puerto 80:
                    Reenviar a servidores 1 a 3. Al 1 más conexiones, peso de 2 frente a 1, 1.
                Si es a puerto 22:
                    Reenviar a servidor 2 o 4. Al 4 más conexiones, peso de 4 frente a 1.
                Si es a puerto 443:
                    Reenviar a servidor 2 o 3. Igual pesos.
            Si es UDP:
                No hacer nada extra de l2_learning
            Si es ICMP:
                Balanceo paralelo, pero configurado igual que HTTP, pues lo esperado es que los clientes hagan ping para ver si la web está activa.
            Resto:
                "Delegar" en l2_learning
    """
    srv_to_mac = {
        1 : "00:00:00:00:01:01",
        2 : "00:00:00:00:01:02",
        3 : "00:00:00:00:01:03",
        4 : "00:00:00:00:01:04",
    }

    srv_to_port = {
        1 : 2,
        2 : 3,
        3 : 4,
        4 : 5,
    }

    #Instala flujo con proxy mac del srv desde un cliente
    def flowToSrv(srv, tp_port = None, ipProto = ipv4.TCP_PROTOCOL):
      print "Flujo de cli=", packet.src, " asking for ", packet.dst, " proxy a srv=", srv
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(in_port = event.port,
                              dl_src = packet.src,
                              dl_dst = packet.dst,
                              dl_type = 0x800, # Siempre trabajamos con IP
                              nw_proto = ipProto,
                              nw_src = packet.next.srcip,
                              nw_dst = "10.0.0.101",
                              tp_dst = tp_port)
      #msg.idle_timeout = 10
      #msg.hard_timeout = 30
      msg.actions.append(of.ofp_action_dl_addr(5, srv_to_mac[srv])) # MAC PROXY
      msg.actions.append(of.ofp_action_output(port = srv_to_port[srv]))
      msg.data = event.ofp
      self.connection.send(msg)

    #Instala flujo con proxy mac del srv hacia un cliente
    def flowToCli(srvmac, tp_port = None, ipProto = ipv4.TCP_PROTOCOL):
      print "Flujo de srv=", packet.src, " a cli=", packet.dst, " asking for ", srvmac
      # El flujo contrario: srv a cliente
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(in_port = event.port,
                              dl_src = packet.src,
                              dl_dst = packet.dst, #El servidor conoce la mac e ip reales del cliente
                              dl_type = 0x800,
                              nw_proto = ipProto,
                              nw_dst = packet.next.dstip,
                              nw_src = "10.0.0.101",
                              tp_src = tp_port)
      #msg.idle_timeout = 10
      #msg.hard_timeout = 30
      msg.actions.append(of.ofp_action_dl_addr(4, srvmac)) # MAC PROXY
      msg.actions.append(of.ofp_action_output(port = self.macToPort[packet.dst])) #Lo aprendió en la consulta
      msg.data = event.ofp
      self.connection.send(msg)


    #No usado, envía un ARP announcement, usado en pruebas de detectar flujo
    def sendARPannouncement(conn, m, port, dst=ETHER_ANY):
      #print "mac: ", m, " port: ", port, " dst: ", dst
      mac = EthAddr(m)
      arp_reply = arp()
      arp_reply.hwsrc = mac
      arp_reply.hwdst = mac
      arp_reply.opcode = arp.REPLY
      arp_reply.protosrc = IPAddr('10.0.0.101')
      arp_reply.protodst = IPAddr('10.0.0.101')
      ether = ethernet()
      ether.type = ethernet.ARP_TYPE
      ether.dst = dst
      ether.src = mac
      ether.payload = arp_reply
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = ether
      conn.send(msg)

    # DETECCION DE FLUJOS
    # Estamos en el Switch 2
    if dpid_to_str(event.dpid) == "00-00-00-00-00-02":
      if packet.type == packet.IP_TYPE: # Paquete IP
        ipP = packet.next
        if ipP.dstip == "10.0.0.101" : # Se dirige a los servidores
          if ipP.protocol==ipv4.TCP_PROTOCOL: # TCP vs ICMP vs UDP
            tcpP = ipP.next
            if tcpP.dstport==80: # HTTP
              print "Conexión HTTP"
              #Calcular por round robin balanceado el servidor a reenviar el tráfico
              srv = self.rr_web()
              #Guardamos por qué mac preguntaba el cliente antes de aplicar proxy
              self.macToSrvWeb[packet.src] = packet.dst
              #Flujo desde el cliente al servidor aplicando proxy mac del srv
              flowToSrv(srv, tp_port=80)
              return
            elif tcpP.dstport==443: # HTTPS
              print "Conexión HTTPS"
              srv = self.rr_webS()
              self.macToSrvWebS[packet.src] = packet.dst
              flowToSrv(srv, tp_port=443)
              return
            elif tcpP.dstport==22: # SSH
              print "Conexión SSH"
              srv = self.rr_ssh()
              self.macToSrvSsh[packet.src] = packet.dst
              flowToSrv(srv, tp_port=22)
              return
          elif ipP.protocol==ipv4.ICMP_PROTOCOL: # ICMP vs TCP vs UDP
            print "Conexión ICMP"
            icmpP = ipP.next
            self.macToSrvICMP[packet.src] = packet.dst
            srv = self.rr_icmp()
            flowToSrv(srv, ipProto=ipv4.ICMP_PROTOCOL)
            return
          elif ipP.protocol==ipv4.UDP_PROTOCOL: #UDP. No hacer nada
            print "Conexión UDP."

        elif ipP.srcip == "10.0.0.101": # Flujo de vuelta desde el servidor
          if ipP.protocol==ipv4.TCP_PROTOCOL:
            tcpP = ipP.next
            if tcpP.dstport==80: # HTTP
              print "Srv HTTP reply: srv=", packet.src
              #Paso la mac por la que preguntó el cliente, para deshacer proxy mac
              flowToCli(self.macToSrvWeb[packet.dst], tp_port = 80)
              return
            elif tcpP.dstport==443: # HTTPS
              print "Srv HTTPS reply: srv=", packet.src
              flowToCli(self.macToSrvWebS[packet.dst], tp_port = 443)
              return
            elif tcpP.dstport==22: # SSH
              print "Srv SSH reply: srv=", packet.src
              flowToCli(self.macToSrvSsh[packet.dst], tp_port = 22)
              return
          elif ipP.protocol==ipv4.ICMP_PROTOCOL: # ICMP
            print "Srv ICMP reply: srv=", packet.src
            flowToCli(self.macToSrvICMP[packet.dst], ipProto=ipv4.ICMP_PROTOCOL)
            return
        else:                                 #-RESTO-
            print "Conexión no TCP/UDP/ICMP"
      elif ( packet.type == packet.ARP_TYPE and     # ARP REQUEST
            packet.next.opcode == arp.REQUEST and
            packet.next.protodst == "10.0.0.101" ):
        print "ARP REQUEST"
        # Round-Robin
        # Reenviar ARP, no crear flujo
        # Cualquier tipo de flujo no tenido en cuenta antes (HTTP, HTTPS, ...)
        # se reenvía por round robin a cualquier servidor
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = self.roundRobin()))
        msg.data = event.ofp
        self.connection.send(msg)
        return


    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return

        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
