import os,sys,nmap
import re ,datetime,json
import style

nm=nmap.PortScanner()
result={}
ports=[]

def display(res):
    for i in res:
      for r in res[i]['port']:
        key=list(r.keys())[0]
        info=str(r[key]).strip()
        if '[IP]' in str(key):
          print('\t',style.black(style.on_yellow(" "+str(key)+" ")),'\t',style.yellow(str(info)))
        if '[TCP]' in str(key):
          print('\t',style.black(style.on_green(" "+str(key)+" ")),'\t',style.green(str(info)))
        if '[UDP]' in str(key):
          print('\t',style.black(style.on_magenta(" "+str(key)+" ")),'\t',style.magenta(str(info)))


def _scan(ip,arg):
    result={}
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    for i in list(res.keys()):
        x=[];p={}
        if 'tcp' in list(res[i].keys()):
            for j in (res[i]['tcp']):
                y={}
                port=str(j)
                if 'open' in str(res[i]['tcp'][j]['state']).lower():
                    info=str(res[i]['tcp'][j]['name']).upper()+' '+str(res[i]['tcp'][j]['product'])+' '+str(res[i]['tcp'][j]['version'])+' '+str(res[i]['tcp'][j]['extrainfo'])
                    y['[TCP] '+port]=str(info)
                    x.append(y)
                    #y=['[TCP] '+port,info]

        if 'udp' in list(res[i].keys()):
            for j in (res[i]['udp']):
                y={}
                port=str(j)
                if 'open' in str(res[i]['udp'][j]['state']).lower():
                    info=str(res[i]['udp'][j]['name']).upper()+' '+str(res[i]['udp'][j]['product'])+' '+str(res[i]['udp'][j]['version'])+' '+str(res[i]['udp'][j]['extrainfo'])
                    y['[UDP] '+port]=str(info)
                    x.append(y)
                    #y=['[UDP] '+port,info]

        if 'ip' in list(res[i].keys()):
            for j in (res[i]['ip']):
                y={}
                port=str(j)
                if 'open' in str(res[i]['ip'][j]['state']).lower():
                    info=str(res[i]['ip'][j]['name']).upper()+' '+str(res[i]['ip'][j]['product'])+' '+str(res[i]['ip'][j]['version'])+' '+str(res[i]['ip'][j]['extrainfo'])
                    y['[IP] '+port]=str(info)
                    x.append(y)

        if 'osmatch' in list(res[i].keys()):
            for j in (res[i]['osmatch']):
                if int(j['accuracy'])>=85:
                    name=(j['name'])
                    p['os']=name
                    break

        if 'uptime' in list(res[i].keys()):
            hrs=int(int(res[i]['uptime']['seconds'])//3600)
            if hrs>23:
                p['uptime']=str(int(hrs)//24)+' days'
            else:
                p['uptime']=str(hrs)+' hrs'

        p['port']=x
        result[i]=p

    display(result)
    return (json.dumps(result))

def tcp(host):
  res=_scan(host,'-sT')
  return (res)

def udp(host):
  res=_scan(host,'-sU')
  return (res)

def syn(host):
  res=_scan(host,'-sS')
  return (res)

def ack(host):
  res=_scan(host,'-sA')
  return (res)

def win(host):
  res=_scan(host,'-sW')
  return (res)

def maimon(host):
  res=_scan(host,'-sM')
  return (res)

def IP(host):
  res=_scan(host,'-sO')
  return (res)

def serv(host):
  res=_scan(host,'-sV -O -F')
  return (res)

def INIT(host):
  res=_scan(host,'-sY')
  return (res)

def echo(host):
  res=_scan(host,'-sZ')
  return (res)

def ext(host):
  res=_scan(host,'-p 0-65535 -sT -sU -O')
  return (res)

def all(host):
  pass

