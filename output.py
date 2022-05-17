import json
import os
import re
import sys
import datetime,time
from collections import Counter
from operator import itemgetter

def set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,serv):
    vuln={}
    vuln['name'] = str(v_name)
    vuln['score'] = float(score)
    vuln['string'] = str(strng)
    vuln['risk'] = str(risk)
    vuln['desc'] = str(desc)
    vuln['imp'] = str(imp)
    vuln['sol'] = str(sol)
    vuln['ref'] = str(ref)
    vuln['link'] = str(link)
    vuln['port']=str(port)
    vuln['service']=str(serv)
    vuln['output']=str(script)
    return vuln

def xss(script):
    result={}
    v_name = 'Cross-Site Scripting(XSS)'
    score = 6.1
    strng = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
    risk = 'Medium'
    desc ='Cross-site Scripting can be classified into four major categories:  \n\tStored XSS, \n\tReflected XSS, \n\tDOM-based XSS \n\tBlind XSS.  In all cases with XSS, the goal of an attacker is to get a victim to  inadvertently execute a maliciously injected script. The malicious  script is often referred to as a malicious payload, or simply a payload. Stored (Persistent) XSS attacks involve an attacker injecting a script  (referred to as the payload) that is permanently stored (persisted) on  the target application (for instance within a database, in a comment  field or in a forum post). Reflected XSS attacks involve an attacker luring a victim to  inadvertently make an HTTP request containing an XSS payload  to a web server, usually achieved through phishing or other social  engineering attacks. Once sent to the web server, the payload is then  reflected back in such a way that the HTTP response includes the  payload from the HTTP request. DOM-based XSS is an advanced type of XSS wherein a payload is  executed as a result of legitimate client-side JavaScript modifying  the Document Object Model (DOM) in a victim’s browser. In contrast  to the other types of XSS, with DOM-based XSS, the HTTP response  itself does not typically change, but rather client side code designed  to process elements in the DOM, executes the malicious payload that  has been injected in the DOM elements processed by the vulnerable  JavaScript code.'
    imp = 'Cross-site Scripting (XSS) refers to client-side code injection attack wherein an attacker can execute malicious scripts into a legitimate website or web application. XSS occurs when a web application makes use of unvalidated or unencoded user input within the output it generates.\nThere are three main types of XSS attacks. These are:\n\tReflected XSS, where the malicious script comes from the current HTTP request.\n\tStored XSS, where the malicious script comes from the website\'s database.\n\tDOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.\nThe actual impact of an XSS attack generally depends on the nature of the application, its functionality and data, and the status of the compromised user. For example:\nIn a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.\nIn an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.\nIf the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.'
    sol = 'Preventing cross-site scripting is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:\nFilter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.\nEncode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.\nUse appropriate response headers. To prevent XSS in HTTP responses that aren\'t intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.\nContent Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.'
    ref = 'CWE:79,CVE-2020-10385'
    link = 'http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting,https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet'

    head = '[MED]  CROSS-SITE SCRIPTING'
    port=""
    name=""
    #display('PORT: ' + str(port) + '\t' + head)
    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, name)
    return head,json.dumps(result)

def sqli(script):
    result={}
    v_name = 'SQL Injection'
    score = 10.0
    strng = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N'
    risk = 'Critical'
    desc = 'SQL injection (SQLi) refers to an injection attack wherein an attacker can execute malicious SQL statements that control a web application\'s database server.SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application\'s content or behavior.\nIn some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack'
    imp = 'A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Many high-profile data breaches in recent years have been the result of SQL injection attacks, leading to reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization\'s systems, leading to a long-term compromise that can go unnoticed for an extended period.'
    sol = 'Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.'
    ref = 'CWE:89,CVE-2022-26201,CVE-2022-24646,CVE-2022-24707,CVE-2022-25506,CVE-2022-25404, CVE-2022-25394'
    link = 'https://www.acunetix.com/websitesecurity/sql-injection/,https://www.acunetix.com/websitesecurity/sql-injection2/,https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/,https://www.owasp.org/index.php/SQL_Injection,http://pentestmonkey.net/category/cheat-sheet/sql-injection'

    head = '[HIGH] SQL INJECTION VULNERABILTY'
    port = ""
    name = ""
    #display('PORT: ' + str(port) + '\t' + head)
    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, name)
    return head,json.dumps(result)

def rce(script):
    result={}
    v_name = 'Remote Code Execution'
    score = 9.8
    strng = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    risk = 'Critical'
    desc = 'Remote Code Execution (RCE) is a very dangerous vulnerability that allows an attacker to execute arbitrary commands on the target web server (usually in a target process). The ability to trigger arbitrary code execution from one machine on another, especially over the Internet, is often referred to as remote code execution (RCE).'
    imp ='A code execution bug is arguably the most severe effect a vulnerability can cause since it potentially allows an attacker to take over the system entirely, from where an attacker can likely achieve lateral movement, taking note of resources on the network and seeking opportunities for collecting additional credentials or privilege escalation.'
    sol = 'The best way to protect a computer from a remote code execution vulnerability is to fix loopholes that could allow an attacker to gain access.\n\tTo protect a computer from such vulnerability, users must periodically update their software and must keep their system up-to-date.\n\tIf your organization is using servers that have software which is vulnerable to remote code execution, then the latest software security patch should be applied.\n\tMoreover, it is best to automate server patching in order to prevent remote code execution attacks.\n\tIt is recommended not to open any file or attachment from an anonymous sender.\n\tAnother best option would be to not use functions such as eval and to not allow anyone to edit the content of files that might be parsed by the respective languages.\n\tIn order to protect a computer from RCE, you should not allow a user to decide the name and extensions of files.\n\tTo prevent RCE, you should not sanitize user input and should not pass any user-controlled input inside evaluation functions or callbacks.\n\tIt is also recommended to not blacklist special characters or function names.'
    ref = 'CVE-2021-31166,CWE:416'
    link = 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-31166,http://packetstormsecurity.com/files/162722/Microsoft-HTTP-Protocol-Stack-Remote-Code-Execution.html'
    head = '[CRIT] REMOTE CODE EXECUTION'
    port = ""
    name = ""
    #display('PORT: ' + str(port) + '\t' + head)
    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, name)
    return head,json.dumps(result)

def ssti(script):
    result={}
    v_name = 'Server-Side Template Injection'
    score = 7.3
    strng = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
    risk = 'High'
    desc ='Server-Side Template Injection,Web applications often rely on template engines to manage the dynamic generation of the HTML pages presented to their users.'
    imp ='A Server-Side Template Injection (SSTI) vulnerability exists when an application embeds unsafe user-controlled inputs in its templates and then evaluates it.\nBy injecting a specific payload dependent on the template engine used by the application, an attacker can leverage this vulnerability to gain access to sensitive information or to achieve remote code execution.'
    sol = 'Developers should avoid using user inputs in server templates to prevent malicious injections. If the application still requires this type of inputs, logic-less template engines should be preferred when possible to decrease the attack surface by removing the logic part of the code from the templates. Finally, another solution is to create sandboxed environments by leveraging language capabilities or docker isolated containers.'
    ref = 'CWE:74'
    link ='https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/,https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection,https://www.okiok.com/server-side-template-injection-from-detection-to-remote-shell/,https://medium.com/@adrien_jeanneau/how-i-was-able-to-list-some-internal-information-from-paypal-bugbounty-ca8d217a397c'
    head = '[HIGH] SST INJECTION'
    port = ""
    name = ""
    #display('PORT: ' + str(port) + '\t' + head)
    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, name)
    return head,json.dumps(result)


def create_HTML(data):
    vulnerabilities=[];v_name=[]
    html_data='<center><h2>HOST WISE ANALYSIS</h2></center>'

    h_count=0
    m_chart=''
    for d in data:
        h_count+=1
        #x={}
        #print(d)
        vuln=[]
        if len(json.loads(data[d]['vuln']['sql']))>0:
            script=[];x={}
            for i in list(json.loads(data[d]['vuln']['sql'])):
                #print(list(i.keys())[0])
                script.append(list(i.keys())[0])
            head,res=(sqli(list(set(script))))
            res=json.loads(res)[head]
            vuln.append(res)
            vulnerabilities.append(res)
            x['name']=res['name']
            x['host']=d
            v_name.append(x)


        if len(json.loads(data[d]['vuln']['rce']))>0:
            script=[];x={}
            for i in (json.loads(data[d]['vuln']['rce'])):
                #print(list(i.keys())[0])
                script.append(list(i.keys())[0])
            head,res=(rce(list(set(script))))
            res=json.loads(res)[head]
            vuln.append(res)
            vulnerabilities.append(res)
            x['name']=res['name']
            x['host']=d
            v_name.append(x)

        if len(json.loads(data[d]['vuln']['ssti']))>0:
            script=[];x={}
            for i in (json.loads(data[d]['vuln']['ssti'])):
                #print(list(i.keys())[0])
                script.append(list(i.keys())[0])
            head, res = (ssti(list(set(script))))
            res = json.loads(res)[head]
            vuln.append(res)
            vulnerabilities.append(res)
            x['name']=res['name']
            x['host']=d
            v_name.append(x)

        if len(json.loads(data[d]['vuln']['xss']))>0:
            script=[];x={}
            for i in (json.loads(data[d]['vuln']['xss'])):
                #print(list(i.keys())[0])
                script.append(list(i.keys())[0])
            head, res = (ssti(list(set(script))))
            res = json.loads(res)[head]
            vuln.append(res)
            vulnerabilities.append(res)
            x['name']=res['name']
            x['host']=d
            v_name.append(x)

        for v in (data[d]['vuln']['common']):
            v=json.loads(v)
            for i in (v.keys()):
                y={};x={}
                if v[i] not in vuln:
                    vuln.append(v[i])
                #print(v[i])
                y['name']=v[i]['name']
                y['risk']=v[i]['risk']
                y['score']=v[i]['score']
                y['ref']=v[i]['ref']
                y['host']=d
                #vulnerabilities.append(x)
                vulnerabilities.append(v[i])
                x['name'] = v[i]['name']
                x['host'] = d
                v_name.append(x)


        vuln=[dict(y) for y in set(tuple(x.items()) for x in vuln)]
        vuln = (sorted(vuln, key=lambda item: item['score'], reverse=True))

        d=data[d]
        start=str(d['start'])
        end=str(d['end'])
        s=datetime.datetime(int(start.split(' ')[0].split('-')[0]),int(start.split(' ')[0].split('-')[1]),int(start.split(' ')[0].split('-')[2]),int(start.split(' ')[-1].split('.')[0].split(':')[0]),int(start.split(' ')[-1].split('.')[0].split(':')[1]),int(start.split(' ')[-1].split('.')[0].split(':')[2]))
        e=datetime.datetime(int(end.split(' ')[0].split('-')[0]),int(end.split(' ')[0].split('-')[1]),int(end.split(' ')[0].split('-')[2]),int(end.split(' ')[-1].split('.')[0].split(':')[0]),int(end.split(' ')[-1].split('.')[0].split(':')[1]),int(end.split(' ')[-1].split('.')[0].split(':')[2]))
        #print(d.keys())
        html_data = html_data + ('\t<div class="host_summary" align="center"><table><tr><td id="info">\n')

        html_data=html_data+('\t\t<div align="center" id="host_info">\n')
        html_data=html_data+('\t\t<h4>HOST DETAILS</h4>\n')
        html_data=html_data+('\t\t<table id="host_summary">\n')
        html_data=html_data+('\t\t\t<tr id="host"><th>HOST</th><td id="'+str(d['host']).lower().replace('.','_')+'">'+str(d['host'])+'</td></tr>\n')
        html_data=html_data+('\t\t\t<tr id="ip"><th>IP ADDRESS</th><td>'+str(d['ip'])+'</td></tr>\n')
        if (len(d['names']))>0:
            html_data=html_data+('\t\t\t<tr id="hostname"><th>HOSTNAME</th><td>'+str('<br>'.join((map(str,list(d['names'])))))+'</td>\n')
        if (len(str(d['mac'])))>0:
            html_data=html_data+('\t\t\t<tr id="mac"><th>MAC ADDRESS</th><td>'+str(d['mac'])+'</td></tr>\n')
        if (len(str(d['os'])))>0:
            html_data=html_data+('\t\t\t<tr id="os"><th>OPERATING SYSTEM</th><td>'+str(d['os'])+'</td></tr>\n')
        html_data=html_data+('\t\t\t<tr id="uptime"><th>SYSTEM UPTIME</th><td>'+str(d['uptime'])+'</td></tr>\n')
        html_data=html_data+('\t\t\t<tr id="duration"><th>SCAN DURATION</th><td>' + str(e-s) + ' hrs</td></tr>\n')
        html_data=html_data+('\t\t\t<tr id="link"><th>AVAILABLE LINKS</th><td><ul>\n')
        if len(d['url'])>0:
            for u in list(set(list(d['url']))):
                html_data=html_data+('\t\t\t\t<li><a target="_blank" href="'+str(u)+'">'+str(u)+'</a></li>\n')
        html_data=html_data+('\t\t\t</ul></td></tr>\n')
        html_data=html_data+('\t\t</table></div></td><td id="ports">\n')

        html_data = html_data + ('\t\t<div align="center" id="host_port_info">\n')
        html_data = html_data + ('\t\t<h4>OPEN PORT DETAILS</h4>\n')
        html_data = html_data + ('\t\t<table id="port_summary">\n')
        html_data = html_data + ('\t\t\t<tr><th>PORT</th><th>INFORMATION</th></tr>\n')
        for i in list(d['ports']):
            port = (list(i.keys())[0])
            info = i[port]
            html_data = html_data + (
                        '\t\t\t<tr><td id="port">' + str(port) + '</td><td id="info">' + str(info) + '</td></tr>\n')
        html_data = html_data + ('\t\t</table></div></td></tr></table>\n')


        summary={}
        for i in Counter(map(itemgetter('risk'), vuln)).most_common():
            summary[i[0]]=str(i[1])

        m_chart_data='''CanvasJS.addColorSet("mycolor",["#8b0000","#ff0000","#daa520","#b2ec5d","#00ced1"]);
        var chart = new CanvasJS.Chart("chartContainer'''+str(h_count)+'''",
        {colorSet: "mycolor",title:{text: "Vulnerability Summary"}, data: [{indexLabelPlacement: "outside",type: "doughnut",showInLegend: true,toolTipContent: "{y} - #percent %",yValueFormatString: "count ,#",legendText: "{indexLabel}",
                dataPoints: [
                '''
        try:
            m_chart_data=m_chart_data+str('{  y: '+summary['Critical']+', indexLabel: "Critical" },')
        except:
            m_chart_data=m_chart_data+str('{  y: 0 , indexLabel: "Critical"}, ')
        try:
            m_chart_data = m_chart_data + str('{  y: ' + summary['High'] + ', indexLabel: "High" },')
        except:
            m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "High"}, ')
        try:
            m_chart_data = m_chart_data + str('{  y: ' + summary['Medium'] + ', indexLabel: "Medium" },')
        except:
            m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Medium"}, ')
        try:
            m_chart_data = m_chart_data + str('{  y: ' + summary['Low'] + ', indexLabel: "Low" },')
        except:
            m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Low"}, ')
        try:
            m_chart_data = m_chart_data + str('{  y: ' + summary['Informational'] + ', indexLabel: "Informational" },')
        except:
            m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Informational"}, ')
        m_chart_data=m_chart_data+''']}]});chart.render();'''


        m_chart=m_chart+m_chart_data



        html_data=html_data+('\t</div>\n')

        html_data=html_data+('\t\t<div align="center" id="host_vuln_info"><table><tr><td id="chart">\n')

        html_data = html_data + ('\t\t\t<div class="vuln_chart" id="chartContainer' + str(h_count) + '"></div></td><td id="v_info">\n')

        html_data=html_data+('\t\t\t<div><h4>VULNERABILITY SUMMARY</h4>\n')
        html_data=html_data+('\t\t\t<table id="host_vuln_summary">\n')
        v_sl=1
        #html_data=html_data+('\t\t\t\t<tr><th>SL</th><th>SERVERITY</th><th>VULNERABILITY NAME</th><th>SCORE</th><th>AFFECTED PORT</th><th>CLASSIFICATION</th></tr>\n')
        html_data=html_data+('\t\t\t\t<tr><th>SL</th><th>SERVERITY</th><th>VULNERABILITY NAME</th><th>SCORE</th><th>AFFECTED PORT</th></tr>\n')
        for v in vuln:
            #print(v_sl,v['risk'],v['name'],v['score'],v['port'])
            html_data=html_data+('\t\t\t\t<tr class="'+str(v['risk']).lower()+'">')
            html_data=html_data+('<td id="sl">'+str(v_sl)+'</td>')
            html_data=html_data+('<td id="risk">'+str(v['risk'])+'</td>')
            html_data=html_data+('<td id="name"><a href="#'+str(v['name']).lower().strip().replace(' ','_')+'">'+str(v['name'])+'</a></td>')
            html_data=html_data+('<td id="score">'+str(v['score'])+'</td>')
            html_data=html_data+('<td id="port">'+str(v['port'])+'</td>')
            ref=[]
            for r in str(v['ref']).split(','):
                if r.strip().upper().startswith('CVE'):
                    ref.append('<a target="_blank" href="https://nvd.nist.gov/vuln/detail/'+str(r).strip().upper()+'">'+str(r)+'</a>')
                if r.strip().upper().startswith('CWE'):
                    ref.append('<a target="_blank" href="https://cwe.mitre.org/data/definitions/'+str(r).strip().split(":")[-1].strip()+'.html">'+str(r)+'</a>')
                if r.strip().upper().startswith('CERT'):
                    ref.append('<a target="_blank" href="https://www.kb.cert.org/vuls/id/'+str(r).strip().split(":")[-1].strip()+'.html">'+str(r)+'</a>')
            #html_data=html_data+('<td id="ref">'+str("<br>".join(map(str,ref)))+'</td>')
            html_data=html_data+('</tr>\n')

            v_sl+=1
        html_data=html_data+('\t\t</table></div></td></tr></table></div>\n')



    #print(html_data)
    temp_data=''

    vulnerabilities = [dict(y) for y in set(tuple(x.items()) for x in vulnerabilities)]
    vulnerabilities = (sorted(vulnerabilities, key=lambda item: item['score'], reverse=True))
    v_name=[dict(y) for y in set(tuple(x.items()) for x in v_name)]

    temp_data = temp_data + ('\t\t\t\n')

    temp_data=temp_data+('\t\t\t\t<div align="center" id="total_vuln"><h2>TOTAL VULNERABILITIES FOUND</h2><div class="vuln_chart" id="mainChart"></div><table id="total_vuln">')
    temp_data=temp_data+('\t\t\t\t<tr><th>SL</th><th>SERVERITY</th><th>VULNERABILITY NAME</th><th>AFFECTED SYSTEM</th><th>SCORE</th><th>CLASSIFICATION</th></tr>\n')

    v_sl=0
    for v in vulnerabilities:
        host=[]
        for v2 in v_name:
            if str(v['name'])==str(v2['name']):
                host.append(v2['host'])
        host=list(set(host))
        v_sl+=1
        temp_data=temp_data+('\t\t\t\t<tr class="' + str(v['risk']).lower() + '">')
        temp_data=temp_data+ ('<td id="sl">' + str(v_sl) + '</td>')
        temp_data=temp_data +('<td id="risk">' + str(v['risk']) + '</td>')
        temp_data=temp_data +(
                    '<td id="name"><a href="#' + str(v['name']).lower().strip().replace(' ', '_') + '">' + str(
                v['name']) + '</a></td>')
        x=[]
        for h in host:
            x.append('<a href="#'+str(h).lower().replace('.','_')+'">'+h+'</a>')
        temp_data=temp_data+('<td id="system">' + str("<br>".join(map(str, x))) + '</td>')
        temp_data=temp_data +('<td id="score">' + str(v['score']) + '</td>')
        ref = []
        for r in str(v['ref']).split(','):
            if r.strip().upper().startswith('CVE'):
                ref.append(
                    '<a target="_blank" href="https://nvd.nist.gov/vuln/detail/' + str(r).strip().upper() + '">' + str(
                        r) + '</a>')
            if r.strip().upper().startswith('CWE'):
                ref.append(
                    '<a target="_blank" href="https://cwe.mitre.org/data/definitions/' + str(r).strip().split(":")[
                        -1].strip() + '.html">' + str(r) + '</a>')
            if r.strip().upper().startswith('CERT'):
                ref.append('<a target="_blank" href="https://www.kb.cert.org/vuls/id/' + str(r).strip().split(":")[
                    -1].strip() + '.html">' + str(r) + '</a>')
        temp_data=temp_data+('<td id="ref">'+str("<br>".join(map(str,ref)))+'</td>')
        temp_data=temp_data +('</tr>\n')
    temp_data=temp_data+('</table></div>\n')


    summary = {}
    for i in Counter(map(itemgetter('risk'), vulnerabilities)).most_common():
        summary[i[0]] = str(i[1])
        #print(i)

    m_chart_data = '''CanvasJS.addColorSet("mycolor",["#8b0000","#ff0000","#daa520","#b2ec5d","#00ced1"]);
    var chart = new CanvasJS.Chart("mainChart",
    {colorSet: "mycolor",title:{text: ""}, data: [{indexLabelPlacement: "outside",type: "pie",showInLegend: true,toolTipContent: "{y} - #percent %",yValueFormatString: "count ,#",legendText: "{indexLabel}",
            dataPoints: [
            '''
    try:
        m_chart_data = m_chart_data + str('{  y: ' + summary['Critical'] + ', indexLabel: "Critical" },')
    except:
        m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Critical"}, ')
    try:
        m_chart_data = m_chart_data + str('{  y: ' + summary['High'] + ', indexLabel: "High" },')
    except:
        m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "High"}, ')
    try:
        m_chart_data = m_chart_data + str('{  y: ' + summary['Medium'] + ', indexLabel: "Medium" },')
    except:
        m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Medium"}, ')
    try:
        m_chart_data = m_chart_data + str('{  y: ' + summary['Low'] + ', indexLabel: "Low" },')
    except:
        m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Low"}, ')
    try:
        m_chart_data = m_chart_data + str('{  y: ' + summary['Informational'] + ', indexLabel: "Informational" },')
    except:
        m_chart_data = m_chart_data + str('{  y: 0 , indexLabel: "Informational"}, ')
    m_chart_data = m_chart_data + ''']}]});chart.render();'''
    m_chart = m_chart + m_chart_data

    vuln_data='<h2>VULNERABILITY DETAILS</h2>'
    vuln_data=vuln_data+('\t\t<div id="vuln_summ" align="center">\n')
    for v in vulnerabilities:
        #print(v.keys())

        vuln_data=vuln_data+('\t\t\t<table class="'+str(v['risk']).lower()+'">\n')

        vuln_data=vuln_data+('\t\t\t\t<tr id="name"><td colspan=3 ><span id="'+str(v['name']).lower().strip().replace(' ','_')+'">'+str(v['name'])+'</span>\n')
        vuln_data=vuln_data+('\t\t\t\t<br><span id="point">Category : </span><span id="risk">'+str(v['risk'])+'</span></td></tr>\n')
        vuln_data=vuln_data+('\t\t\t\t<tr id="cvss"><td colspan=3><span id="score">'+str(v['score'])+'</span><span id="string">'+str(v['string'])+'</span></td></tr>\n')
        vuln_data=vuln_data+('\t\t\t\t<tr><th>Description</th><th>Impact</th><th>Solution</th></tr>\n')
        vuln_data=vuln_data+('\t\t\t\t<tr id="details_info">\n')
        vuln_data=vuln_data+('<td td="desc">'+str(v['desc']).replace('\n','<br>').replace(';','<br>')+'</td>')
        vuln_data=vuln_data+('<td td="imp">'+str(v['imp']).replace('\n','<br>').replace(';','<br>')+'</td>')
        vuln_data=vuln_data+('<td td="sol">'+str(v['sol']).replace('\n','<br>').replace(';','<br>')+'</td>')
        vuln_data=vuln_data+('</tr>\n')
        vuln_data=vuln_data+('\t\t\t\t<tr id="poc"><td id="point">Output</td><td id="info" colspan=2>'+str(v['output'])+'</td></tr>\n')

        link=[]
        for l in str(v['link']).split(','):
            link.append('<a target="_blank" href="'+l+'">'+l+'</a>')

        vuln_data=vuln_data+('\t\t\t\t<tr id="ref"><td id="point">References</td><td colspan=2 id="details">'+str("<br>".join(link))+'</td></tr>\n')
        vuln_data=vuln_data+('\t\t\t</table>\n')

    vuln_data=vuln_data+('\t\t</div>\n')


    html_data='<html><head><meta http-equiv="refresh" content="60"/><link rel="stylesheet" type="text/css" href="newx.css"><script type="text/javascript">function demo() {'+str(m_chart)+'}</script><script type="text/javascript" src="https://canvasjs.com/assets/script/canvasjs.min.js"></script></head><body onload="demo()">'+temp_data+html_data+vuln_data+'</body></html>'
    return (html_data)
