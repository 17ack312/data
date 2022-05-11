import json
import os
import sys
import datetime,time

vulnerabilities=[]

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


def create_summary(data):
    v_names=[];temp=[]
    for d in data:
        hosts={};vulns=[]
        #print(d)
        if len(json.loads(data[d]['vuln']['xss']))>0:
            script=""
            for i in json.loads(data[d]['vuln']['xss']):
                key=list(i.keys())[0]
                script=script+'\n'+key
                #print(i[key])
            t_name,result=xss(script)
            v_names.append(t_name)
            vulnerabilities.append(json.loads(result))
            vulns.append(json.loads(result))
            list(data[d]['vuln']['common']).append(result)


        if len(json.loads(data[d]['vuln']['sql'])) > 0:
            script = ""
            for i in json.loads(data[d]['vuln']['sql']):
                key = list(i.keys())[0]
                script = script + '\n' + key
                #print(i[key])
            t_name, result = sqli(script)
            v_names.append(t_name)
            vulnerabilities.append(json.loads(result))
            vulns.append(json.loads(result))
            list(data[d]['vuln']['common']).append(result)

        if len(json.loads(data[d]['vuln']['rce'])) > 0:
            script = ""
            for i in json.loads(data[d]['vuln']['rce']):
                key = list(i.keys())[0]
                script = script + '\n' + key
                #print(i[key])
            t_name, result = rce(script)
            v_names.append(t_name)
            vulnerabilities.append(json.loads(result))
            vulns.append(json.loads(result))
            list(data[d]['vuln']['common']).append(result)

        if len(json.loads(data[d]['vuln']['ssti'])) > 0:
            script = ""
            for i in json.loads(data[d]['vuln']['ssti']):
                key = list(i.keys())[0]
                script = script + '\n' + key
                #print(i[key])
            t_name, result = ssti(script)
            v_names.append(t_name)
            vulnerabilities.append(json.loads(result))
            vulns.append(json.loads(result))
            list(data[d]['vuln']['common']).append(result)

        for v in data[d]['vuln']['common']:
            v=json.loads(v)
            for v1 in list(v.keys()):
                x={}
                x[v1]=v[v1]
                v_names.append(v1)
                #print(json.dumps(x))
                vulnerabilities.append((x))
                vulns.append(x)
        hosts['host']=d
        hosts['vulns']=vulns
        temp.append(hosts)


    v_names = list(set(v_names))

    return data,temp

def create_HTML(data):
    html_data=''
    data1,data2=create_summary(data)
    vulns=[];v_names=[]

    for v in vulnerabilities:
        x={}
        key=(list(v.keys())[0])
        v_names.append(key)
        x['key']=key
        x['name'] = v[key]['name']
        x['score']=v[key]['score']
        x['risk']=v[key]['risk']
        x['string']=v[key]['string']
        x['desc']=v[key]['desc']
        x['imp']=v[key]['imp']
        x['sol']=v[key]['sol']
        x['ref']=v[key]['ref']
        x['link']=v[key]['link']
        if x not in vulns:
            vulns.append(x)

    vulns = (sorted(vulns, key=lambda item: item['score'], reverse=True))
    v_names=list(set(v_names))

    summary_html="\t<h3>VULNERABILITY SUMMARY</h3>\n"
    summary_html=summary_html+str('\t<div align="center" id="summary" class="summary">\n')
    summary_html=summary_html+str('\t\t<table id="summary">\n')
    summary_html=summary_html+str('\t\t\t<tr id="heading"><th id="sl">SL</th><th id="risk">RISK</th><th id="name">VULNERABILITY NAME</th><th id="score">CVSS SCORE</th><th id="affected">AFFECTED HOSTS</th><th id="refs">CLASSIFICATION</th></tr>\n')
    count=1
    for v in vulns:
        hosts=[]
        #print(v)
        for d in data2:
            for i in (d['vulns']):
                #print(v['key'],list(i.keys())[0])
                if v['key']==list(i.keys())[0]:
                    hosts.append(d['host'])

        hosts=list(set(hosts))
        #print(v['key'],hosts)
        summary_html=summary_html+str('\t\t\t<tr id="'+str(v['risk']).lower().strip()+'"><td id="sl">'+str(count)+'</td><td id="risk">'+str(v['risk']).upper()+'</td><td id="name"><a href="#'+str(v['name']).lower().strip().replace(' ','_')+'">'+str(v['name']).upper().strip()+'</a></td><td id="score">'+str(v['score'])+'</td><td id="affected">'+str("<br>".join(map(str,hosts)))+'</td><td>'+str(v['ref']).replace(',','<br>')+'</td></tr>\n')
        count+=1
    summary_html=summary_html+str('\t\t</table>')
    summary_html=summary_html+str('\t\t</div>')

    host_html="\t<h3>HOST WISE INFORMATION</h3>\n"

    hc=0
    for d1 in data:
        hc+=1
        #print("============================================================================================")
        #print(data[d1].keys())

        start=str(data[d1]['start'])
        end=str(data[d1]['end'])
        s=datetime.datetime(int(start.split(' ')[0].split('-')[0]),int(start.split(' ')[0].split('-')[1]),int(start.split(' ')[0].split('-')[2]),int(start.split(' ')[-1].split('.')[0].split(':')[0]),int(start.split(' ')[-1].split('.')[0].split(':')[1]),int(start.split(' ')[-1].split('.')[0].split(':')[2]))
        e=datetime.datetime(int(end.split(' ')[0].split('-')[0]),int(end.split(' ')[0].split('-')[1]),int(end.split(' ')[0].split('-')[2]),int(end.split(' ')[-1].split('.')[0].split(':')[0]),int(end.split(' ')[-1].split('.')[0].split(':')[1]),int(end.split(' ')[-1].split('.')[0].split(':')[2]))


        host_html=host_html+str('\t<h3 id="'+str(data[d1]['host']).replace('.','_')+'"><span id="sl">'+str(hc)+'.  </span><span id="host"><u>'+str(data[d1]['host'])+'</u></span></h3>\n')

        host_html=host_html+str('\t<div id="host_information" align="center"><table id="host_details"><tr><td>\n')
        host_html=host_html+str('\t<div >\n')
        host_html = host_html + str('\t\t<h4>HOST INFORMATION</h4>\n')
        host_html=host_html+str('\t\t<table id="host_info" class="host_info">\n')
        #host_html=host_html+str('\t\t\t<tr id="host"><td id="bullet">Host</td><td id="info">'+str(data[d1]['host'])+'</td></tr>\n')
        host_html=host_html+str('\t\t\t<tr id="ip"><th id="bullet">IP Address</th><td id="info">'+str(data[d1]['ip'])+'</td></tr>\n')
        if len(str(data[d1]['names']))>0:
            host_html=host_html+str('\t\t\t<tr id="mac"><th id="bullet">Hostnames</th><td id="info">'+"<br>".join(data[d1]['names'])+'</td></tr>\n')
        if len(str(data[d1]['mac']))>0:
            host_html=host_html+str('\t\t\t<tr id="mac"><th id="bullet">MAC Address</th><td id="info">'+str(data[d1]['mac'])+'</td></tr>\n')
        if len(str(data[d1]['os']))>0:
            host_html=host_html+str('\t\t\t<tr id="os"><th id="bullet">Operating System</th><td id="info">'+str(data[d1]['os'])+'</td></tr>\n')

        host_html=host_html+str('\t\t\t<tr id="started"><th id="bullet">Scan Started at</th><td id="info">'+str(data[d1]['start'])+'</td></tr>\n')
        host_html=host_html+str('\t\t\t<tr id="started"><th id="bullet">Scan Finished at</th><td id="info">'+str(data[d1]['start'])+'</td></tr>\n')
        host_html=host_html+str('\t\t\t<tr id="duration"><th id="bullet">Scan Duration</th><td id="info">'+str(e-s)+' Hrs</td></tr>\t')

        host_html=host_html+str('\t\t\t<tr id="urls"><th id="bullet">Found URLs</th><td id="info"><ul>')
        for u in list(set(list(data[d1]['url']))):
            host_html=host_html+str('<li><a href="'+str(u)+'" target="_blank">'+str(u)+'</a></li>')#+'<br>'
        host_html=host_html+str('</ul></tr>\n')
        host_html=host_html+str('\t\t</table>\n')
        host_html = host_html + str('\t</div>\n')

        host_html=host_html+str('\t</td><td>\n')

        host_html = host_html + str('\t<div id="open_port_information">\n')

        host_html = host_html + str('\t\t<h4>OPEN PORT INFORMATION</h4>\n')

        host_html=host_html+str('\t\t<table id="open_ports">\n')
        host_html=host_html+str('\t\t\t<tr><th id="port">PORT</th><th id="port_info">INFORMATION</th></tr>\n')
        for p in list(data[d1]['ports']):
            key=list(p.keys())[0]
            host_html=host_html+str('\t\t\t<tr><td id="port">'+str(key)+'</td><td id="port_info">'+str(p[key])+'</td></tr>\n')
        host_html=host_html+str('\t\t</table>\n')
        host_html = host_html + str('\t</div>\n')
        host_html=host_html+str('\t</td></tr></table></div>\n')
        vuls=[]
        for d2 in data2:
            if str(d2['host'])==str(data[d1]['host']):
                for v in (d2['vulns']):
                    key=list(v.keys())[0]
                    vuls.append(json.dumps(v[key]))
        vuls=list(set(vuls))
        temp=[]
        for v in vuls:
            v=json.loads(v)
            temp.append(v)
        vuls=temp
        vuls = (sorted(vuls, key=lambda item: item['score'], reverse=True))

        host_html=host_html+str('\n<div id="clear" style="clear:both;"></div>\n')
        host_html = host_html + str('\t<div align="center" id="vuln_information" >\n')
        host_html = host_html + str('\t\t<h4>VULNERABILITY INFORMATION</h4>\n')
        count=0
        for v in vuls:
            count+=1
            #host_html=host_html+str(v.keys())
            host_html=host_html+str('\t\t<table id="vuln_details" class="'+str(v['risk']).lower()+'">\n')
            host_html=host_html+str('\t\t\t<tr id="vuln_name"><td id="'+str(v['name']).lower().strip().replace(' ','_')+'" colspan=3><span id="bullet">'+str(count)+') </span><span id="info">'+str(v['name']).upper()+'</span></td></tr>\n')
#            host_html=host_html+str('\t\t\t<tr id="vuln_name"><td id="'+str(v['name']).lower().strip().replace(' ','_')+'" colspan=3><span id="bullet">'+str(count)+'. ['+str(v['risk']).upper()+'] </span><span id="info">'+str(v['name']).upper()+'</span></td></tr>\n')
            if str(v['risk']).lower().strip()=='informational':
                host_html=host_html+str('\t\t\t<tr id="cvss"><td colspan=1 id="bullet">CVSS INFO</td><td colspan=2 id="info">N </td></tr>\n')
            else:
                host_html=host_html+str('\t\t\t<tr id="cvss"><td colspan=1 id="bullet">CVSS</td><td colspan=2 id="info">'+str(v['score'])+' '+str(v['string'])+'</td></tr>\n')
            host_html = host_html + str('\t\t\t<tr id="aff_host"><td colspan=1 id="bullet">AFFECTED HOST</td><td colspan=2 id="info">' + str((data[d1]['host'])) + ' [' + str((data[d1]['ip'])) + '] </td></tr>\n')
            if len(str(v['port']))>0:
                host_html = host_html + str('\t\t\t<tr id="aff_port"><td colspan=1 id="bullet">AFFECTED PORT</td><td colspan=2 id="info">' + str(v['port']) + ' ' + str(v['service']) + '</td></tr>\n')
            host_html=host_html+str('\t\t\t<tr id="head_desc"><th id="desc">DESCRIPTION</th><th id="imp">IMPACT</th><th id="sol">SOLUTION</th></tr>\n')
            host_html=host_html+str('\t\t\t<tr id="info_desc"><td id="desc">'+str(v['desc'])+'</td><td id="imp">'+str(v['imp'])+'</td><td id="sol">'+str(v['sol'])+'</td></tr>\n')
            host_html=host_html+str('\t\t\t<tr id="poc"><td colspan=1 id="bullet">PROOF OF CONCEPT</td><td colspan=2 id="info">'+str(v['output'])+'</td></tr>\n')
            if len(str(v['ref'])) > 0:
                host_html=host_html+str('\t\t\t<tr id="classi"><td colspan=1 id="bullet">CLASSIFICATION</td><td colspan=2 id="info">'+str(v['ref'])+'</td></tr>\n')
            if len(str(v['link'])) > 0:
                host_html=host_html+str('\t\t\t<tr id="ref_link"><td colspan=1 id="bullet">MORE INFORMATION</td><td colspan=2 id="info"><ul>')
                for u in str(v['link']).split(','):
                    host_html=host_html+str('<li><a href="'+str(u)+'" target="_blank">'+str(u)+'</a></li>')
                host_html=host_html+str('</ul></td></tr>\n')

            host_html=host_html+str('\t\t</table>\n')
        host_html=host_html+str('\t</div>\n')
    html_data=summary_html+'\n\n'+host_html

    return str(html_data)

def create_XL(data):
	pass

