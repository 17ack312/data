import requests,sys,os


def encrypt(text):
    #url='https://online-toolz.com//functions/ENCRYPT.php'
    url='https://online-toolz.com//functions/TEXT-HEX.php'
    origin=''
    payload="input="+text
    header={
       # 'Cookie':'PHPSESSID=680at9it9k24ptc30aga74l5r2; __gads=ID=9211ec0e3d182f6b-22585b831ad00025:T=1642797007:RT=1642797007:S=ALNI_MYchLzCDAnleLuXl9ijfm8CdUayiw; _ga_JY9C3TP5R4=GS1.1.1642797016.1.0.1642797016.0; _ga=GA1.2.1468353587.1642797008; _gid=GA1.2.1956302364.1642797019; _gat_gtag_UA_16835414_5=1',
        'Content-Type':'application/x-www-form-urlencoded',
        'Referer': 'https://online-toolz.com/tools/text-encryption-decryption.php',
        'Accept': '*/*',
        'Origin':'https://online-toolz.com',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Dest':'empty'
    }
    res = requests.post(url, data=payload ,headers=header)
    #print(res.content)
    #return(res.content.decode())
    return (res.text)

def decypt(text):
    #url='https://online-toolz.com//functions/DECRYPT.php'
    url = 'https://online-toolz.com//functions/HEX-TEXT.php'
    payload="input="+text
    header={
        #'Cookie':'PHPSESSID=680at9it9k24ptc30aga74l5r2; __gads=ID=9211ec0e3d182f6b-22585b831ad00025:T=1642797007:RT=1642797007:S=ALNI_MYchLzCDAnleLuXl9ijfm8CdUayiw; _ga_JY9C3TP5R4=GS1.1.1642797016.1.0.1642797016.0; _ga=GA1.2.1468353587.1642797008; _gid=GA1.2.1956302364.1642797019',
        'Content-Type':'application/x-www-form-urlencoded',
        'Referer': 'https://online-toolz.com/tools/text-encryption-decryption.php',
        'Accept': '*/*',
        'Origin':'https://online-toolz.com',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Dest':'empty'
    }
    res = requests.post(url, data=payload ,headers=header)
    return (res.text)


print(decypt(sys.argv[1]))