# Panda Error Based SQLi 

'Panda Error Based SQL injection' (or 'PandaErrorBasedSQLi') is a rudimentary tool for automating 'Errorbased SQL injection' pentest Process, currently specialized in post method, Coded fully in Python, with a few lib.
'Panda Error Based SQLi'는 Error Based SQL injection의 침투테스트를 위한 초보적인 툴이며, 몇몇 라이브러리를 포함한 파이썬으로 코딩하였습니다.
해당 코드의 첫 커밋은 블로그에 상술되어 있습니다. [https://blog.naver.com/panda_university/223286579252]

# Specification
method : POST
parameter(fixed at the moment) : UserId, Password, Submit
Utilized Error Func : extractvalue()
attack format : normaltic' and extractvalue('1', concat(0x3a, (select query))) and '1'='1


# Required library 필요한 라이브러리
1. requests                **[required for sending requests to web]**
2. parse                   [unnecessary at the moment]
3. diff_match_patch        **[used for checking differences between two requests]**
4. bs4 (or BeautifulSoap)  **[used for stripping html tags and etcs]**
5. lxml                    [you need this to use bs4]
6. json                    [unnecessary at the moment]

~~~
pip install requests
pip install parse
pip install diff_match_patch
pip install bs4
pip install lxml
~~~

# Basic Process
This Error Based SQL Injection goes through 7 steps.
1. Find SQLi point [ input : Links and Param(NOT YET) ]
2. select Func [ Choosing func depending on DBMS(NOT YET) ]
3. Attack Format [ no input required ]
4. DB Name, by using "Database()" payload. [ you need to choose which item is the name of a DB ]
5. Table Name, by checking schema [ you need to choose which item is the name of a table ]
6. Column Name, by checking schema [ you need to choose which item is the name of a column ]
7. Row Name [ you need to choose which item is the name of a row ]

# Future Plan
1. Get/POST method selection
2. parameter Customize
3. Function Selection
4. Scanning every column of a table

# Ref.
Rudimentary Algorithm record & explanation(KR) : https://blog.naver.com/panda_university/223286579252
