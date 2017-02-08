from p_models import WebappAnalysis
#f = open("/home/vinusha/test.txt",'w')

#for analysis in WebappAnalysis.select().limit(20):
 #   print([analysis.file.title, analysis.vulnerability.id, analysis.risk, analysis.file.packages,
  #      analysis.description or "[]"])

sdk = []
detected_packages = []
def stripPunc(wordList):
    puncList = [",","'","}","{","[","]",":",'"']
    for punc in puncList:
        for word in wordList:
            wordList=[word.replace(punc,'') for word in wordList]
    return wordList

def mapper(doc_name, text):
    result = []
    a = WebappAnalysis.select()
    for analysis in a[800001: 810001]:
        try:
            description = analysis.description.split()
            words = stripPunc(description)
            anal = []
            for word in words:
                include_list = ["com.", "org."]
                for package in include_list:
                    if package in word:
                        anal.append(word)
            sdk.append(list(anal))
        except:
            pass

    for package in sdk:
        detected_packages_app = []
        for sdks in package:
            package_list = sdks.split(",")
            for pack in package_list:
                try:
                    sdk_list = pack.split(".")[1]
                    detected_packages_app.append(sdk_list)
                except:
                    pass
        detected_packages.append(list(set(detected_packages_app)))
    for line in detected_packages:
        for word in line:
            result.append((word, 1))
    return result

def reducer(key, values):
    print("%s : %d" % (key, sum(values)))

def shuffle(detected_packages):
    # sorting the words
    sorted_keys = sorted(detected_packages)
    tmp = ""
    val_list = []
    for i in sorted_keys:
        if i[0] != tmp and tmp != " ":
            #print(tmp, val_list)
            reducer(tmp,val_list)
            val_list = []
            tmp = i[0]
            val_list.append(i[1])
        elif i[0] == tmp or tmp == " ":
            tmp = i[0]
            val_list.append(i[1])
    reducer(tmp,val_list)

text_file_mapper = mapper("test_doc", WebappAnalysis)
shuffle(text_file_mapper)




    
