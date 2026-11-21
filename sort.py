#-----------------------------------------------------------------------------------------------------------|
''' Merge sort '''#                                                                                         |
#-----------------------------------------------------------------------------------------------------------|

def merge(dataset1, dataset2, valueFunction=None):
    if(valueFunction == None):
        valueFunction = lambda x: x

    tempdata = []
    i = 0
    j = 0
    while(i < len(dataset1) and j < len(dataset2)):
        #print(f"compare...\ndataset1={valueFunction(dataset1[i])}\ndataset2={valueFunction(dataset2[j])}")
        if(valueFunction(dataset1[i]) <= valueFunction(dataset2[j])):
            tempdata.append(dataset1[i])
            i += 1
        else:
            tempdata.append(dataset2[j])
            j += 1
    while(i < len(dataset1)):
        tempdata.append(dataset1[i])
        i += 1
    while(j < len(dataset2)):
        tempdata.append(dataset2[j])
        j += 1
    return tempdata

def mergeSort(dataset, valueFunction=None):
    #print(f"comp function = {valueFunction}")
    if (len(dataset) > 2):
        middle = int((len(dataset) / 2))
        tempdata1 = mergeSort(dataset[0:middle], valueFunction=valueFunction)
        tempdata2 = mergeSort(dataset[middle:], valueFunction=valueFunction)
        return merge(tempdata1, tempdata2, valueFunction=valueFunction)

    elif (len(dataset) == 2):
        tempdata1 = [dataset[0]]
        tempdata2 = [dataset[1]]
        return merge(tempdata1, tempdata2, valueFunction=valueFunction)

    else:
        return dataset

#-----------------------------------------------------------------------------------------------------------|
''' Misc Stuff '''#                                                                                         |
#-----------------------------------------------------------------------------------------------------------|

def fixPrecision(num, figs):  # Don't use this for number generation.
    if isinstance(num, float):
        value = bin(num)
    elif isinstance(num, int):
        value = bin(num)
    else:
        return None # Please pass a number into num

    if(not isinstance(figs, int) or figs <= 0):
        return None # Pass an int greater than 0 into figs

    precision = 10 # string length limiter for data analysis
    temp = value[2:]

    if(precision == 0):
        return int(temp)

    difference = len(temp) - precision
    if (difference > 0):
            temp = temp[difference:]
    elif (difference < 0):
        for i in range(abs(difference)):
            temp = "0" + temp
    else:
        return temp
    return temp
