from rng import *
from math import sqrt, pow
from sort import *
from time import perf_counter

class DataSet:

    # For now, assumes ints and floats for data types... should convert strings to numbers if possible, fail to empty state otherwise.

    # TODO Rename comparison function to something more intuitive. Pulls out a value rather than compares stuff. Merge sort compares VALUES, not comparisons.
    def __init__(self, label=None, collection=None, calc=False, sort=False, valueFunction=None):

        self.type = None # Marks what kind of data the object is working with.
        self.label = label if label is not None else "No Label"        # Name/ID of the dataset. Useful for searching.
        self.collection = collection if collection is not None else [] # Local dataset. Pretty intuitive.
        self.scollection = [] # Sorted dataset. If dictionary object type, sorts require a quality to sort by. valueFunction should handle that.
        self.outlierSensitivity = 3 # Value for changing sensitivity to anomalies. Lower values = more sensitive, Higher values = less sensitive.
        self.valueFunction = valueFunction # Value for comparing passed dictionaries to each other. Not used if passed data is only floats/ints.

        self.size = -1  # Contains the number of elements in collections. len() does this, but recomputing is more expensive than storing the value.
        self.min = 1e99 # Lowest number in the dataset.
        self.max = -1e99# Highest number in the dataset.
        self.range = -1 # Difference between highest and lowest. Indicates the area that values inside the dataset exist between.
        self.average = 0.0   # Average value of the dataset. Indicates a sort of weighted center.
        self.variance = -1.0 # Indicates how far from the average the values in the dataset tend to be.
        self.stddev = -1.0   # Same as variance, but smaller and easier to read. Useful for outlier detection through z scores.

        self.q1 = 0.0
        self.median = 0.0 # Middle-of-the-dataset value. Should represent the center of spread for datasets. Q1 and Q3 represent similar values at the 1st and 3rd quarter.
        self.q3 = 0.0
        self.iqr = 0.0    # Inter-Quartile Range. Defines a useful cutoff for outlier detection when combined with MAD.
        self.mad = 0.0    # Median absolute deviation. Represents the median value of all deviations from the median. Useful for outlier detection.

        # Checks to make sure all data passed into initialization is an integer or float... soon to take datapoint class.
        if(len(self.collection) > 0):
            if(isinstance(self.collection[0], int) or isinstance(self.collection[0], float)):
                for i in range(len(self.collection)):
                    if(not isinstance(self.collection[i], int) and not isinstance(self.collection[i], float)):
                        print(f"Failed type checking during iteration... found \"{self.collection[i]}\" instead of an int or float.")
                        raise TypeError
                self.type = int
            elif(isinstance(self.collection[0], dict)): # This... is gonna require a very thorough set of compatibility checking.
                for i in range(len(self.collection)):
                    if(not isinstance(self.collection[i], dict)):
                        print(f"Failed type checking during iteration... found a {type(self.collection[i])} instead of a dictionary object.")
                        raise TypeError
                self.type = dict
            else:
                print("Failed inital type check. Please pass datasets containing ints/floats or dictionary objects!")
                raise TypeError

        # Checks whether or not to find all relevant data now
        if(calc == True):
            self.calculate()
            if(sort == False):
                self.destroySorted()

        # Checks whether or not to sort all data now
        if(self.collection != [] and sort == True):
            self.sortData()

    def resetStats(self):
        self.size = -1
        self.min = 1e99
        self.max = -1e99
        self.range = -1
        self.average = 0.0
        self.variance = -1.0
        self.stddev = -1.0

        self.q1 = 0.0
        self.median = 0.0
        self.q3 = 0.0
        self.iqr = 0.0
        self.mad = 0.0

    def destroySet(self, keepStats=True):
        self.collection = []
        self.scollection = []
        self.type = None
        if(keepStats == False):
            self.resetStats()

    def destroySorted(self):
        self.scollection = []

    def calculate(self):         # Calculates *all* values.
        self.findRange()         # Implicitly calls min and max
        self.findStdDeviation()  # Implicitly calls average and variance
        self.findMAD()           # Implicitly calls sort, Q1, Median, Q3, and IQR

    def sortData(self):
        if(self.collection != [] and self.scollection == []):
            if(self.valueFunction == None):
                self.scollection = mergeSort(self.collection)
            else:
                self.scollection = mergeSort(self.collection, valueFunction=self.valueFunction)

    def findMin(self):
        self.min = 1e99
        self.size = len(self.collection)
        if (self.type == int):
            for i in range(self.size):
                if(self.collection[i] < self.min):
                    self.min = self.collection[i]
        elif (self.type == dict):
            for i in range(self.size):
                if(self.valueFunction(self.collection[i]) < self.min):
                    self.min = self.valueFunction(self.collection[i])
        return self.min

    def findMax(self):
        self.max = -1e99
        self.size = len(self.collection)
        if (self.type == int):
            for i in range(self.size):
                if(self.collection[i] > self.max):
                    self.max = self.collection[i]
        elif (self.type == dict):
            for i in range(self.size):
                if(self.valueFunction(self.collection[i]) > self.max):
                    self.max = self.valueFunction(self.collection[i])
        return self.max

    def findRange(self):
        self.max = self.findMax()
        self.min = self.findMin()
        self.range = self.max - self.min
        return self.range

    def findAverage(self):
        self.size = len(self.collection)
        total = 0.0
        if (self.type == int):
            for i in range(self.size):
                total += self.collection[i]
            self.average = float(total) / float(self.size)
        elif (self.type == dict):
            for i in range(self.size):
                total += self.valueFunction(self.collection[i])
            self.average = float(total) / float(self.size)
        return self.average

    def findVariance(self):
        self.average = self.findAverage()
        self.size = len(self.collection)
        total = 0.0
        if (self.type == int):
            for i in range(self.size):
                total += pow((self.collection[i] - self.average), 2)
            self.variance = total / (self.size)
        elif (self.type == dict):
            for i in range(self.size):
                total += pow((self.valueFunction(self.collection[i]) - self.average), 2)
            self.variance = total / self.size
        return self.variance

    def findStdDeviation(self):
        self.variance = self.findVariance()
        self.stddev = sqrt(self.variance)
        return self.stddev

    def zscoreOf(self, value): # Will trust that data exists.
        return abs((value - self.average) / self.stddev)

    def findMedian(self):
        self.sortData()
        center = int(len(self.scollection) / 2) # Rounds up...
        if(len(self.collection) % 2 == 0):
            if (self.type == int):
                self.median = (self.scollection[center] + self.scollection[center - 1]) / 2
            elif (self.type == dict):
                self.median = (self.valueFunction(self.scollection[center]) + self.valueFunction(self.scollection[center - 1])) / 2
        else:
            if (self.type == int):
                self.median = self.scollection[center]
            elif (self.type == dict):
                self.median = self.valueFunction(self.scollection[center])

    def findQ1(self):
        self.sortData()
        quarter = int(int(len(self.scollection) / 2) / 2) # Should find 1st Quartile
        if (self.type == int):
            self.q1 = self.scollection[quarter]
        elif (self.type == dict):
            self.q1 = self.valueFunction(self.scollection[quarter])

    def findQ3(self):
        self.sortData()
        quarter = int(int(len(self.scollection) / 2) / 2) # Should find 3rd Quartile
        quarter = len(self.scollection) - quarter - 1
        if (self.type == int):
            self.q3 = self.scollection[quarter]
        elif (self.type == dict):
            self.q3 = self.valueFunction(self.scollection[quarter])

    def findIQR(self):
        self.sortData()
        self.findQ3()
        self.findQ1()
        self.iqr = abs(self.q3 - self.q1)

    def findMAD(self):
        self.size = len(self.collection)
        self.sortData()
        self.findIQR()
        self.findMedian()
        medians = []
        if (self.type == int):
            for i in range(self.size):
                medians.append(abs(self.scollection[i] - self.median)) # Append median deviation from sorted dataset...
        elif (self.type == dict):
            for i in range(self.size):
                medians.append(abs(self.valueFunction(self.scollection[i]) - self.median))

        center = int(len(self.scollection) / 2) # Rounds up...
        medians = mergeSort(medians)
        if(len(self.collection) % 2 == 0):
            self.mad = (medians[center] + medians[center - 1]) / 2
        else:
            self.mad = medians[center]

    def zmadOf(self, value):
        if(self.mad != 0 or self.mad != 0.0): # Have to handle 0 as the median deviation. Otherwise it's division by 0.
            return abs(0.6745 * (value - self.median)) / self.mad # 0.6745 obeys z scores roughly for bell curves.
        else:                                 # If MAD is 0, then all datapoints MUST be the same. Any deviation from median is an anomaly.
            if(value == self.median):
                return 0.0
            else:
                return self.outlierSensitivity + 1

    def findAnomalies(self):
        self.calculate()
        anomalies = []
        for i in range(self.size):
            value = self.zmadOf(self.collection[i])
            if(value > self.outlierSensitivity):
                anomalies.append(self.collection[i])
        return anomalies

    def removeAnomalies(self, calc=False):
        anomalies = self.findAnomalies()
        for i in range(len(anomalies)):
            found = False
            j = 0
            while not found:
                if (self.collection[j] == anomalies[i]):
                    found = True
                    self.collection.pop(j)
                j += 1
        self.destroySorted()
        if(calc == True):
            self.calculate()

# End of class code...
'''----------------------------------------------------------------------------------------------------------------'''
# Start of testing code...

stop = ""
name = "Sorting by time"
numValues = 20

def returnTime(point):
    return point['time-delta']

while(stop == ""):
    counter = 0
    values = []
    thing = None
    start = perf_counter()

    reinitializeState()
    thing = DataSet(label=name, collection=entropyPool, calc=True)

    finish = perf_counter() - start
    print(f"{'\033[93m'}label={thing.label}")
    print(f"max={thing.max}, min={thing.min}, range={thing.range}, avg={thing.average:.3f}, variance={thing.variance:.3f}, stdDev={thing.stddev:.3f}")
    print(f"median={thing.median}, q1={thing.q1}, q3={thing.q3}, iqr={thing.iqr}, MAD={thing.mad}")

    print(f"{'\033[94m'}Total Generation Time: {'\033[91m'}{finish:.5f}s\n")
    print(f"{'\033[94m'}---------------------------------------------------------------------------------------")
    stop = str(input())
