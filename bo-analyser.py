# coding=utf-8
import array
import json
import operator
import re
import sys

# Each dangerous function and its args
dangerous_fun = {"gets": 1, "strcpy": 2, "strcat": 2, "fgets": 3, "strncpy": 3, "strncat": 3}

program = {}
variables = {}
stack = {}
vulns = []
  
# Loads the variables list and creates the stack
def load_vars():
    global stack
    stack = {"rbp": 0, "ret": 8}

    for function in program:
        variables[function] = []
        for variable in program[function]['variables']:
            variables[function].append(variable)
            address = re.search(r'rbp-(.*)', variable['address']).group(1)
            stack[variable['name']] = -int(address, 16)
    
    stack = sorted(stack.items(), key=operator.itemgetter(0))

def getVarFromAddr(rbp_addr):
    for fun in variables:
        for var in variables[fun]:
            if rbp_addr == var['address']:
                return var

def getStartingPoint(name):
    for element in stack:
        if element[0] == name:
            return element[1]

def updateStack(name, value):
    for i in range(0, len(stack)):
        if stack[i][0] == name:
            aux = list(stack[i])
            aux[1] = value
            stack[i] = tuple(aux)

# Generates a list of all dangerous function and its arguments / scope / address
def simplify():
    s = []

    for fun in program:
        for ins in program[fun]["instructions"]:
            if ins["op"] == "mov" or ins["op"]=="lea":
                if "PTR" in ins["args"]["value"]:
                    pass
                elif "[" in ins["args"]["value"]:
                    s.append(ins["args"]["value"])
                elif "0x" in ins["args"]["value"]:
                    s.append(int(ins["args"]["value"], 16))
            
            elif ins["op"] == "call":
                if "plt" in ins["args"]["fnname"]:
                    s.append(fun)
                    s.append(ins["args"]["fnname"])
                    s.append(ins["address"])      
    return s

# Emulates execution of dangerous functions
def process(simple):
    global stack
    for i in range(0, len(simple)):

        if simple[i] == "<gets@plt>":
            # Get destination variable and its offset on the stack
            dest = simple[i-3][1:-1]
            dest_var = getVarFromAddr(dest)
            starting_point = -int(re.search(r'rbp-(.*)', dest_var['address']).group(1), 16) # Offset values are stored in base 10

            for element in stack:
                if element[1] > starting_point: # Any data after the destination variable can get corrupted
                    vuln_name = getVulnName(element[1])
                    addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])
            addVuln("SCORRUPTION", dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

        elif simple[i] == "<fgets@plt>":

            dest = simple[i-3][1:-1]
            n = simple[i-2]    
            
            dest_var = getVarFromAddr(dest)

            starting_point = getStartingPoint(dest_var['name'])
            ending_point = starting_point + n

            # Check if elements in stack are in the written area, and detect the corresponding vulnerability
            for element in stack:
                if starting_point < element[1] and element[1] < ending_point:
                    if element[0] != dest_var['name']:
                        vuln_name = getVulnName(element[1])
                        addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])    

            # Check if its past the return address
            if ending_point >= 16:
                addVuln(getVulnName(ending_point), dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])                    

            updateStack(dest_var['name'], ending_point)

        elif simple[i] == "<strcpy@plt>":
            dest = simple[i-2][1:-1]
            source = simple[i-3][1:-1]

            dest_var = getVarFromAddr(dest)
            source_var = getVarFromAddr(source)

            starting_point = getStartingPoint(dest_var['name'])

            for element in stack:
                if element[0] == source_var['name']:
                    init_size = -int(re.search(r'rbp-(.*)', source_var['address']).group(1), 16)
                    ending_point = starting_point - (init_size- element[1])

            for element in stack:
                if starting_point < element[1] and element[1] <= ending_point:
                    if element[0] != dest_var['name']:
                        vuln_name = getVulnName(element[1])
                        addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

            if ending_point >= 16:
                addVuln(getVulnName(ending_point), dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])
                        
            updateStack(dest_var['name'], ending_point)

        elif simple[i] == "<strcat@plt>":
            dest = simple[i-2][1:-1]
            source = simple[i-3][1:-1]
            
            dest_var = getVarFromAddr(dest)
            source_var = getVarFromAddr(source)

            starting_point = getStartingPoint(dest_var['name'])
           
            for element in stack:
                if element[0] == source_var['name']:
                    init_size = -int(re.search(r'rbp-(.*)', source_var['address']).group(1), 16)
                    ending_point = starting_point - (init_size - element[1])
            
            for element in stack:
                if starting_point <= element[1] and element[1] < ending_point:
                    if element[0] != dest_var['name']:
                        vuln_name = getVulnName(element[1])
                        addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

            if ending_point >= 16:
                addVuln(getVulnName(ending_point), dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

            updateStack(dest_var['name'], ending_point)
                                    
        elif simple[i] == "<strncpy@plt>":
            dest = simple[i-3][1:-1]
            source = simple[i-4][1:-1]
            n = simple[i-2]
            
            dest_var = getVarFromAddr(dest)
            source_var = getVarFromAddr(source)

            starting_point = getStartingPoint(dest_var['name'])
            ending_point = starting_point + n
            
            for element in stack:
                if starting_point < element[1] and element[1] < ending_point:
                    if element[0] != dest_var['name']:
                        vuln_name = getVulnName(element[1])
                        addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

            if ending_point >= 16:
                addVuln(getVulnName(ending_point), dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])

            updateStack(dest_var['name'], ending_point)

        elif simple[i] == "<strncat@plt>":
            dest = simple[i-3][1:-1]
            source = simple[i-4][1:-1]
            n = simple[i-2]
            
            dest_var = getVarFromAddr(dest)
            source_var = getVarFromAddr(source)

            starting_point = getStartingPoint(dest_var['name'])
            ending_point = starting_point + n
            
            for element in stack:
                if starting_point <= element[1] and element[1] < ending_point:
                    if element[0] != dest_var['name']:
                        vuln_name = getVulnName(element[1])
                        addVuln(vuln_name, dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])
                
            if ending_point >= 16:
                addVuln(getVulnName(ending_point), dest_var["name"], element[0], simple[i-1], simple[i+1], simple[i])
                    
            updateStack(dest_var['name'], ending_point)

# Each register is 8 bytes long
def getVulnName(ending_point):
    if ending_point < 0:
        return 'VAROVERFLOW'
    if 0 <= ending_point and ending_point < 8:
        return 'RBPOVERFLOW'
    if 8 <= ending_point and ending_point < 16:
        return 'RETOVERFLOW'
    if ending_point >= 16:
        return 'SCORRUPTION'

# Appends new vulnerability to the JSON output object
def addVuln(vulnerability, overflow_var, overflown_var, vuln_function, address, fnname):
    v = {}
    v['vulnerability'] = vulnerability
    v['overflow_var'] = overflow_var
    v['vuln_function'] = vuln_function
    v['address'] = address
    v['fnname'] = fnname[1:-5]

    if vulnerability == 'VAROVERFLOW':
        v['overflown_var'] = overflown_var
    elif vulnerability == 'SCORRUPTION':
        v['overflown_address'] = "rbp+0x10" # Already off the stack frame of main

    vulns.append(v)

def usage():
    print "Instituto Superior Tecnico - Segurança em Software"
    print "BufferOverflow Analysis Tool by Group 19"
    print ""
    print "Usage:"
    print "       python ./bo-analyser.py <program.json>"
    print ""
    sys.exit()

def main():
    global program
    if(len(sys.argv) != 2):
        usage()
    
    with open(sys.argv[1]) as infile:
        program = json.load(infile)

    load_vars()
    process(simplify())

    outputFileName = sys.argv[1][:-5] + ".output.json"
    with open(outputFileName, "w") as f:
        json.dump(vulns, f, indent=4)
        f.close()
    
if __name__ == "__main__":
    main()
