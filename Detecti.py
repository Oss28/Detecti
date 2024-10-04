#!/usr/bin/env python3

import subprocess
import sys
import json
import argparse
from array import array
import subprocess
from array import array
import networkx as nx
import matplotlib.pyplot as plt
import argparse

#get the parameters for tool execution
def main():
	parser = argparse.ArgumentParser(description='Example script with -v parameter and file name')
	parser.add_argument('file', metavar='file', type=str, help='The file name')
	parser.add_argument('-v', '--verbose', action='store_true', help='Enable the verbose mode')
	parser.add_argument('-s', '--sel_vuln', type=str, help='Comma-separated list of vulnerabilities to check (e.g., "1,2")')
	parser.add_argument('-a', '--sel_alerts', type=str, help='Comma-separated list of tuples/alerts to check (e.g., "1,2"), otherwise a for all')
	args = parser.parse_args()
	return args.file, args.verbose, args.sel_vuln, args.sel_alerts

file_name, verbose_modality, vulnerability_selection, alert_selection= main()

#craft the command to be executed
command = 'surya parse -j'
command = command + " " + file_name	

#execute parsing
output = subprocess.check_output(command, shell=True, text=True)

json_string = json.dumps(output, indent=2)

#transform string into json object
contract_json = json.loads(output)
json_string = json.dumps(contract_json, indent=2)

################################################### various functions for CFG creation
def extract_text_after_rankdir_LR(text):
    before_rankdir_LR = text.split("rankdir=LR")[0]
    after_last_bracket = before_rankdir_LR.rsplit("}", 1)[-1]
    return after_last_bracket.strip()

def extract_calls(text):
    lines = text.strip().split('\n')
    calls = []
    for line in lines:
        if '->' in line:
            caller, callee = line.strip().split('->')
            caller = caller.strip().strip('"')
            callee = callee.strip().split('[')[0].strip().strip('"')
            calls.append((caller, callee))

    return calls

def add_call_to_graph(graph, call):
    caller, callee = call
    graph.add_node(caller)
    graph.add_node(callee)
    graph.add_edge(caller, callee)
####################################################
#build CFG

cfg = False
try:
	command = 'surya graph ' + file_name
	output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.PIPE)
	extracted_text = extract_text_after_rankdir_LR(output)
	calls = extract_calls(extracted_text)
	G = nx.DiGraph()
	for call in calls:
		add_call_to_graph(G, call)
	#nx.draw(G, with_labels=True, node_color='lightblue', node_size=1000, font_size=10, font_weight='bold', arrowsize=20)
	#plt.show()
	G_inverted = G.reverse()
	cfg=True
except subprocess.CalledProcessError:
    print("\033[91mError during CFG generation with Surya\033[0m")
except Exception:
    print("\033[91mAn error occurred\033[0m")

#print tool name: Detecti
pixel_art_detecti = """
|||||\\\\    ||\\\\\\\\\\ /////||\\\\\\\\\\ ||\\\\\\\\\\   //|||| /////||\\\\\\\\\\  ||
||    \\\\   ||		||	||       //  	      ||       ||
||     ||  |||||||	||	|||||||	||	      ||       ||
||    //   ||		||	||	 \\\\	      ||       ||
|||||//    ||/////	||	||/////	  \\\\||||      ||       ||
"""

print(pixel_art_detecti)

print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
print("DESCRIPTION OF OUTPUT (divided into 3 sections)")
print("1. SINGLE CHECKS: For each part of the code analyzed, it is reported whether the result of the single check assumes it is a true positive (T) or a false positive (F)")
print("2. DETAILED OUTPUT: It is possible to find more detailed notes of what was found in the analysis regarding FPs presence")
print("3. FINAL RESULTS: For each part of the code analyzed, the final verdict (derived from the overall consideration of all checks) is clearly indicated")
print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
        
    
#selection of vulnerabilities to be verified
def select_vulnerabilities(selection_string):
	#selection given through parameter -s
	if selection_string:
		vulnerabilities_selection = [0, 0, 0]
		for num in selection_string.split(','):
			try:
				index = int(num.strip()) - 1
				vulnerabilities_selection[index] = 1
			except ValueError:
				print("!INVALID INPUT!")
				exit()
			except IndexError:
				print("!INVALID INPUT!")
				exit()
		return vulnerabilities_selection
	#if selection not given as command parameter ask the user
	else:
		print("Select which vulnerabilities to check:")
		print("(enter the corresponding numbers, divided by comma)")
		vulnerabilities_selection = [0, 0, 0]
		print("1. Unchecked Return Value")
		print("2. Timestamp Dependence")
		print("3. Reentrancy")
		input_string = input("choice:")
		if all(number.strip().isdigit() for number in input_string.split(',')):
			numbers = [int(num.strip()) for num in input_string.split(',')]
			for val in numbers:
				if val==1:
					vulnerabilities_selection[0]=1
				elif val==2:
					vulnerabilities_selection[1]=1
				elif val==3:
					vulnerabilities_selection[2]=1
			return vulnerabilities_selection
		else:
			print("!INVALID INPUT!")
			exit()

vulnerabilities_selection = select_vulnerabilities(vulnerability_selection)

#UTILITIES
#function to read variables name
def read(dictionary):
		name=""
		value=dictionary
		if isinstance(dictionary, dict):
			if value['type']=='IndexAccess':
				if value['index']['type']=='Identifier' and 'name' in value['base'] and 'name' in value['index']:
					name=value['base']['name'] + "[" + value['index']['name'] + "]"
				elif value['index']['type']=='MemberAccess' and 'name' in value['base'] and 'name' in value['index']['expression']:
					name=value['base']['name'] + "[" + value['index']['expression']['name'] + "." + value['index']['memberName'] + "]"
			elif value['type']=='Identifier':
				name=value['name']
			elif value['type']=='MemberAccess':
				if value['expression']['type']=='Identifier':
					name=value['expression']['name'] + "." + value['memberName']
				elif value['expression']['type']=='IndexAccess' and 'name' in value['expression']['base'] and 'name' in value['expression']['index']:
					name=value['expression']['base']['name'] + "[" + value['expression']['index']['name'] + "]." + value['memberName']
				else:
					name=""
			elif value['type']=='FunctionCall':
				if value['expression']['type']=='Identifier':
					if value['arguments']!=[]:
						name=value['expression']['name']+"("+read(value['arguments'][0])+")"
					else:
						name=value['expression']['name']+"()"
			elif value['type']=='NumberLiteral':
				name=value['number']

			if name!="":
				return name
			else:
				if verbose_modality:
					return "Variable Name not recognized" + str(dictionary)
				else:
					return "Variable Name not recognized"
		return dictionary

#function to identifiy the visibility of a function
visibility=""
def search_visibility(dictionary,cf):
	contr,func = cf.split('.')
	global visibility
	if not isinstance(dictionary, dict):
			return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
					visibility=element['visibility']
				search_visibility(element, cf)
		elif isinstance(value, dict):
			search_visibility(value, cf)

##function to identifiy the modifiers of a function
modifiers={}
def search_modifier(dictionary,cf):
	contr,func = cf.split('.')
	global modifiers
	if not isinstance(dictionary, dict):
			return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
					modifiers=element['modifiers']
				search_modifier(element, cf)
		elif isinstance(value, dict):
			search_modifier(value, cf)

#function to extract all state variables
state_variables=[]
def extract_variables(dictionary):
	if not isinstance(dictionary, dict):
		return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if key=='subNodes':
					if "type" in element and element["type"]=="StateVariableDeclaration":
						state_variables.append(element['variables'][0]['identifier'])
						extract_variables(element)
						continue
					else:
						continue
				extract_variables(element)			
		elif isinstance(value, dict):
			extract_variables(value)

extract_variables(contract_json)

#function to check whether the state is changed after an instruction
check=0
start=0
avoid_loops=[]
inside_cond={}
inside_body=0
stop=False
def state_verification(dictionary, instruction, cf, cond=None, b=0):
	global check
	global start
	global avoid_loops
	global inside_cond
	global inside_body
	global stop
	contr,func = cf.split('.')
	if not isinstance(dictionary, dict):
		return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if key=='subNodes':
					if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
						state_verification(element, instruction, cf, cond, b)
						continue
					else:
						continue
				if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and start==1 and stop==False:
					for var in state_variables:
						if (element['expression']['left']==var or ('base' in element['expression']['left'] and element['expression']['left']['base']==var)):
							check=1
				if 'type' in element and element['type']=="ExpressionStatement" and element['expression']['type']=="FunctionCall" and element['expression']['expression']['type']=="Identifier":
					if element['expression']['expression']['name'] not in avoid_loops:
						avoid_loops.append(element['expression']['expression']['name'])
						state_verification(contract_json, None, contr+"."+element['expression']['expression']['name'], cond, b)
				if 'type' in element and element['type']=="IfStatement":
					state_verification(element, instruction, cf, element['condition'], b)
					continue
				if element==instruction:
					start=1
					if cond!=None:
						inside_cond=cond
					if b!=0:
						inside_body=b
				if 'type' in element and element['type']=="ReturnStatement" and cond==inside_cond and b==inside_body:
					stop=True

				state_verification(element, instruction, cf, cond, b)					
		
		elif isinstance(value, dict):
			if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and (value['expression']['memberName']=='send' or value['expression']['memberName']=='transfer') and len(value['arguments'])==1 and start==1 and stop==False:
				check=1
			if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and start==1 and stop==False:
				check=1
			if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="NameValueExpression" and 'memberName' in value['expression']['expression'] and 'arguments' in value['expression'] and 'value' in value['expression']['arguments']['names'] and start==1 and stop==False:
				check=1
			if 'type' in value and value['type']=="UnaryOperation" and (value['operator']=="delete" or value['operator']=="--" or value['operator']=="++") and start==1 and stop==False:
				for var in state_variables:
					if value['subExpression']['type']=='Identifier' and value['subExpression']==var:
						check=1
					elif value['subExpression']['type']=='IndexAccess' and value['subExpression']['base']['type']=='Identifier' and value['subExpression']['base']==var:
						check=1
					elif value['subExpression']['type']=='IndexAccess' and value['subExpression']['base']['type']=='IndexAccess' and value['subExpression']['base']['base']['type']=='Identifier' and value['subExpression']['base']['base']==var:
						check=1
			if value==instruction:
				start=1
				if cond!=None:
					inside_cond=cond
				if b!=0:
					inside_body=b
			if key=="trueBody":
				state_verification(value, instruction, cf, cond, 1)
				continue
			if key=="falseBody":
				if cond==inside_cond and inside_body==1:
					continue
				else:
					state_verification(value, instruction, cf, cond, 2)
					continue
			state_verification(value, instruction, cf, cond, b)


#function to check whether an event is emitted after an instruction
check2=0
def event_verification(dictionary, instruction, cf, cond=None, b=0):
	global check2
	global start
	global avoid_loops
	global inside_cond
	global inside_body
	global stop
	contr,func = cf.split('.')
	if not isinstance(dictionary, dict):
		return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if key=='subNodes':
					if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
						event_verification(element, instruction, cf, cond, b)
						continue
					else:
						continue
				if 'type' in element and element['type']=="EmitStatement" and start==1 and stop==False:
					check2=1
				if 'type' in element and element['type']=="ExpressionStatement" and element['expression']['type']=="FunctionCall" and element['expression']['expression']['type']=="Identifier":
					if element['expression']['expression']['name'] not in avoid_loops:
						avoid_loops.append(element['expression']['expression']['name'])
						event_verification(contract_json, None, contr+"."+element['expression']['expression']['name'], cond, b)
				if 'type' in element and element['type']=="IfStatement":
					event_verification(element, instruction, cf, element['condition'], b)
					continue
				if element==instruction:
					start=1
					if cond!=None:
						inside_cond=cond
					if b!=0:
						inside_body=b
				if 'type' in element and element['type']=="ReturnStatement" and cond==inside_cond and b==inside_body:
					stop=True

				event_verification(element, instruction, cf, cond, b)					
		
		elif isinstance(value, dict):
			if value==instruction:
				start=1
				if cond!=None:
					inside_cond=cond
				if b!=0:
					inside_body=b
			if key=="trueBody":
				event_verification(value, instruction, cf, cond, 1)
				continue
			if key=="falseBody":
				if cond==inside_cond and inside_body==1:
					continue
				else:
					event_verification(value, instruction, cf, cond, 2)
					continue
			event_verification(value, instruction, cf, cond, b)


parameters=[]
def extract_parameters(dictionary,cf):
	contr,func = cf.split('.')
	global parameters
	if not isinstance(dictionary, dict):
			return 0
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
					for par in element['parameters']:
						parameters.append(par['identifier'])
				extract_parameters(element, cf)
		elif isinstance(value, dict):
			extract_parameters(value, cf)

#function to identify the instruction calling the function containing URV instruction or Ree external call
instruction = {} 
def search_instruction(dictionary,f1,f2):
	contr,func = f1.split('.')
	global instruction
	if not isinstance(dictionary, dict):
		return 0
	global check
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if key=='subNodes':
					if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
						search_instruction(element, f1, f2)
						continue
					else:
						continue
				if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=="Identifier" and element['expression']['name']==f2 and instruction=={}:
					instruction=element
				search_instruction(element, f1, f2)
			
		elif isinstance(value, dict):
			if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier" and value['expression']['name']==f2 and instruction=={}:
				instruction=value
			search_instruction(value, f1, f2)

#variable to use as a comparison to check which variables on which send/call/callcode/delegatecall is called are set to msg.sender
msg_sender={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'sender'}

#function to determine if the condition is checking msg.sender and consequently preventing execution by "common" users
block=0
def blocking_condition(cond):
	global block
	if isinstance(cond, list):
		for con in cond:
			if 'type' in con and con['type']=="BinaryOperation" and (con['operator']=="==" or con['operator']=="!=") and (con['left']==msg_sender or con['right']==msg_sender):
				block=1
				return 0
			for key, value in con.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=="BinaryOperation" and element['operator']=="==" and (element['left']==msg_sender or element['left']==msg_sender):
							block=1
						blocking_condition(element)
					
				elif isinstance(value, dict):
					if 'type' in value and value['type']=="BinaryOperation" and (value['operator']=="==" or value['operator']=="!=") and (value['left']==msg_sender or value['left']==msg_sender):
						block=1
					blocking_condition(value)
	elif isinstance(cond, dict):
		if 'type' in cond and cond['type']=="BinaryOperation" and (cond['operator']=="==" or cond['operator']=="!=") and (cond['left']==msg_sender or cond['right']==msg_sender):
			block=1
			return 0
		for key, value in cond.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						continue
					if 'type' in element and element['type']=="BinaryOperation" and element['operator']=="==" and (element['left']==msg_sender or element['left']==msg_sender):
						block=1
					blocking_condition(element)
				
			elif isinstance(value, dict):
				if 'type' in value and value['type']=="BinaryOperation" and (value['operator']=="==" or value['operator']=="!=") and (value['left']==msg_sender or value['left']==msg_sender):
					block=1
				blocking_condition(value)


#function to determine whether an instruction is subject to some if condition
def search_conditions(dictionary, ident, fc=None, plus=None, cond=None):
    if cond is None:
        cond = []
    
    contr, func = fc.split('.')
    
    if not isinstance(dictionary, dict):
        return 0
    
    global check
    
    for key, value in dictionary.items():
        if isinstance(value, list):
            for element in value:
                if not isinstance(element, dict):
                    continue
                if 'type' in element and element['type'] == 'ContractDefinition' and element['name'] != contr:
                    continue
                if key == 'subNodes':
                    if 'type' in element and element['type'] == 'FunctionDefinition' and (element['name'] == func or (func == "<Fallback>" and element['isFallback']) or (func == "<Constructor>" and element['isConstructor'])):
                        search_conditions(element, ident, fc, plus, cond.copy())
                        continue
                    else:
                        continue
                if 'type' in element and element['type'] == 'IfStatement':
                    new_cond = cond.copy()  # Crea una nuova copia di cond per ogni iterazione
                    new_cond.append(element['condition'])
                    search_conditions(element, ident, fc, 1, new_cond)
                    continue
                search_conditions(element, ident, fc, plus, cond.copy())
                    
        elif isinstance(value, dict):
            if plus == 1 and value == ident:
                check = 1
                blocking_condition(cond)
            search_conditions(value, ident, fc, plus, cond.copy())


#function to determine whether an instruction is subject to some require condition (the require can also be after the instruction)
def search_require(dictionary,ident,fc):
	contr,func = fc.split('.')
	if not isinstance(dictionary, dict):
		return 0
	global check
	for key, value in dictionary.items():
		if isinstance(value, list):
			for element in value:
				if not isinstance(element, dict):
					continue
				if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
					continue
				if key=='subNodes':
					if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
						search_require(element, ident,fc)
						continue
					else:
						continue
				search_require(element, ident,fc)
			
		elif isinstance(value, dict):
			if key=='expression' and 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier" and value['expression']['name']=="require":
				check=1
				blocking_condition(value['arguments'][0])
			search_require(value, ident,fc)
	
################################################################################################################################################
#part of code dealing with UNCHECKED RETURN VALUE vulnerability 
if vulnerabilities_selection[0]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("				/////////////////////////")
	print("				\033[1m UNCHECKED RETURN VALUE\033[0m")
	print("				/////////////////////////")
	print()

	#array to store the information of unchecked return value instructions [instruction_type, c_name, f_name, visibility, target_adr, modifiers, dictionary_ident]
	URV_instructions=[]

	def search_urv_instructions(dictionary, contract_name=None, function_name=None, visibility=None, modifiers=None):
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						continue
					if 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						visibility=element['visibility']
						modifiers=element['modifiers']
						if element['isFallback']== True:
							function_name="<Fallback>"
						elif element['isConstructor']== True:
							function_name="<Constructor>"
					if 'type' in element and element['type']=='ContractDefinition':
						contract_name=element['name']
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						continue
					search_urv_instructions(element, contract_name, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				#send
				if key=="condition" or key=="initialValue" or key=="right":
					continue
				#if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
				if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send':
					URV_instructions.append(("send", contract_name, function_name, visibility, value['expression']['expression'], modifiers, value))
				#call including eth transfer with {}
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call':
					URV_instructions.append(("call", contract_name, function_name, visibility, value['expression']['expression'], modifiers, value))
				#call not involving eth transfer
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='call':
					URV_instructions.append(("call", contract_name, function_name, visibility, value['expression']['expression'], modifiers, value))
				#call.value
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['type']=="MemberAccess" and value['expression']['expression']['memberName']=="call":
					URV_instructions.append(("call.value", contract_name, function_name, visibility, value['expression']['expression']['expression'], modifiers, value))
				#delegatecall
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='delegatecall':
					URV_instructions.append(("delegatecall", contract_name, function_name, visibility, value['expression']['expression'], modifiers, value))
				#callcode
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='callcode':
					URV_instructions.append(("callcode", contract_name, function_name, visibility, value['expression']['expression'], modifiers, value))
				search_urv_instructions(value, contract_name, function_name, visibility, modifiers)
	
	search_urv_instructions(contract_json)

	#obtain the functions calling the functions containing URV in 2 hops
	URV_calling_func_1hop = [None] * len(URV_instructions)
	if cfg == True:
		for i in range(len(URV_instructions)):
			target_function = URV_instructions[i][1] + "." + URV_instructions[i][2]
			try:
				URV_calling_func_1hop[i] = list(nx.dfs_predecessors(G_inverted, source=target_function, depth_limit=1))
			except (KeyError, nx.NetworkXError):
				URV_calling_func_1hop[i] = []

		URV_calling_func_2hops = [[None for _ in range(len(row))] for row in URV_calling_func_1hop]
		for i, sublist in enumerate(URV_calling_func_1hop):
			for j, value in enumerate(sublist):
				try:
					URV_calling_func_2hops[i][j] = list(nx.dfs_predecessors(G_inverted, source=URV_calling_func_1hop[i][j], depth_limit=1))
				except (KeyError, nx.NetworkXError):
					URV_calling_func_2hops[i][j] = []

	#filter calling functions to avoid including loops
	if cfg==True:
		for i, sublist in enumerate(URV_calling_func_1hop[:]):
			for j, value in enumerate(sublist):
				if URV_calling_func_1hop[i][j]==(URV_instructions[i][1]+"."+URV_instructions[i][2]):
					URV_calling_func_1hop[i].pop(j)

		for i, sublist in enumerate(URV_calling_func_2hops[:]):
			for j, subsublist in enumerate(sublist):
				for y, value in enumerate(subsublist):
					if URV_calling_func_2hops[i][j][y]==URV_calling_func_1hop[i][j] or URV_calling_func_2hops[i][j][y]==(URV_instructions[i][1]+"."+URV_instructions[i][2]):
						URV_calling_func_2hops[i][j].pop(y)

	#checks whether there are actually instructions in the code that might seem vulnerable
	if URV_instructions==[]:
		print("No parts of code were found that might appear vulnerable to Unchecked Return Value\n")
	else:
		#function to allow the user to choose which instructions they want to verify
		def tuple_selection(array):
			tuple_to_keep=[]
			global URV_calling_func_1hop
			global URV_calling_func_2hops
			if alert_selection:
				choice=alert_selection
			else:
				print("format: Variable on which function is called, Instruction Type, Contract.Function")
				print("(Those shown indented (if present) are the functions that call the function containing the instruction with the unchecked return value - MAX 2 hops)\n")
				for i, tupla in enumerate(array):
					print(f"{i + 1}. {read(tupla[4])}, {tupla[0]}, {str(tupla[1])}.{str(tupla[2])}")
					if cfg==True and URV_calling_func_1hop[i]!=[]:
						for j,elem in enumerate(URV_calling_func_1hop[i]):
							print(f"	{i + 1}.{j + 1}.{elem}")
							if URV_calling_func_2hops[i][j]!=[]:
								for y,el in enumerate(URV_calling_func_2hops[i][j]):
									print(f"		{i + 1}.{j + 1}.{y + 1}.{el}")
				choice=input("\nInsert the number of the instructions that need to be verified (separated by comma) - put n for none / put a for all:")
			if choice == "a" or choice == "n" or all(number.strip().isdigit() for number in choice.split(',')):
				if choice=="n":
					return tuple_to_keep
				if choice=="a":
					return array
				selected_indexes=[int(index.strip()) - 1 for index in choice.split(',')]
				#print(selected_indexes)
				for indice in selected_indexes:
					if 0<= indice < len(array):
						tuple_to_keep.append(array[indice])

				URV_calling_func_1hop = [URV_calling_func_1hop[i] for i in selected_indexes if 0 <= i < len(URV_calling_func_1hop)]
				URV_calling_func_2hops = [URV_calling_func_2hops[i] for i in selected_indexes if 0 <= i < len(URV_calling_func_2hops)]
				return tuple_to_keep
			else:
				if alert_selection:
					print("!INVALID ARGUMENT FOR TUPLE SELECTION!")
				else:
					print("!INVALID INPUT!")
				print()
				return tuple_selection(array)


		URV_instructions=tuple_selection(URV_instructions)

		#print selected instructions details in case they were chosen through -s parameter
		if alert_selection:
			print("Selected code parts for analysis (target address, instruction type, contract.function):")
			for i, tupla in enumerate(URV_instructions):
					print(f"{i + 1}. {read(tupla[4])}, {tupla[0]}, {str(tupla[1])}.{str(tupla[2])}")
					if cfg==True and URV_calling_func_1hop[i]!=[]:
						for j,elem in enumerate(URV_calling_func_1hop[i]):
							print(f"	{i + 1}.{j + 1}.{elem}")
							if URV_calling_func_2hops[i][j]!=[]:
								for y,el in enumerate(URV_calling_func_2hops[i][j]):
									print(f"		{i + 1}.{j + 1}.{y + 1}.{el}")

		#arrays used in the "Final Results" output - store overall verdict for each URV instruction
		results_URV=array('u',['t']*len(URV_instructions))
		if cfg==True:
			results_URV_calling_1hop = [["t" for _ in row] for row in URV_calling_func_1hop]
			results_URV_calling_2hops = [
				[
					["t" for _ in inner_list] 
					for inner_list in outer_list
				] 
				for outer_list in URV_calling_func_2hops
			]

		print("\n-------------------------------------------------------------------------------\n")
		print("{:<60} {}".format("CHECK", "RESULTS"))
		print()

		#creation of array to store reports
		alert_string = ['' for _ in URV_instructions]
		for i, variable in enumerate(URV_instructions):
			alert_string[i]+="REPORT for "+read(variable[4])+"."+variable[0]+" ("+variable[1]+"."+variable[2]+"):"

##################################################################################################################### FPs VERIFICATION BASED ON FUNCTIONS VISIBILITY 
		print("\033[94m-Function is public/external-\033[0m")
		for i, variable in enumerate(URV_instructions):
			if variable[3] == "private" or variable[3] == "internal":
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i] += f"The visibility of the function \"{variable[2]}\" is {variable[3]}. "
				results_URV[i] = 'f'
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					visibility = ""
					search_visibility(contract_json, URV_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if visibility == "private" or visibility == "internal":
						print("{:<63} {}".format(indent_level_1, "F"))
						results_URV_calling_1hop[i][j] = 'f'
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							visibility = ""
							search_visibility(contract_json, URV_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if visibility == "private" or visibility == "internal":
								print("{:<63} {}".format(indent_level_2, "F"))
								results_URV_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))


		print()

############################################################################################################################# FPs VERIFICATION BASED ON FUNCTIONS MODIFIERS 
		##function to determine whether inside a modifier there are conditions preventing execution
		check=0
		def search_cond_modifier(dictionary,mod):
			if not isinstance(dictionary, dict):
				return 0
			global check
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='ModifierDefinition' and element['name']==mod:
								search_cond_modifier(element, mod)
								continue
							else:
								continue
						if 'type' in element and element['type']=='IfStatement':
							check=1
							blocking_condition(element['condition'])
						search_cond_modifier(element, mod)
					
				elif isinstance(value, dict):
					if key=='expression' and 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier" and value['expression']['name']=="require":
						check=1
						blocking_condition(value['arguments'][0])
					search_cond_modifier(value, mod)

		
		print("\033[94m-Absence of Modifiers preventing execution-\033[0m")
		absolute1=False
		absolute2=False		
		for i, variable in enumerate(URV_instructions):
			absolute1=False
			check=0
			block=0
			for mod in variable[5]:
				search_cond_modifier(contract_json, mod['name'])
			if block==1:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i]+="The modifiers of the function \"" + str(variable[1]) + "\" prevent the execution (check msg.sender). "
				results_URV[i] = 'f'
				absolute1=True
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
				if check==1:
					alert_string[i]+="The modifiers of the function \"" + str(variable[1]) + "\" do NOT appear to prevent execution, but please check their implementations. "
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					modifiers = {}
					check=0
					block=0
					absolute2=False
					search_modifier(contract_json, URV_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					for mod in modifiers:
						search_cond_modifier(contract_json, mod['name'])
					if block==1 or absolute1==True:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_URV_calling_1hop[i][j] = 'f'
						absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							modifiers = {}
							check=0
							block=0
							search_modifier(contract_json, URV_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							for mod in modifiers:
								search_cond_modifier(contract_json, mod['name'])
							if block==1 or absolute2==True:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_URV_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))

		print()

################################################################################################################################## FPs VERIFICATION BASED ON INSTRUCTION SUBJECT TO CONDITIONS 
		print("\033[94m-Instruction not subject to conditions\033[0m")
		print("\033[94m preventing execution (if or require)-\033[0m")
		absolute1=False	
		absolute2=False		
		for i, variable in enumerate(URV_instructions):
			absolute1=False
			check=0
			cond={}
			block=0
			fc=variable[1]+"."+variable[2]
			search_conditions(contract_json,variable[6],fc)
			search_require(contract_json,variable[6],fc)
			if block==1:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i]+="The instruction is subject to some conditions (if or require) preventing the execution of code (check msg.sender). "
				results_URV[i] = 'f'
				absolute1=True
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
				if check==1:
					alert_string[i]+="The instruction is subject to some conditions (if or require) which appear NOT to prevent the execution of the part of the code analyzed, but please check their implementations. "
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					instruction = {}
					absolute2=False
					check=0
					cond={}
					block=0
					search_instruction(contract_json, URV_calling_func_1hop[i][j], URV_instructions[i][2])
					search_conditions(contract_json, instruction, URV_calling_func_1hop[i][j])
					search_require(contract_json, instruction, URV_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if block==1 or absolute1==True:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_URV_calling_1hop[i][j] = 'f'
						absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							instruction = {}
							check=0
							cond={}
							block=0
							c,f = URV_calling_func_1hop[i][j].split('.')
							search_instruction(contract_json, URV_calling_func_2hops[i][j][y], f)
							search_conditions(contract_json, instruction, URV_calling_func_2hops[i][j][y])
							search_require(contract_json, instruction, URV_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if block==1 or absolute2==True:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_URV_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))		

#####################################################################################################################################################FPs VERIFICATION BASED ON TARGET ADDRESS DEFINITION 
		definition="Not Found"
		final_definition="Not Found"
				
		#function to identify how the variable on which send/call/callcode/delegatecall is called is defined
		def search_definition(dictionary,variable_name,fc, ident):
			if not isinstance(dictionary, dict):
				return 0
			global definition
			global final_definition
			contr,func = fc.split('.')
			if variable_name['type']=="FunctionCall" and variable_name['expression']['name']=="payable":
				variable_name=variable_name['arguments'][0]
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								search_definition(element, variable_name, fc, ident)
								continue
							else:
								continue
						if key=="statements":
							if "type" in element and element["type"]=="VariableDeclarationStatement" and "name" in element["variables"][0] and variable_name['type']=="Identifier" and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						search_definition(element, variable_name, fc, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					#condition to check when to stop looking for assignments to the variable, we do not want to consider those after the URV instruction
					if key=='expression' and value==ident:
						final_definition=definition
					search_definition(value, variable_name, fc, ident)

		print()

		#checks whether the variables on which send/call/callcode/delegatecall is called are equal to msg.sender
		print("\033[94m-Variable defined differently\033[0m")
		print("\033[94m from address of msg.sender-\033[0m")
		matching_index1 = -1
		matching_index2 = -1
		absolute1=False
		absolute2=False	
		for i, variable in enumerate(URV_instructions):
			absolute1=False
			matching_index1 = -1
			definition="Not Found"
			final_definition="Not Found"
			search_definition(contract_json,variable[4],variable[1]+"."+variable[2],variable[6])
			if final_definition==msg_sender or variable[4]==msg_sender or (variable[4]['type']=="FunctionCall" and variable[4]['expression']['name']=="payable" and variable[4]['arguments'][0]==msg_sender):
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i]+="The target address is assigned to the address of message sender (possible attacker), thereby falling into self-harm. "
				results_URV[i] = 'f'
				absolute1=True
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
			parameters=[]
			extract_parameters(contract_json, URV_instructions[i][1]+"."+URV_instructions[i][2])
			for index, param in enumerate(parameters):
				if URV_instructions[i][4] == param:
					matching_index1 = index
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					absolute2=False
					matching_index2 = -1
					if matching_index1!=-1:
						instruction={}
						definition="Not Found"
						final_definition="Not Found"
						search_instruction(contract_json, URV_calling_func_1hop[i][j], URV_instructions[i][2])
						par=instruction['arguments'][matching_index1]
						search_definition(contract_json,par,URV_calling_func_1hop[i][j],instruction)
						if absolute1==True or (final_definition==msg_sender or par==msg_sender or (par['type']=="FunctionCall" and par['expression']['name']=="payable" and par['arguments'][0]==msg_sender)):
							print("{:<63} {}".format(indent_level_1, "F"))
							results_URV_calling_1hop[i][j] = 'f'
							absolute2=True
						else:
							print("{:<63} {}".format(indent_level_1, "T"))
						parameters=[]
						extract_parameters(contract_json, URV_calling_func_1hop[i][j])
						for index, param in enumerate(parameters):
							if par == param:
								matching_index2 = index
								#print(f"!!!Target ADR equal to parameter at index {matching_index2}!!!")
					else:
						if absolute1==True:
							print("{:<63} {}".format(indent_level_1, "F"))
							results_URV_calling_1hop[i][j] = 'f'
							absolute2=True
						else:
							print("{:<63} {}".format(indent_level_1, "T"))

					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if matching_index2!=-1:
								instruction={}
								definition="Not Found"
								final_definition="Not Found"
								contr,func = URV_calling_func_1hop[i][j].split('.')
								search_instruction(contract_json, URV_calling_func_2hops[i][j][y], func)
								par=instruction['arguments'][matching_index2]
								search_definition(contract_json,par,URV_calling_func_2hops[i][j][y],instruction)
								if absolute2==True or (final_definition==msg_sender or par==msg_sender or (par['type']=="FunctionCall" and par['expression']['name']=="payable" and par['arguments'][0]==msg_sender)):
									print("{:<63} {}".format(indent_level_2, "F"))
									results_URV_calling_2hops[i][j][y] = 'f'
								else:
									print("{:<63} {}".format(indent_level_2, "T"))
							else:
								if absolute2==True:
									print("{:<63} {}".format(indent_level_2, "F"))
									results_URV_calling_2hops[i][j][y] = 'f'
								else:
									print("{:<63} {}".format(indent_level_2, "T"))

		print()

#####################################################################################################################################FPs VERIFICATION BASED ON INSTRUCTION FOLLOWED BY STATE CHANGE 
		final=""
		#function to extract last instruction of a function
		def last_statement(dictionary, function):
			if not isinstance(dictionary, dict):
				return 0
			global final
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								last_statement(element, function)
								continue
							else:
								continue
						if key=="statements" and value.index(element)==len(value)-1:
							final=element
							if 'type' in element and element['type']=="IfStatement" and "statements" not in element['trueBody']:
								final=element['trueBody']
						last_statement(element, function)
					
				elif isinstance(value, dict):
					last_statement(value, function)

		#checks whether the URV instruction is followed by state chage
		print("\033[94m-Instruction followed by state change-\033[0m")
		absolute1=False	
		absolute2=False		
		for i, variable in enumerate(URV_instructions):
			absolute1=False
			check=0
			start=0
			avoid_loops=[]
			inside_cond={}
			inside_body=0
			stop=False
			fc=variable[1]+"."+variable[2]
			state_verification(contract_json,variable[6],fc)
			if check==0:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i]+="The instruction is not followed by a change in the state of the contract."
				results_URV[i] = 'f'
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
				absolute1=True
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					instruction = {}
					absolute2=False
					check=0
					start=0
					avoid_loops=[]
					inside_cond={}
					inside_body=0
					stop=False
					search_instruction(contract_json, URV_calling_func_1hop[i][j], URV_instructions[i][2])
					state_verification(contract_json, instruction, URV_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if check==0 and absolute1==False:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_URV_calling_1hop[i][j] = 'f'
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
						absolute2=True
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							instruction = {}
							check=0
							start=0
							avoid_loops=[]
							inside_cond={}
							inside_body=0
							stop=False
							c,f = URV_calling_func_1hop[i][j].split('.')
							search_instruction(contract_json, URV_calling_func_2hops[i][j][y], f)
							state_verification(contract_json, instruction, URV_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if check==0 and absolute2==False:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_URV_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))

		print()

######################################################################################################################################################FPs VERIFICATION BASED ON FUNCTION BEING THE CONSTRUCTOR
		print("\033[94m-Function is not the constructor-\033[0m")
		for i, variable in enumerate(URV_instructions):
			if variable[2] == "<Constructor>":
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "F"))
				alert_string[i] += f"The function \"{variable[2]}\" is the constructor (not present in the runtime bytecode, it cannot be called). "
				results_URV[i] = 'f'
			else:
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "T"))
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					contr,func = URV_calling_func_1hop[i][j].split('.')
					if func=="<Constructor>":
						print("{:<63} {}".format(indent_level_1, "F"))
						results_URV_calling_1hop[i][j] = 'f'
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							contr,func = URV_calling_func_2hops[i][j][y].split('.')
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if func=="<Constructor>":
								print("{:<63} {}".format(indent_level_2, "F"))
								results_URV_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))
#########################################################################################################################################

		print("\n-------------------------------------------------------------------------------\n")
		print("                		 DETAILED OUTPUT")
		for i, variable in enumerate(URV_instructions):
			if not alert_string[i].endswith(':'):
				print()
				print(alert_string[i])
				if results_URV[i]=='f' and cfg==True and URV_calling_func_1hop[i] != []:
					for j, elem in enumerate(URV_calling_func_1hop[i]):
						if results_URV_calling_1hop[i][j]=='t':
							print(f"!!!ATTENTION!!! {URV_calling_func_1hop[i][j]}, which is calling {variable[2]}, appears not to match any FP patterns and consequenty is evaluated as a TP, take a look at single checks")
						if URV_calling_func_2hops[i][j] != []:
							for y, el in enumerate(URV_calling_func_2hops[i][j]):
								indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
								if results_URV_calling_2hops[i][j][y]=='t':
									print(f"!!!ATTENTION!!! {URV_calling_func_2hops[i][j][y]}, which is calling {URV_calling_func_1hop[i][j]} (which in turn is calling {variable[2]}), appears not to match any FP patterns and consequenty is evaluated as a TP, take a look at single checks")

		print("\n-------------------------------------------------------------------------------\n")
		print("                       		 FINAL RESULTS\n")

		for i, variable in enumerate(URV_instructions):
			if results_URV[i]=='t':
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "True Positive"))
			elif results_URV[i]=='f':
				print("{:<63} {}".format(f"{i+1}. {read(variable[4])}.{variable[0]}, {variable[1]}.{variable[2]}", "False Positive"))
			if cfg==True and URV_calling_func_1hop[i] != []:
				for j, elem in enumerate(URV_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if results_URV_calling_1hop[i][j]=='t':
						print("{:<63} {}".format(indent_level_1, "True Positive"))
					elif results_URV_calling_1hop[i][j]=='f':
						print("{:<63} {}".format(indent_level_1, "False Positive"))
					if URV_calling_func_2hops[i][j] != []:
						for y, el in enumerate(URV_calling_func_2hops[i][j]):
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if results_URV_calling_2hops[i][j][y]=='t':
								print("{:<63} {}".format(indent_level_2, "True Positive"))
							elif results_URV_calling_2hops[i][j][y]=='f':
								print("{:<63} {}".format(indent_level_2, "False Positive"))

###########################################################################################################################################################
###########################################################################################################################################################

#part of code dealing with TIMESTAMP DEPENDENCE vulnerability 
if vulnerabilities_selection[1]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("				/////////////////////")
	print("				 TIMESTAMP DEPENDENCE")
	print("				/////////////////////")
	print()

	timestamp={'type': 'MemberAccess','expression': {'type': 'Identifier','name': 'block'},'memberName': 'timestamp'}
	now={'type': 'Identifier','name': 'now'}
	alert_string=""

	presence=0
	#function to check whether there is an occurrence of the timestamp within a dictionary
	def timestamp_presence(dictionary,p_c=None):
		global presence
		if dictionary==timestamp or dictionary==now:
			presence=1
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						return 0
					if 'type' in element and element['type']=="FunctionCall" and p_c==1:
						continue
					timestamp_presence(element,p_c)
			elif isinstance(value, dict):
				if 'type' in value and value['type']=="FunctionCall" and p_c==1:
					continue
				if (key=="left" or key=="right") and (value==timestamp or value==now):
					presence=1
				timestamp_presence(value,p_c)

	#array to save information about the instructions in which the timestamp is used [instruc_type, c_name, f_name, f/m, ident, + elements specific for each type of instruction] -> v_name, s or l / count / f_called, n#_par / -
	timestamp_usage=[]
	#counters in case the timestamp is used in different conditions (of the same type) within the same function
	c1=1 #if conditions
	c2=1 #require conditions
	c3=1 #while conditions

	#function to look up where timestamp is used and for what
	def search_timestamp(dictionary, contract_name=None, function_name=None, tipo=None):
		global presence
		global c1
		global c2
		global c3
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						return 0
					if 'type' in element and element['type']=='ContractDefinition':
						contract_name=element['name']
					if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						if element['isFallback']== True:
							function_name="<Fallback>"
						elif element['isConstructor']== True:
							function_name="<Constructor>"
						c1=1
						c2=1
						c3=1
						search_timestamp(element, contract_name, function_name, "function")
						continue
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						function_name=element['name']
						c1=1
						c2=1
						c3=1
						search_timestamp(element, contract_name, function_name, "modifier")
						continue
					#verification definition state variables
					if key=='subNodes' and element['type']=='StateVariableDeclaration':
						presence=0
						timestamp_presence(element["initialValue"])
						if presence==1:
							timestamp_usage.append(("assignment",contract_name,"NA","NA",element,element['variables'][0]['identifier'],"s"))
					#verification variable definition in functions
					if key=='statements' and element['type']=='VariableDeclarationStatement':
						presence=0
						timestamp_presence(element["initialValue"])
						if presence==1:
							timestamp_usage.append(("assignment",contract_name,function_name, tipo, element, element['variables'][0]['identifier'], "l"))
					#check assignments
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
						presence=0
						timestamp_presence(element['expression']['right'])
						if presence==1:
							if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
								timestamp_usage.append(("assignment",contract_name,function_name, tipo, element, element['expression']['left'],"s"))
							else:
								timestamp_usage.append(("assignment",contract_name,function_name, tipo, element, element['expression']['left'],"l"))
							
					#check if conditions
					if key=='statements' and element['type']=='IfStatement':
						presence=0
						timestamp_presence(element["condition"],1)
						if presence==1:
							timestamp_usage.append(("if condition", contract_name,function_name, tipo, element, c1, element["condition"]))
							c1+=1
					#check require conditions
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require':
						presence=0
						timestamp_presence(element['expression']['arguments'][0],1)
						if presence==1:
							timestamp_usage.append(("require condition", contract_name,function_name, tipo, element, c2, element['expression']['arguments'][0]))
							c2+=1
					#check while conditions
					if key=='statements' and element['type']=='WhileStatement':
						presence=0
						timestamp_presence(element["condition"],1)
						if presence==1:
							timestamp_usage.append(("while condition", contract_name,function_name, tipo, element, c3, element["condition"]))
							c3+=1
					#return statements
					if key=='statements' and element['type']=='ReturnStatement':
						presence=0
						timestamp_presence(element["expression"])
						if presence==1:
							timestamp_usage.append(("return statement", contract_name,function_name, tipo, element))
					
					search_timestamp(element, contract_name, function_name, tipo)
			elif isinstance(value, dict):
				#function calls
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier":
					g=0
					for i, par in enumerate(value['arguments']):
						if (par==timestamp or par==now) and g==0:
							if key=="eventCall":
								timestamp_usage.append(("event emission", contract_name,function_name, tipo, value, value['expression']['name'], i))
							elif not value['expression']['name'][0].isupper():
								timestamp_usage.append(("function call", contract_name,function_name, tipo, value, value['expression']['name'], i))
							g=1
				if 'type' in value and value['type']=='IfStatement':
						presence=0
						timestamp_presence(value["condition"],1)
						if presence==1:
							timestamp_usage.append(("if condition", contract_name,function_name, tipo, value, c1, value['condition']))
							c1+=1
				search_timestamp(value, contract_name, function_name, tipo)

	l=0
	search_timestamp(contract_json)

	#checks whether there are actually instructions in the code that might seem vulnerable
	if timestamp_usage==[]:
		print("No parts of code were found that might appear vulnerable to Timestamp Dpendence\n")
	else:
		#function to allow the user to choose which uses of the timestamp to analyze
		def tuple_selection(array):
			tuple_to_keep=[]
			if alert_selection:
				choice=alert_selection
			else:
				print("format: instruction type, function/modifier name (contract), + other parameters specific for instruction type (var. def. name / condition occurrence / func. called / event emitted)\n")
				for i, tupla in enumerate(array):
					if tupla[0]=="assignment":
						print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}")
					elif tupla[0]=="function call" or tupla[0]=="event emission":
						print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}")
					elif tupla[0]=="return statement":
						print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})")
					else:
						print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}")
				choice=input("\nInsert the number of the tuples that need to be verified (separated by comma) - put n for none / put a for all:")
			if choice == "a" or choice == "n" or all(number.strip().isdigit() for number in choice.split(',')):
				if choice=="n":
					return tuple_to_keep
				if choice=="a":
					return array
				selected_indexes=[int(index.strip()) - 1 for index in choice.split(',')]
				for indice in selected_indexes:
					if 0<= indice < len(array):
						tuple_to_keep.append(array[indice])
				return tuple_to_keep
			else:
				if alert_selection:
					print("!INVALID ARGUMENT FOR TUPLE SELECTION!")
				else:
					print("!INVALID INPUT!")
				print()
				return tuple_selection(array)

		timestamp_usage=tuple_selection(timestamp_usage)
		#for t in timestamp_usage:
		#	print("--------------------------")
		#	print(t[4])
		#	print("--------------------------")

		results_TD=array('u',['f']*len(timestamp_usage))
		#print(results_TD)

		alert_string = ['' for _ in timestamp_usage]
		for i, variable in enumerate(timestamp_usage):
			alert_string[i]+=f"REPORT for usage of block timestamp ({variable[0]}) in {variable[3]} {variable[1]}.{variable[2]}:"

		if alert_selection:
			print("Selected code parts for analysis:")
			print("format: instruction type, function/modifier name, + other parameters specific for instruction type (var. def. name / condition containing block timestamp instance / func. called )")
			for i, tupla in enumerate(timestamp_usage):
				if tupla[0]=="assignment":
					print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}")
				elif tupla[0]=="function call":
					print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}")
				elif tupla[0]=="return statement":
					print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})")
				else:
					print(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}")

############################################################################################################################### check of tuples with type condition
		def control_condition(cond):
			global check
			global presence
			if not isinstance(cond, dict):
				return 0
			if "type" in cond and cond["type"]=="BinaryOperation" and cond["operator"]=="==":
				presence=0
				timestamp_presence(cond["left"])
				timestamp_presence(cond["right"])
				if presence==1:
					check=1

			for key, value in cond.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						control_condition(element)
				elif isinstance(value, dict):
					control_condition(value)
		
		for i,t in enumerate(timestamp_usage):
			if t[0]=="if condition" or t[0]=="while condition" or t[0]=="require condition":
				check=0
				control_condition(t[6])
				if check==1:
					results_TD[i]="t"
					#alert_string[i]+=f" The block timestamp is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use."
				#print(f"{i + 1}. {t[0]},{t[3]} {t[2]} ({t[1]}),#{t[5]} -> {results_TD[i]}")

##################################################################################################################### check of tuples with type function call
		#function to check whether a variable appears within an expression (dictionary)
		def variable_presence(dictionary,variable):
			global presence
			if not isinstance(dictionary, dict):
				return 0
			if dictionary==variable:
				presence=1
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						variable_presence(element, variable)
				elif isinstance(value, dict):
					if (key=="left" or key=="right") and value==variable:
						presence=1
					variable_presence(value, variable)
		
		#function to identify variables defined using a specific variable
		sub_var=[]
		def scroll_definitions_local(dictionary,variable_name, cf, ident=None):
			global presence
			global sub_var
			global start
			contr,func = cf.split('.')
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								scroll_definitions_local(element, variable_name, cf, ident)
								continue
							else:
								continue
						
						#verification local variable definition in functions
						if key=='statements' and element['type']=='VariableDeclarationStatement' and start==1:
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], "l", func, element))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and start==1:
							presence=0
							variable_presence(element['expression']['right'],variable_name)
							if presence==1:
								if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
									sub_var.append((element['expression']['left'], "s"))
								else:
									sub_var.append((element['expression']['left'], "l", func, element))	
						if ident!=None and element==ident:
							start=1		

						scroll_definitions_local(element,variable_name, cf, ident)
				elif isinstance(value, dict):
					if ident!=None and value==ident:
						start=1	
					scroll_definitions_local(value,variable_name, cf, ident)


		def scroll_definitions_state(dictionary,variable_name, contr, function_name=None):
			global presence
			global sub_var
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if 'type' in element and element['type']=='FunctionDefinition':
							function_name=element['name']
							if element['isFallback']== True:
								function_name="<Fallback>"
							elif element['isConstructor']== True:
								function_name="<Constructor>"
						
						if key=='subNodes' and element['type']=='StateVariableDeclaration':
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], "s"))
						#verification local variable definition in functions
						if key=='statements' and element['type']=='VariableDeclarationStatement':
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], "l", function_name, element))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
							presence=0
							variable_presence(element['expression']['right'],variable_name)
							if presence==1:
								if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
									sub_var.append((element['expression']['left'], "s"))
								else:
									sub_var.append((element['expression']['left'], "l", function_name, element))				

						scroll_definitions_state(element,variable_name, contr, function_name)
				elif isinstance(value, dict):
					scroll_definitions_state(value,variable_name, contr, function_name)

		alert=0
		alert2=0
		def var_dang_cond(cond,var):
			global alert
			global presence
			if not isinstance(cond, dict):
				return 0
			if "type" in cond and cond["type"]=="BinaryOperation" and cond["operator"]=="==":
				presence=0
				variable_presence(cond["left"],var)
				variable_presence(cond["right"],var)
				if presence==1:
					alert=1

			for key, value in cond.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						var_dang_cond(element,var)
				elif isinstance(value, dict):
					var_dang_cond(value,var)
		
		parameter_value={'type':'Identifier', 'name':'value'}
		def check_dangerous_uses_local(dictionary, var, contr, func, ident=None):
			global start
			global presence
			global alert2
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								check_dangerous_uses_local(element, var, contr, func, ident)
								continue
							else:
								continue	

						if key=='statements' and element['type']=='IfStatement' and start==1:
							var_dang_cond(element["condition"], var)
						#check require conditions
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require' and start==1:
							var_dang_cond(element['expression']['arguments'][0], var)
						#check while conditions
						if key=='statements' and element['type']=='WhileStatement' and start==1:
							var_dang_cond(element["condition"], var)
						if ident!=None and element==ident:
							start=1

						check_dangerous_uses_local(element, var, contr, func, ident)
				elif isinstance(value, dict):
					if ident!=None and value==ident:
						start=1
					if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and len(value['arguments'])==1 and start==1:
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='transfer' and len(value['arguments'])==1 and start==1:
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['type']=="MemberAccess" and value['expression']['expression']['memberName']=="call" and start==1:
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['type']=='MemberAccess' and 'arguments' in value['expression'] and value['expression']['arguments']['identifiers'][0]==parameter_value and start==1:
						presence=0
						variable_presence(value['expression']['arguments']['arguments'][0],var)
						if presence==1:
							alert2=1
					check_dangerous_uses_local(value, var, contr, func, ident)

		def check_dangerous_uses_state(dictionary, var, contr):
			global alert2
			global presence
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='statements' and element['type']=='IfStatement':
							var_dang_cond(element["condition"], var)
						#check require conditions
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require':
							var_dang_cond(element['expression']['arguments'][0], var)
						#check while conditions
						if key=='statements' and element['type']=='WhileStatement':
							var_dang_cond(element["condition"], var)

						check_dangerous_uses_state(element, var, contr)
				elif isinstance(value, dict):
					if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and len(value['arguments'])==1:
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='transfer' and len(value['arguments'])==1:
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['type']=="MemberAccess" and value['expression']['expression']['memberName']=="call":
						presence=0
						variable_presence(value['arguments'][0],var)
						if presence==1:
							alert2=1
					if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['type']=='MemberAccess' and 'arguments' in value['expression'] and value['expression']['arguments']['identifiers'][0]==parameter_value:
						presence=0
						variable_presence(value['expression']['arguments']['arguments'][0],var)
						if presence==1:
							alert2=1
					check_dangerous_uses_state(value, var, contr)
		
		def check_fc_rv(dictionary, var, contr, func, ident=None):
			global start
			global rv
			global f_info
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								check_fc_rv(element, var, contr, func, ident)
								continue
							else:
								continue	

						if key=='statements' and element['type']=='ReturnStatement' and ((element['expression']['type']!="TupleExpression" and element['expression']==var) or (element['expression']['type']=="TupleExpression" and var in element['expression']['components'])):
							rv=1
						if ident!=None and element==ident:
							start=1

						check_fc_rv(element, var, contr, func, ident)
				elif isinstance(value, dict):
					if ident!=None and value==ident:
						start=1
					if key!="eventCall" and 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier" and not value['expression']['name'][0].isupper() and var in value['arguments'] and start==1:
						f_info=(value['expression']['name'],value['arguments'].index(var))
					check_fc_rv(value, var, contr, func, ident)

		def search_usage_rv(dictionary, cf, ident):
			global sub_var
			global presence
			contr,func = cf.split('.')
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							#print("skip contract")
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								search_usage_rv(element, cf, ident)
								continue
							else:
								continue	

						if key=='statements' and element['type']=='VariableDeclarationStatement':
							presence=0
							variable_presence(element["initialValue"],ident)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'],"l",func,element))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
							presence=0
							timestamp_presence(element['expression']['right'])
							variable_presence(element['expression']['right'],ident)
							if presence==1:
								if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
									sub_var.append((element['expression']['left'],"s"))
								else:
									sub_var.append((element['expression']['left'],"l",func,element))

						search_usage_rv(element, cf, ident)
				elif isinstance(value, dict):
					search_usage_rv(value, cf, ident)
		
		related_variables = [[] for _ in timestamp_usage]
		for i,t in enumerate(timestamp_usage):
			if t[0]=="function call":
				parameters=[]
				cf=t[1]+"."+t[5]
				extract_parameters(contract_json,cf)
				var_tainted=parameters[t[6]]
				#print(f"Variabile start: {read(var_tainted)}")
				sub_var=[]
				start=1
				scroll_definitions_local(contract_json,var_tainted, cf)
				for agg in sub_var:
					if agg not in related_variables[i]:
						related_variables[i].append(agg)
				while sub_var!=[]:
					cycle=sub_var
					sub_var=[]
					for vari in cycle:
						if vari[1]=="l":
							cf=t[1]+"."+vari[2]
							start=0
							scroll_definitions_local(contract_json,vari[0],cf,vari[3])
							#additional checks to verifiy if the sub variable is used inside return statements or as parameters in function calls
							rv=0
							start=0
							f_info=("",-1)
							check_fc_rv(contract_json,vari[0],t[1],vari[2],vari[3])
							if rv==1 and cfg==True:
								#print(f"{read(vari[0])} used in return statement")
								try:
									calling_func = list(nx.dfs_predecessors(G_inverted, source=cf, depth_limit=1))
								except (KeyError, nx.NetworkXError):
									calling_func = []
								for func in calling_func:
									instruction={}
									search_instruction(contract_json, func, vari[2])
									var_rv=[]
									search_usage_rv(contract_json,func,instruction)
									alert=0
									alert2=0
									cont,fun = func.split('.')
									start=1
									check_dangerous_uses_local(contract_json,instruction,cont,fun)
									if alert==1:
										#print("used in condition with strict equality")
										results_TD[i]="t"
										#alert_string[i]+=f" The parameter for which the timestamp block is passed ({read(var_tainted)}) is influencing a variable which is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
									if alert2==1:
										#print("used as ETH amount to transfer")
										results_TD[i]="t"
										#alert_string[i]+=f"In the {func} function, the return value of the function {vari[3]}, influenced by block timestamp, is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
							if f_info!=("",-1):
								#print(f"{read(vari[0])} used to call function {f_info[0]}, par: {f_info[1]}")
								parameters=[]
								cf=t[1]+"."+f_info[0]
								extract_parameters(contract_json,cf)
								var_taint=parameters[f_info[1]]
								#print(f"Tainted variable: {read(var_taint)}")
								start=1
								scroll_definitions_local(contract_json,var_taint, cf)
								alert=0
								alert2=0
								start=1
								check_dangerous_uses_local(contract_json,var_taint,t[1],f_info[0])
								if alert==1:
									#print(f"{read(var_taint)} used in condition with strict equality")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
								if alert2==1:
									#print(f"{read(var_taint)} used as ETH amount to transfer")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
						elif vari[1]=="s":
							scroll_definitions_state(contract_json,vari[0],t[1])
						else:
							print("Errore")
							sys.exit()

					for agg in sub_var:
						if agg in related_variables[i]:
							sub_var.remove(agg)
						else:
							related_variables[i].append(agg)
				alert=0
				alert2=0
				start=1
				check_dangerous_uses_local(contract_json,var_tainted,t[1],t[5])
				if alert==1:
					#print(f"{read(var_tainted)} used in condition with strict equality")
					results_TD[i]="t"
					#alert_string[i]+=f"the {read(var_tainted)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
				if alert2==1:
					#print(f"{read(var_tainted)} used as ETH amount to transfer")
					results_TD[i]="t"
					#alert_string[i]+=f"the {read(var_tainted)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
				for v in related_variables[i]:
					#print(read(v[0]))
					alert=0
					alert2=0
					if v[1]=="l":
						start=0
						check_dangerous_uses_local(contract_json,v[0],t[1],v[2],v[3])
					elif v[1]=="s":
						check_dangerous_uses_state(contract_json,v[0],t[1])
					if alert==1:
						#print("used in condition with strict equality")
						results_TD[i]="t"
						#alert_string[i]+=f"the {read(v[0])} variable (which is influenced by the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
					if alert2==1:
						#print("used as ETH amount to transfer")
						results_TD[i]="t"
						#alert_string[i]+=f"the {read(v[0])} variable (which is influenced by the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"

########################################################################################check of tuples with type assignment
		for i,t in enumerate(timestamp_usage):
			if t[0]=="assignment":
				cf=t[1]+"."+t[2]
				var_tainted=t[5]
				sub_var=[]
				if t[6]=="l":
					start=0
					scroll_definitions_local(contract_json,var_tainted, cf, t[4])
				elif t[6]=="s":
					scroll_definitions_state(contract_json,var_tainted, t[1])
				else:
					print("!ERROR!")
					sys.exit()
				sub_var.append((t[5],t[6],t[2],t[4]))
				for agg in sub_var:
					if agg not in related_variables[i]:
						related_variables[i].append(agg)
				while sub_var!=[]:
					cycle=sub_var
					sub_var=[]
					for vari in cycle:
						if vari[1]=="l":
							cf=t[1]+"."+vari[2]
							start=0
							scroll_definitions_local(contract_json,vari[0],cf,vari[3])
							#additional checks to verifiy if the sub variable is used inside return statements or as parameters in function calls
							rv=0
							start=0
							f_info=("",-1)
							check_fc_rv(contract_json,vari[0],t[1],vari[2],vari[3])
							if rv==1 and cfg==True:
								#print(f"{read(vari[0])} used in return statement")
								try:
									calling_func = list(nx.dfs_predecessors(G_inverted, source=cf, depth_limit=1))
								except (KeyError, nx.NetworkXError):
									calling_func = []
								for func in calling_func:
									instruction={}
									search_instruction(contract_json, func, vari[2])
									var_rv=[]
									search_usage_rv(contract_json,func,instruction)
									alert=0
									alert2=0
									cont,fun = func.split('.')
									start=1
									check_dangerous_uses_local(contract_json,instruction,cont,fun)
									if alert==1:
										#print("used in condition with strict equality")
										results_TD[i]="t"
										#alert_string[i]+=f"In the {func} function, the return value of the function {vari[3]}, influenced by block timestamp, is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
									if alert2==1:
										#print("used as ETH amount to transfer")
										results_TD[i]="t"
										#alert_string[i]+=f"In the {func} function, the return value of the function {vari[3]}, influenced by block timestamp, is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
							if f_info!=("",-1):
								#print(f"{read(vari[0])} used to call function {f_info[0]}, par: {f_info[1]}")
								parameters=[]
								cf=t[1]+"."+f_info[0]
								extract_parameters(contract_json,cf)
								var_taint=parameters[f_info[1]]
								#print(f"Tainted variable: {read(var_taint)}")
								start=1
								scroll_definitions_local(contract_json,var_taint, cf)
								alert=0
								alert2=0
								start=1
								check_dangerous_uses_local(contract_json,var_taint,t[1],f_info[0])
								if alert==1:
									#print(f"{read(var_taint)} used in condition with strict equality")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
								if alert2==1:
									#print(f"{read(var_taint)} used as ETH amount to transfer")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
						elif vari[1]=="s":
							scroll_definitions_state(contract_json,vari[0],t[1])
						else:
							print("Errore")
							sys.exit()

					for agg in sub_var:
						if agg in related_variables[i] or agg==t[5]:
							sub_var.remove(agg)
						else:
							related_variables[i].append(agg)
				alert=0
				alert2=0
				if t[6]=="l":
					start=0
					check_dangerous_uses_local(contract_json,var_tainted,t[1],t[2],t[4])
				elif t[6]=="s":
					check_dangerous_uses_state(contract_json,var_tainted,t[1])
				if alert==1:
					#print("used in condition with strict equality")
					results_TD[i]="t"
					#alert_string[i]+=f"the {read(var_tainted)} variable (defined using the timestamp) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
				if alert2==1:
					#print("used as ETH amount to transfer")
					results_TD[i]="t"
					#alert_string[i]+=f"the {read(var_tainted)} variable (defined using the timestamp) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
				for v in related_variables[i]:
					alert=0
					alert2=0
					if v[1]=="l":
						start=0
						check_dangerous_uses_local(contract_json,v[0],t[1],v[2],v[3])
					elif v[1]=="s":
						check_dangerous_uses_state(contract_json,v[0],t[1])
					if alert==1:
						#print("used in condition with strict equality")
						results_TD[i]="t"
						#alert_string[i]+=f"the {read(v[0])} variable (which is defined using directly or indirectly the var. {read(t[5])}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
					if alert2==1:
						#print("used as ETH amount to transfer")
						results_TD[i]="t"
						#alert_string[i]+=f"the {read(v[0])} variable (which is defined using directly or indirectly the var. {read(t[5])}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"


########################################################################################check of tuples with type return value
		
		if cfg == False:
			print("\033[31mAn error occurred in the generation of the CFG, it was not possible to analyze the uses of the block timestamp inside the return statements\033[0m")
		else:
			for i,t in enumerate(timestamp_usage):
				if t[0]=="return statement":
					cf=t[1]+"."+t[2]
					try:
						calling_func = list(nx.dfs_predecessors(G_inverted, source=cf, depth_limit=1))
					except (KeyError, nx.NetworkXError):
						calling_func = []
					for func in calling_func:
						instruction={}
						sub_var=[]
						search_instruction(contract_json, func, t[2])
						sub_var=[]
						search_usage_rv(contract_json,func,instruction)
						alert=0
						alert2=0
						cont,fun = func.split('.')
						start=1
						check_dangerous_uses_local(contract_json,instruction,cont,fun)
						if alert==1:
							#print("used in condition with strict equality")
							results_TD[i]="t"
							#alert_string[i]+=f"In the {func} function, the return value is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
						if alert2==1:
							#print("used as ETH amount to transfer")
							results_TD[i]="t"
							#alert_string[i]+=f"In the {func} function, the return value is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
						if sub_var!=[]:
							for agg in sub_var:
								if agg not in related_variables[i]:
									related_variables[i].append(agg)
							while sub_var!=[]:
								cycle=sub_var
								sub_var=[]
								for vari in cycle:
									if vari[1]=="l":
										cf=t[1]+"."+vari[2]
										start=0
										scroll_definitions_local(contract_json,vari[0],cf,vari[3])
										#additional checks to verifiy if the sub variable is used inside return statements or as parameters in function calls
										rv=0
										start=0
										f_info=("",-1)
										check_fc_rv(contract_json,vari[0],t[1],vari[2],vari[3])
										if rv==1 and cfg==True:
											#print(f"{read(vari[0])} used in return statement")
											try:
												calling_func = list(nx.dfs_predecessors(G_inverted, source=cf, depth_limit=1))
											except (KeyError, nx.NetworkXError):
												calling_func = []
											#print(calling_func)
											for func in calling_func:
												instruction={}
												search_instruction(contract_json, func, vari[2])
												#print(instruction)
												var_rv=[]
												search_usage_rv(contract_json,func,instruction)
												alert=0
												alert2=0
												cont,fun = func.split('.')
												start=1
												check_dangerous_uses_local(contract_json,instruction,cont,fun)
												if alert==1:
													#print("used in condition with strict equality")
													results_TD[i]="t"
													#alert_string[i]+=f"In the {func} function, the return value of the function {vari[3]}, influenced by block timestamp, is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
												if alert2==1:
													#print("used as ETH amount to transfer")
													results_TD[i]="t"
													#alert_string[i]+=f"In the {func} function, the return value of the function {vari[3]}, influenced by block timestamp, is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
										if f_info!=("",-1):
											#print(f"{read(vari[0])} used to call function {f_info[0]}, par: {f_info[1]}")
											parameters=[]
											cf=t[1]+"."+f_info[0]
											extract_parameters(contract_json,cf)
											var_taint=parameters[f_info[1]]
											#print(f"Tainted variable: {read(var_taint)}")
											start=1
											scroll_definitions_local(contract_json,var_taint, cf)
											alert=0
											alert2=0
											start=1
											check_dangerous_uses_local(contract_json,var_taint,t[1],f_info[0])
											if alert==1:
												#print(f"{read(var_taint)} used in condition with strict equality")
												results_TD[i]="t"
												#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
											if alert2==1:
												#print(f"{read(var_taint)} used as ETH amount to transfer")
												results_TD[i]="t"
												#alert_string[i]+=f"the {read(var_taint)} variable (which is the parameter for which the block timestamp is passed in the call to function {t[5]}) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
									elif vari[1]=="s":
										scroll_definitions_state(contract_json,vari[0],t[1])
									else:
										print("Errore")
										sys.exit()

								for agg in sub_var:
									if agg in related_variables[i]:
										sub_var.remove(agg)
									else:
										related_variables[i].append(agg)
							for v in related_variables[i]:
								alert=0
								alert2=0
								if v[1]=="l":
									start=0
									check_dangerous_uses_local(contract_json,v[0],t[1],v[2],v[3])
								elif v[1]=="s":
									check_dangerous_uses_state(contract_json,v[0],t[1])
								if alert==1:
									#print("used in condition with strict equality")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(v[0])} variable (which is influenced by the return value from the {t[2]} function call) is used in a strict equality comparison (supposed to be exploited as a source of randomness) and consequently to be regarded as hazardous use"
								if alert2==1:
									#print("used as ETH amount to transfer")
									results_TD[i]="t"
									#alert_string[i]+=f"the {read(v[0])} variable (which is influenced by the return value from the {t[2]} function call) is used in the definition of the amount of ETH to transfer and consequently to be regarded as hazardous use"
		
		print("\n-------------------------------------------------------------------------------\n")
		print("{:<70} {}".format("CHECK", "RESULTS"))
		print()

		print("\033[94m-Timestamp NOT used EXCLUSIVELY for majority\033[0m")
		print("\033[94m or minority comparisons-\033[0m")
		for i,tupla in enumerate(timestamp_usage):
			if tupla[0]=="assignment":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}", "T"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}", "F"))
			elif tupla[0]=="function call":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}", "T"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}", "F"))
			elif tupla[0]=="return statement":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})", "T"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})", "F"))
			else:
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}", "T"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}", "F"))

		
		print("\n-------------------------------------------------------------------------------\n")
		print("                		 DETAILED OUTPUT")
		for i, variable in enumerate(timestamp_usage):
			if results_TD[i]=="f":
				alert_string[i]+="This use of the block timestamp is limited exclusively to informational purposes (ex.: saving the time of an event) or for the purpose of comparison to verify that an event is occurring within a time interval. From a code perspective, this results in the block timestamp (and the variables it affects) being used exclusively to be returned to the user and/or inside an event emission, and to perform majority and/or minority comparisons."
			if not alert_string[i].endswith(':'):
				print()
				print(alert_string[i])

		print("\n-------------------------------------------------------------------------------\n")	
		print("                       		 FINAL RESULTS\n")
		for i,tupla in enumerate(timestamp_usage):
			if tupla[0]=="assignment":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}", "True Positive"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{read(tupla[5])}", "False Positive"))
			elif tupla[0]=="function call" or tupla[0]=="event emission":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}", "True Positive"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),{tupla[5]}", "False Positive"))
			elif tupla[0]=="return statement":
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})", "True Positive"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]})", "False Positive"))
			else:
				if results_TD[i]=="t":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}", "True Positive"))
				elif results_TD[i]=="f":
					print("{:<73} {}".format(f"{i + 1}. {tupla[0]},{tupla[3]} {tupla[2]} ({tupla[1]}),#{tupla[5]}", "False Positive"))

###########################################################################################################################################################
###########################################################################################################################################################

if vulnerabilities_selection[2]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("				///////////")
	print("\033[1m				REENTRANCY\033[0m")
	print("				//////////")
	print()

	alert_string=""

	print("NOTE: The send and transfer instructions, although they are effectively external calls, are deemed to be out of reentrancy danger due to the forwarded gas limit, set at 2300.\n\n")

	#array to store information about functions possibly vulnerable to Reentrancy
	risky_calls=[]
	
	#list of membername functions which may look external but are not
	exception=["pop","push","add","sub","mul","div","mod","send","value","call"]

	parameter_value={'type':'Identifier', 'name':'value'}

	#function to extract all instructions performing an external call through call or direct reference of external function
	def search_functions(dictionary, contract_name=None, function_name=None):
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						continue
					if 'type' in element and element['type']=='ContractDefinition':
						contract_name=element['name']
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						continue
					if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						if element['isFallback']== True:
							function_name="<Fallback>"
						elif element['isConstructor']== True:
							function_name="<Constructor>"
					if 'type' in element and element['type']=="NameValueExpression" and 'memberName' in element['expression'] and element['expression']['memberName']=='call':
						if 'arguments' in element and element['arguments']['identifiers'][0]==parameter_value:
							risky_calls.append(("call",contract_name, function_name,element['expression']['expression'],element,element['arguments']['arguments'][0]))
						else:
							risky_calls.append(("call",contract_name, function_name,element['expression']['expression'],element,0))
					
					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='MemberAccess' and element['expression']['expression']['type']=='Identifier' and element['expression']['memberName']=='call':
						risky_calls.append(("call",contract_name, function_name,element['expression']['expression'],element,0))

					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='MemberAccess' and element['expression']['expression']['type']=='MemberAccess' and element['expression']['memberName']=='value' and element['expression']['expression']['memberName']=='call':
						risky_calls.append(("call.value",contract_name, function_name,element['expression']['expression']['expression'],element,element['arguments'][0]))
					
					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='MemberAccess' and element['expression']['memberName'] not in exception:
						if element['expression']['memberName']!="transfer" or len(element["arguments"])!=1:
							if element['expression']['expression']['type']!="Identifier" or (element['expression']['expression']['name']!="abi" and element['expression']['expression']['name']!="super" and element['expression']['expression']['name']!="this"):
								risky_calls.append(("direct reference",contract_name, function_name,element['expression']['expression'],element,0))
					
					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='NameValueExpression' and element['expression']['expression']['type']=='MemberAccess' and element['expression']['expression']['memberName'] not in exception:
						if element['expression']['expression']['memberName']!="transfer" or len(element["arguments"])!=1:
							if element['expression']['expression']['expression']['type']!="Identifier" or element['expression']['expression']['expression']['name']!="abi":
								if 'arguments' in element['expression'] and element['expression']['arguments']['identifiers'][0]==parameter_value: 
									risky_calls.append(("direct reference",contract_name, function_name,element['expression']['expression']['expression'],element,element['expression']['arguments']['arguments'][0]))
								else:
									risky_calls.append(("direct reference",contract_name, function_name,element['expression']['expression']['expression'],element,0))
											
					search_functions(element, contract_name, function_name)
			elif isinstance(value, dict):
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call':
					if 'arguments' in value and value['arguments']['identifiers'][0]==parameter_value:
						risky_calls.append(("call",contract_name, function_name,value['expression']['expression'],value,value['arguments']['arguments'][0]))
					else:
						risky_calls.append(("call",contract_name, function_name,value['expression']['expression'],value,0))
				
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['memberName']=='call':
					risky_calls.append(("call.value",contract_name, function_name,value['expression']['expression']['expression'],value,value['arguments'][0]))
				
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['expression']['type']=='Identifier' and value['expression']['memberName']=='call':
					risky_calls.append(("call",contract_name, function_name,value['expression']['expression'],value,0))
				
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName'] not in exception:
					if value['expression']['memberName']!="transfer" or len(value["arguments"])!=1:
						if value['expression']['expression']['type']!="Identifier" or (value['expression']['expression']['name']!="abi" and value['expression']['expression']['name']!="super" and value['expression']['expression']['name']!="this"):
							risky_calls.append(("direct reference",contract_name, function_name,value['expression']['expression'],value,0))

				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['type']=='MemberAccess' and value['expression']['expression']['memberName'] not in exception:
					if value['expression']['expression']['memberName']!="transfer" or len(value["arguments"])!=1:
						if value['expression']['expression']['expression']['type']!="Identifier" or value['expression']['expression']['expression']['name']!="abi":
							if 'arguments' in value['expression'] and value['expression']['arguments']['identifiers'][0]==parameter_value: 
								risky_calls.append(("direct reference",contract_name, function_name,value['expression']['expression']['expression'],value,value['expression']['arguments']['arguments'][0]))
							else:
								risky_calls.append(("direct reference",contract_name, function_name,value['expression']['expression']['expression'],value,0))

				search_functions(value, contract_name, function_name)

	search_functions(contract_json)

	#check which external calls are followed, in the same function, by a state change
	only_event_emis=["f"] * len(risky_calls)
	calls_to_check_raw=[]
	to_remove=[]
	for i,call in enumerate(risky_calls):
		start=0
		check=0
		avoid_loops=[]
		inside_cond={}
		inside_body=0
		stop=False
		state_verification(contract_json,call[4],call[1]+"."+call[2])
		start=0
		check2=0
		avoid_loops=[]
		inside_cond={}
		inside_body=0
		stop=False
		event_verification(contract_json,call[4],call[1]+"."+call[2])
		if check==0 and check2==0:
			calls_to_check_raw.append(call)
			to_remove.append(i)
			only_event_emis[i]="r"
		elif check==0 and check2==1:
			only_event_emis[i]="t"

	for el in reversed(to_remove):
		risky_calls.pop(el)

	while "r" in only_event_emis:
		only_event_emis.remove("r")
	
	
	#check if the externall calls not followed by a state change inside the same function are followed by a state change when the function is called by another function
	cf_to_check=[]
	for call in calls_to_check_raw:
		cf=call[1] + "." + call[2]
		if cf not in cf_to_check:
			cf_to_check.append(cf)

	calling_func_1hop = [None] * len(cf_to_check)
	if cfg == True:
		for i,func in enumerate(cf_to_check):
			try:
				calling_func_1hop[i] = list(nx.dfs_predecessors(G_inverted, source=func, depth_limit=1))
			except (KeyError, nx.NetworkXError):
				calling_func_1hop[i] = []

	to_add=[]
	for i, variable in enumerate(cf_to_check):
		if cfg==True and calling_func_1hop[i] != []:
			for j, elem in enumerate(calling_func_1hop[i]):
				instruction = {}
				check=0
				start=0
				avoid_loops=[]
				inside_cond={}
				inside_body=0
				stop=False
				contr,func = cf_to_check[i].split('.')
				search_instruction(contract_json, calling_func_1hop[i][j], func)
				state_verification(contract_json, instruction, calling_func_1hop[i][j])
				start=0
				check2=0
				avoid_loops=[]
				inside_cond={}
				inside_body=0
				stop=False
				event_verification(contract_json, instruction, calling_func_1hop[i][j])
				if check==1:
					to_add.append((calling_func_1hop[i][j],cf_to_check[i],instruction,"f"))
				elif check2==1:
					to_add.append((calling_func_1hop[i][j],cf_to_check[i],instruction,"t"))

	#creation of the list of functions containg an external call (even through the call of another function)
	risky_functions=[]
	cf_seen=set()
	for call in risky_calls:
		if len(call)==6:
			cf=(call[1],call[2])
			cf2=call[1]+"."+call[2]
			c=call[1]
			f=call[2]
		else:
			cf=(call[0],call[1])
			cf2=call[0]+"."+call[1]
			c=call[0]
			f=call[1]
		if cf not in cf_seen:
			visibility=""
			modifiers={}
			search_visibility(contract_json, cf2)
			search_modifier(contract_json, cf2)
			risky_functions.append((c,f,visibility,modifiers))
			cf_seen.add(cf)

	for add in to_add:
		visibility=""
		modifiers={}
		search_visibility(contract_json,add[0])
		search_modifier(contract_json,add[0])
		contr,func = add[0].split('.')
		contr2,func2 = add[1].split('.')
		if (contr,func) not in cf_seen and (contr2,func2) not in cf_seen:
			risky_functions.append((contr, func, visibility, modifiers))
			cf_seen.add((contr,func))
		risky_calls.append((contr,func,contr2,func2,add[2]))
		only_event_emis.append(add[3])
		for el in calls_to_check_raw:
			if (el[1]+"."+el[2])==add[1] and el not in risky_calls:
				risky_calls.append(el)
				only_event_emis.append("na")
	
	#obtain the functions calling the functions containing externall calls in 2 hops
	Ree_calling_func_1hop = [None] * len(risky_functions)
	if cfg == True:
		for i in range(len(risky_functions)):
			target_function = risky_functions[i][0] + "." + risky_functions[i][1]
			try:
				Ree_calling_func_1hop[i] = list(nx.dfs_predecessors(G_inverted, source=target_function, depth_limit=1))
			except (KeyError, nx.NetworkXError):
				Ree_calling_func_1hop[i] = []
		Ree_calling_func_2hops = [[None for _ in range(len(row))] for row in Ree_calling_func_1hop]
		for i, sublist in enumerate(Ree_calling_func_1hop):
			for j, value in enumerate(sublist):
				try:
					Ree_calling_func_2hops[i][j] = list(nx.dfs_predecessors(G_inverted, source=Ree_calling_func_1hop[i][j], depth_limit=1))
				except (KeyError, nx.NetworkXError):
					Ree_calling_func_2hops[i][j] = []

	#filter calling functions to avoid including loops
	if cfg==True:
		for i, sublist in enumerate(Ree_calling_func_1hop[:]):
			for j, value in enumerate(sublist):
				if Ree_calling_func_1hop[i][j]==(risky_functions[i][0]+"."+risky_functions[i][1]):
					Ree_calling_func_1hop[i].pop(j)

		for i, sublist in enumerate(Ree_calling_func_2hops[:]):
			for j, subsublist in enumerate(sublist):
				for y, value in enumerate(subsublist):
					if Ree_calling_func_2hops[i][j][y]==Ree_calling_func_1hop[i][j] or Ree_calling_func_2hops[i][j][y]==(risky_functions[i][0]+"."+risky_functions[i][1]):
						Ree_calling_func_2hops[i][j].pop(y)


	#checks whether there are actually functions in the code that might seem vulnerable
	if risky_functions==[]:
		print("No functions in code were found that might appear vulnerable to Reentrancy\n")
	else:
		print("\033[33mExternal Calls in yellow: NOT transfering ETH -> LOW RISK\033[0m")
		print("\033[31mExternal Calls in red: transfering ETH -> HIGH RISK\033[0m\n")
		#User's choice of which functions to go to check for Reentrancy risk
		def tuple_selection(array):
			func_to_keep=[]
			global Ree_calling_func_1hop
			global Ree_calling_func_2hops
			if alert_selection:
				choice=alert_selection
			else:
				print("format: contract_name.function_name. The items in the list, indicated by \"->\", show the external calls contained in the functions")
				print("(Those shown indented (if present) are the functions that call the function containing the external calls - MAX 2 hops)\n")
				for i,func in enumerate(array):
					print(f"{i+1}. {func[0]}.{func[1]}")
					for call in risky_calls:
						if len(call)==6 and call[1]==func[0] and call[2]==func[1]:
							if call[5]==0:
								print(f"\033[33m ->{read(call[3])}, {call[0]}\033[0m")
							else:
								print(f"\033[31m ->{read(call[3])}, {call[0]}\033[0m")
						elif len(call)==5 and call[0]==func[0] and call[1]==func[1]:
							print(f" ->calling function {call[2]}.{call[3]}")
							for y,ca in enumerate(risky_calls):
								if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
									if ca[5]==0:
										print(f"\033[33m   ->{read(ca[3])}, {ca[0]}\033[0m")
									else:
										print(f"\033[31m   ->{read(ca[3])}, {ca[0]}\033[0m")
					if cfg==True and Ree_calling_func_1hop[i]!=[]:
						for j,elem in enumerate(Ree_calling_func_1hop[i]):
							print(f"	{i + 1}.{j + 1}.{elem}")
							if Ree_calling_func_2hops[i][j]!=[]:
								for y,el in enumerate(Ree_calling_func_2hops[i][j]):
									print(f"		{i + 1}.{j + 1}.{y + 1}.{el}")
					print()
				choice=input("Insert the number of the functions that need to be verified (separated by comma) - put n for none / put a for all:")
			if choice == "a" or choice == "n" or all(number.strip().isdigit() for number in choice.split(',')):
				if choice=="n":
					return func_to_keep
				if choice=="a":
					return array
				selected_indexes=[int(index.strip()) - 1 for index in choice.split(',')]
				#print(selected_indexes)
				for indice in selected_indexes:
					if 0<= indice < len(array):
						func_to_keep.append(array[indice])
				
				Ree_calling_func_1hop = [Ree_calling_func_1hop[i] for i in selected_indexes if 0 <= i < len(Ree_calling_func_1hop)]
				Ree_calling_func_2hops = [Ree_calling_func_2hops[i] for i in selected_indexes if 0 <= i < len(Ree_calling_func_2hops)]
				return func_to_keep
			else:
				if alert_selection:
					print("!INVALID ARGUMENT FOR TUPLE SELECTION!")
				else:
					print("!INVALID INPUT!")
				print()
				return tuple_selection(array)

		risky_functions=tuple_selection(risky_functions)

		#clear the risky_calls list according to user choice
		to_remove = []
		for i, call in enumerate(risky_calls):
			found = False
			if len(call) == 5:
				for func in risky_functions:
					if (call[0], call[1]) == (func[0], func[1]):
						found = True
						break
				if not found:
					to_remove.append(i)
					only_event_emis[i] = "r"
		
		for el in reversed(to_remove):
			risky_calls.pop(el)

		while "r" in only_event_emis:
			only_event_emis.remove("r")

		to_remove = []
		for i, call in enumerate(risky_calls):
			found = False
			if len(call) == 6:
				for func in risky_functions:
					if (call[1], call[2]) == (func[0], func[1]):
						found = True
						break
				if not found:
					for rc in risky_calls:
						if len(rc) == 5 and (call[1], call[2]) == (rc[2], rc[3]):
							found = True
							break
				if not found:
					to_remove.append(i)
					only_event_emis[i] = "r"

		
		for el in reversed(to_remove):
			risky_calls.pop(el)

		while "r" in only_event_emis:
			only_event_emis.remove("r")

		#arrays to store overall verdict for each external call
		results_Ree=array('u',['t']*len(risky_calls))
		if cfg==True:
			results_Ree_calling_1hop = [["t" for _ in row] for row in Ree_calling_func_1hop]
			results_Ree_calling_2hops = [
				[
					["t" for _ in inner_list] 
					for inner_list in outer_list
				] 
				for outer_list in Ree_calling_func_2hops
			]

		print("\n-------------------------------------------------------------------------------\n")
		print("{:<60} {}".format("CHECK", "RESULTS"))
		print()

		#creation of array to store reports
		alert_string = ['' for _ in risky_functions]
		for i, variable in enumerate(risky_functions):
			alert_string[i]+="REPORT for function "+variable[0]+"."+variable[1]+":"

################################################################################################################################## FPs VERIFICATION BASED ON FUNCTIONS VISIBILITY
		print("\033[94m-Function is public/external-\033[0m")
		for i, variable in enumerate(risky_functions):
			if variable[2] == "private" or variable[2] == "internal":
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "F"))
				alert_string[i] += f"The visibility of the function \"{variable[1]}\" is {variable[2]}. "
				for j,call in enumerate(risky_calls):
					if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
						results_Ree[j]="f"
					if len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
						results_Ree[j]="f"
			else:
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "T"))
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					visibility = ""
					search_visibility(contract_json, Ree_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if visibility == "private" or visibility == "internal":
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							visibility = ""
							search_visibility(contract_json, Ree_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if visibility == "private" or visibility == "internal":
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))

		print()
################################################################################################################################## FPs VERIFICATION BASED ON FUNCTIONS MODIFIERS 
		bool_false={'type': 'BooleanLiteral', 'value': False}
		bool_true={'type': 'BooleanLiteral', 'value': True}

		body_exec=0
		lock=None
		def blocking_lock(impl):
			global block
			global body_exec
			global lock
			if not isinstance(impl, dict):
				return 0
			for key, value in impl.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						blocking_lock(element)
					
				elif isinstance(value, dict):
					if key=='expression' and 'type' in value and value['type']=="BinaryOperation" and value['operator']=="=" and (value['right']==bool_false or value['right']==bool_true) and body_exec==0 and lock==None:
						lock=value['left']
					if key=='expression' and 'type' in value and value['type']=="Identifier" and value['name']=="_" and lock!=None:
						body_exec=1
					if key=='expression' and 'type' in value and value['type']=="BinaryOperation" and value['operator']=="=" and (value['right']==bool_true or value['right']==bool_false) and value['left']==lock and body_exec==1:
						block=1
					blocking_lock(value)

		#function to determine whether inside a modifier there are conditions preventing execution
		check=0
		def search_cond_modifier(dictionary,mod):
			if not isinstance(dictionary, dict):
				return 0
			global check
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='ModifierDefinition' and element['name']==mod:
								blocking_lock(element['body'])
								search_cond_modifier(element, mod)
								continue
							else:
								continue
						if 'type' in element and element['type']=='IfStatement':
							check=1
							blocking_condition(element['condition'])
						search_cond_modifier(element, mod)
					
				elif isinstance(value, dict):
					if key=='expression' and 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=="Identifier" and value['expression']['name']=="require":
						check=1
						blocking_condition(value['arguments'][0])
					search_cond_modifier(value, mod)

		
		print("\033[94m-Absence of Modifiers preventing reentrancy-\033[0m")
		absolute1=False
		absolute2=False		
		for i, variable in enumerate(risky_functions):
			absolute1=False
			check=0
			block=0
			body_exec=0
			lock=None
			for mod in variable[3]:
				search_cond_modifier(contract_json, mod['name'])
			if block==1:
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "F"))
				alert_string[i]+="The modifiers of the function \"" + str(variable[1]) + "\" prevents the execution (check msg.sender) or prevent reentrancy (reentrancy lock). "
				results_Ree[i] = 'f'
				absolute1=True
				for l,call in enumerate(risky_calls):
					if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
						results_Ree[l]="f"
					elif len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
						results_Ree[l]="f"
			else:
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "T"))
				if check==1:
					alert_string[i]+="The modifiers of the function \"" + str(variable[1]) + "\" NOT appear to prevent execution or reentrancy, but please check their implementations. "
			for call in risky_calls:
				if len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
					modifiers = {}
					check=0
					block=0
					body_exec=0
					lock=None
					search_modifier(contract_json, call[2]+"."+call[3])
					for mod in modifiers:
						search_cond_modifier(contract_json, mod['name'])
					if block==1:
						print("{:<63} {}".format(f" ->{call[2]}.{call[3]}", "F"))
						for j,ca in enumerate(risky_calls):
							if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
								results_Ree[j]="f"
					elif absolute1==True:
						print("{:<63} {}".format(f" ->{call[2]}.{call[3]}", "F"))
					else:
						print("{:<63} {}".format(f" ->{call[2]}.{call[3]}", "T"))
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					modifiers = {}
					check=0
					block=0
					body_exec=0
					lock=None
					absolute2=False
					search_modifier(contract_json, Ree_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					for mod in modifiers:
						search_cond_modifier(contract_json, mod['name'])
					if block==1 or absolute1==True:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
						absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							modifiers = {}
							check=0
							block=0
							body_exec=0
							lock=None
							search_modifier(contract_json, Ree_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							for mod in modifiers:
								search_cond_modifier(contract_json, mod['name'])
							if block==1 or absolute2==True:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))

		print()
################################################################################################################################## FPs VERIFICATION BASED ON INSTRUCTIONS BEING SUBJECT TO CONDITIONS
		print("\033[94m-Instruction not subject to conditions\033[0m")
		print("\033[94m preventing execution (if or require)-\033[0m")
		absolute1=False	
		absolute2=False		
		for i, variable in enumerate(risky_functions):
			print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", ""))
			for j,call in enumerate(risky_calls):
				absolute1=False
				check=0
				block=0
				if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
					search_conditions(contract_json,call[4],call[1]+"."+call[2])
					search_require(contract_json,call[4],call[1]+"."+call[2])
					if block==1:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "F"))
						results_Ree[j]="f"
						alert_string[i]+="The externall call of type \""+call[0]+"\" on "+read(call[3])+" is subject to some conditions (if or require) preventing the execution of code (check msg.sender). "
					else:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						if check==1:
							alert_string[i]+="The externall call of type \""+call[0]+"\" on "+read(call[3])+" is subject to some conditions (if or require) which appear NOT to prevent the execution of the part of the code analyzed, but please check their implementations. "
				elif len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
					search_conditions(contract_json,call[4],call[0]+"."+call[1])
					search_require(contract_json,call[4],call[0]+"."+call[1])
					if block==1:
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "F"))
						alert_string[i]+="The instuction calling function "+call[3]+" (containing external calls) is subject to some conditions (if or require) preventing the execution of code (check msg.sender). "
						results_Ree[j]="f"
						absolute1=True
					else:
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "T"))
						if check==1:
							alert_string[i]+="The instruction calling function "+call[3]+" (containing external calls) is subject to some conditions (if or require) which appear NOT to prevent the execution of the part of the code analyzed, but please check their implementations. "
					for y,ca in enumerate(risky_calls):
						if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
							check=0
							block=0
							search_conditions(contract_json,ca[4],ca[1]+"."+ca[2])
							search_require(contract_json,ca[4],ca[1]+"."+ca[2])
							if block==1 or absolute1==True:
								print("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "F"))
								results_Ree[y]="f"
								alert_string[i]+="The externall call of type \""+ca[0]+"\" on "+read(ca[3])+" in the called function "+call[3]+" is subject to some conditions (if or require) preventing the execution of code (check msg.sender). "
							else:
								print("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "T"))
								if check==1:
									alert_string[i]+="The externall call of type \""+ca[0]+"\" on "+read(ca[3])+" in the called function "+call[3]+" is subject to some conditions (if or require) which appear NOT to prevent the execution of the part of the code analyzed, but please check their implementations. "
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					instruction = {}
					absolute2=False
					check=0
					block=0
					search_instruction(contract_json, Ree_calling_func_1hop[i][j], variable[1])
					search_conditions(contract_json, instruction, Ree_calling_func_1hop[i][j])
					search_require(contract_json, instruction, Ree_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if block==1:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
						absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							instruction = {}
							check=0
							block=0
							c,f = Ree_calling_func_1hop[i][j].split('.')
							search_instruction(contract_json, Ree_calling_func_2hops[i][j][y], f)
							search_conditions(contract_json, instruction, Ree_calling_func_2hops[i][j][y])
							search_require(contract_json, instruction, Ree_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if block==1 or absolute2==True:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))
		
		print()
################################################################################################################################## FPs VERIFICATION BASED ON TARGET ADR
		definition="Not Found"
		final_definition="Not Found"
				
		#function to identify how the target adr of the external call is defined
		def search_definition(dictionary,variable_name,fc, ident):
			if not isinstance(dictionary, dict):
				return 0
			global definition
			global final_definition
			contr,func = fc.split('.')
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='ContractDefinition' and element['name']!=contr:
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and (element['name']==func or (func=="<Fallback>" and element['isFallback']==True) or (func=="<Constructor>" and element['isConstructor']==True)):
								search_definition(element, variable_name, fc, ident)
								continue
							else:
								continue
						if key=="statements":
							if "type" in element and element["type"]=="VariableDeclarationStatement" and "name" in element["variables"][0] and variable_name['type']=="Identifier" and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						if element==ident:
							final_definition=definition
						search_definition(element, variable_name, fc, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					if value==ident:
						final_definition=definition
					search_definition(value, variable_name, fc, ident)

		print("\033[94m-Target adr controllable by user-\033[0m")
		matching_index1 = []
		matching_index2 = -1
		matching_index3 = []
		absolute1=False
		absolute2=False	
		for i, variable in enumerate(risky_functions):
			print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", ""))
			absolute1=False
			matching_index1 = []
			parameters=[]
			extract_parameters(contract_json, variable[0]+"."+variable[1])
			parameters_f=parameters.copy()
			for j,call in enumerate(risky_calls):
				definition="Not Found"
				final_definition="Not Found"
				if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
					if call[3]['type']=="Identifier" or call[3]['type']=='MemberAccess' or call[3]['type']=='NumberLiteral' or call[3]['type']=='IndexAccess':
						target_adr=call[3]
					elif call[3]['type']=="FunctionCall":
						target_adr=call[3]['arguments'][0]
					else:
						target_adr=None
					search_definition(contract_json,target_adr,call[1]+"."+call[2],call[4])
					if target_adr['type']=="IndexAccess":
						target_adr=target_adr['base']
					if final_definition==msg_sender or target_adr==msg_sender:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						absolute1=True
					elif target_adr in parameters_f:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						matching_index1.append(parameters_f.index(target_adr))
					elif isinstance(final_definition, dict) and final_definition['type']=="FunctionCall" and len(final_definition['arguments'])==1 and final_definition['arguments'][0] in parameters_f:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						matching_index1.append(parameters_f.index(final_definition['arguments'][0]))
					else:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "F"))
						alert_string[i]+="The target address ("+read(call[3])+") is NOT controllable by user (different from msg.sender and not passed as a parameter), thereby the externall call is not exploitable for reentrancy. "
						results_Ree[j] = 'f'
				elif len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
					parameters=[]
					extract_parameters(contract_json, call[2]+"."+call[3])
					output_buffer = []
					absolute2=False
					matching_index2=-1
					for y,ca in enumerate(risky_calls):
						definition="Not Found"
						final_definition="Not Found"
						if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
							if ca[3]['type']=="Identifier" or ca[3]['type']=='MemberAccess' or ca[3]['type']=='NumberLiteral' or ca[3]['type']=='IndexAccess':
								target_adr=ca[3]
							elif ca[3]['type']=="FunctionCall":
								target_adr=ca[3]['arguments'][0]
							else:
								target_adr=None
							search_definition(contract_json,target_adr,ca[1]+"."+ca[2],ca[4])
							if target_adr['type']=="IndexAccess":
								target_adr=target_adr['base']
							if final_definition == msg_sender or target_adr == msg_sender:
								output_buffer.append("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "T"))
								absolute2=True
							elif target_adr in parameters:
								matching_index2 = parameters.index(target_adr)
								output_buffer.append("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "T"))
							elif isinstance(final_definition, dict) and final_definition['type']=="FunctionCall" and len(final_definition['arguments'])==1 and final_definition['arguments'][0] in parameters:
								matching_index2 = parameters.index(final_definition['arguments'][0])
								output_buffer.append("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "T"))
							else:
								output_buffer.append("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "F"))
								alert_string[i]+="The target address ("+read(ca[3])+") is NOT controllable by user (different from msg.sender and not passed as a parameter), thereby the externall call is not exploitable for reentrancy. "
								results_Ree[y] = "f"
					if absolute2==True or (matching_index2!=-1 and (call[4]['arguments'][matching_index2]==msg_sender or call[4]['arguments'][matching_index2] in parameters_f)):
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "T"))
						if call[4]['arguments'][matching_index2] in parameters_f:
							matching_index1.append(parameters_f.index(call[4]['arguments'][matching_index2]))
						else:
							absolute1=True
					else:
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "F"))
						results_Ree[j] = "f"
					for l in output_buffer:
						print(l)
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					matching_index3=[]
					absolute2=False
					overall=False
					instruction={}
					search_instruction(contract_json, Ree_calling_func_1hop[i][j], variable[1])
					parameters=[]
					extract_parameters(contract_json, Ree_calling_func_1hop[i][j])
					for ind in matching_index1:
						definition="Not Found"
						final_definition="Not Found"
						if instruction['arguments'][ind]['type']=='Identifier' or instruction['arguments'][ind]['type']=='MemberAccess' or instruction['arguments'][ind]['type']=='NumberLiteral' or instruction['arguments'][ind]['type']=='IndexAccess':
							par=instruction['arguments'][ind]
						elif instruction['arguments'][ind]['type']=="FunctionCall":
							par=instruction['arguments'][ind]['arguments'][0]
						else:
							par=None
						search_definition(contract_json,par,Ree_calling_func_1hop[i][j],instruction)
						if par['type']=="IndexAccess":
							par=par['base']
						if final_definition==msg_sender or par==msg_sender:
							absolute2=True
							overall=True
						elif par in parameters:
							matching_index3.append(parameters.index(par))
							overall=True
						elif isinstance(final_definition, dict) and final_definition['type']=="FunctionCall" and len(final_definition['arguments'])==1 and final_definition['arguments'][0] in parameters:
							matching_index3.append(parameters.index(final_definition['arguments'][0]))
							overall=True
					if absolute1==True or overall==True:
						print("{:<63} {}".format(indent_level_1, "T"))
						if absolute1==True:
							absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j]="f"
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							c,f = Ree_calling_func_1hop[i][j].split('.')
							instruction={}
							search_instruction(contract_json, Ree_calling_func_2hops[i][j][y], f)
							parameters=[]
							extract_parameters(contract_json, Ree_calling_func_2hops[i][j][y])
							overall=False
							for ind in matching_index3:
								definition="Not Found"
								final_definition="Not Found"
								if instruction['arguments'][ind]['type']=='identifier':
									par=instruction['arguments'][ind]
								elif instruction['arguments'][ind]['type']=="FunctionCall" and (instruction['arguments'][ind]['arguments'][0]['type']=="Identifier" or instruction['arguments'][ind]['arguments'][0]['type']=="MemberAccess"):
									par=instruction['arguments'][ind]['arguments'][0]
								else:
									par=None
								search_definition(contract_json,par,Ree_calling_func_2hops[i][j][y],instruction)
								if final_definition==msg_sender or par==msg_sender or par in parameters or (isinstance(final_definition, dict) and final_definition['type']=="FunctionCall" and len(final_definition['arguments'])==1 and final_definition['arguments'][0] in parameters):
									overall=True
							if absolute2==True or overall==True:
								print("{:<63} {}".format(indent_level_2, "T"))
							else:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'		
		
		print()		
################################################################################################################################## FPs VERIFICATION BASED ON STATE CHANGE SUBSEQUENT TO EXTERNALL CALL
		print("\033[94m-Instruction followed by real state change\033[0m")
		print("\033[94m (not only event emission)-\033[0m")	
		for i, variable in enumerate(risky_functions):
			print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", ""))
			absolute1=False
			for j,call in enumerate(risky_calls):
				if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
					if only_event_emis[j]=="t" or only_event_emis[j]=="na":
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "F"))
						results_Ree[j]="f"
						alert_string[i]+="The externall call of type \""+call[0]+"\" on "+read(call[3])+" is not followed by a real change in the state of the contract (only event emission). "
					elif only_event_emis[j]=="f":
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						absolute1=True
				elif len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
					if only_event_emis[j]=="t" or only_event_emis[j]=="na":
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "F"))
						results_Ree[j]="f"
						alert_string[i]+="The instuction calling function "+call[3]+" (containing external calls, themselves not followed by a state change) is not followed by a real change in the state of the contract (only event emission). "
					elif only_event_emis[j]=="f":
						print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", "T"))
						absolute1=True
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					instruction = {}
					check=0
					start=0
					absolute2=False
					avoid_loops=[]
					inside_cond={}
					inside_body=0
					stop=False
					search_instruction(contract_json, Ree_calling_func_1hop[i][j], variable[1])
					state_verification(contract_json, instruction, Ree_calling_func_1hop[i][j])
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if check==1 or absolute1==True:
						print("{:<63} {}".format(indent_level_1, "T"))
						absolute2=True
					else:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							instruction = {}
							check=0
							start=0
							avoid_loops=[]
							inside_cond={}
							inside_body=0
							stop=False
							c,f = Ree_calling_func_1hop[i][j].split('.')
							search_instruction(contract_json, Ree_calling_func_2hops[i][j][y], f)
							state_verification(contract_json, instruction, Ree_calling_func_2hops[i][j][y])
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if check==1 or absolute2==True:
								print("{:<63} {}".format(indent_level_2, "T"))
							else:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
		print()
################################################################################################################################## FPs VERIFICATION BASED ON AMOUNT OF ETH TRANSFERRED (IF ANY)
		#function to check whether the amount to be transferred includes msg.value
		msg_value={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'value'}
		def verify_amount(amount):
			global check
			if not isinstance(amount, dict):
				return 0
			if amount==msg_value:
				check=1
			elif 'type' in amount and amount['type']=="BinaryOperation":
				if (amount['operator']=="/" and amount['left']==msg_value) or (amount['operator']=="-" and amount['left']==msg_value):
					check=1
			elif 'type' in amount and amount['type']=="FunctionCall" and amount['expression']['type']=='MemberAccess' and amount['expression']['expression']==msg_value:
				if amount['expression']['memberName']=='div' or amount['expression']['memberName']=='sub':
					check=1

		print("\033[94m-Amount transferred (if present) NOT\033[0m")
		print("\033[94m equal or less to msg.value-\033[0m")
		for i, variable in enumerate(risky_functions):
			print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", ""))
			absolute1=False
			at_least_one=False
			for j,call in enumerate(risky_calls):
				if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
					check=0
					verify_amount(call[5])
					if call[5]==0:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "NA"))
					elif check==1:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "F"))
						results_Ree[j]="f"
						alert_string[i]+="The externall call of type \""+call[0]+"\" on "+read(call[3])+" appears to be transfering an amount of ETH proportional to the msg.value, specifically less than or equal to the latter. "
						at_least_one=True
					else:
						print("{:<63} {}".format(f" -> {read(call[3])}, {call[0]}", "T"))
						absolute1=True
						at_least_one=True
				elif len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
					print("{:<63} {}".format(f" -> calling function {call[2]}.{call[3]}", ""))
					for y,ca in enumerate(risky_calls):
						if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
							check=0
							verify_amount(ca[5])
							if ca[5]==0:
								print("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "NA"))
							elif check==1:
								print("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "F"))
								results_Ree[y]="f"
								alert_string[i]+="The externall call of type \""+ca[0]+"\" on "+read(ca[3])+" (in the called "+ca[2]+" function) appears to be transfering an amount of ETH proportional to the msg.value, specifically less than or equal to the latter. "
								at_least_one=True
							else:
								print("{:<63} {}".format(f"  -> {read(ca[3])}, {ca[0]}", "T"))
								absolute1=True
								at_least_one=True
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					if at_least_one==False:
						print("{:<63} {}".format(indent_level_1, "NA"))
					elif absolute1==True:
						print("{:<63} {}".format(indent_level_1, "T"))
					else:
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if at_least_one==False:
								print("{:<63} {}".format(indent_level_2, "NA"))
							elif absolute1==True:
								print("{:<63} {}".format(indent_level_2, "T"))
							else:
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
		print()
################################################################################################################################## FPs VERIFICATION BASED ON FUNCTIONS BEING THE CONSTRUCTOR
		print("\033[94m-Function is not the constructor-\033[0m")
		for i, variable in enumerate(risky_functions):
			if variable[1] == "<Constructor>":
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "F"))
				alert_string[i] += f"The function \"{variable[1]}\" is the constructor (not present in the runtime bytecode, it cannot be called). "
				for j,call in enumerate(risky_calls):
					if len(call)==6 and call[1]==variable[0] and call[2]==variable[1]:
						results_Ree[j]="f"
					if len(call)==5 and call[0]==variable[0] and call[1]==variable[1]:
						results_Ree[j]="f"
			else:
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "T"))
			if cfg==True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					contr,func = Ree_calling_func_1hop[i][j].split('.')
					if func == "<Constructor>":
						print("{:<63} {}".format(indent_level_1, "F"))
						results_Ree_calling_1hop[i][j] = 'f'
					else:
						print("{:<63} {}".format(indent_level_1, "T"))
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							contr,func = Ree_calling_func_2hops[i][j][y].split('.')
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							if func == "<Constructor>":
								print("{:<63} {}".format(indent_level_2, "F"))
								results_Ree_calling_2hops[i][j][y] = 'f'
							else:
								print("{:<63} {}".format(indent_level_2, "T"))

		print()
##################################################################################################################################
		print("\n-------------------------------------------------------------------------------\n")
		print("                		 DETAILED OUTPUT")
		for i, variable in enumerate(risky_functions):
			if not alert_string[i].endswith(':'):
				print()
				print(alert_string[i])
				if results_Ree[i]=='f' and cfg==True and Ree_calling_func_1hop[i] != []:
					for j, elem in enumerate(Ree_calling_func_1hop[i]):
						if results_Ree_calling_1hop[i][j]=='t':
							print(f"!!!ATTENTION!!! {Ree_calling_func_1hop[i][j]}, which is calling {variable[1]}, appears not to match any FP patterns and consequenty is evaluated as a TP, take a look at single checks")
						if Ree_calling_func_2hops[i][j] != []:
							for y, el in enumerate(Ree_calling_func_2hops[i][j]):
								indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
								if results_Ree_calling_2hops[i][j][y]=='t':
									print(f"!!!ATTENTION!!! {Ree_calling_func_2hops[i][j][y]}, which is calling {Ree_calling_func_1hop[i][j]} (which in turn is calling {variable[1]}), appears not to match any FP patterns and consequenty is evaluated as a TP, take a look at single checks")

		print("\n-------------------------------------------------------------------------------\n")	
		print("                       		 FINAL RESULTS\n")

		final_results=["f" for _ in risky_functions]

		for i,call in enumerate(risky_calls):
			at_least_one=False
			if len(call)==5 and call[0]==variable[0] and call[1]==variable[1] and results_Ree[i]=="t":
				for y,ca in enumerate(risky_calls):
					if len(ca)==6 and call[2]==ca[1] and call[3]==ca[2]:
						if results_Ree[y]=="t":
							at_least_one=True
				if at_least_one==False:
					results_Ree[i]=="f"


		for a,variable in enumerate(risky_functions):
			for i,call in enumerate(risky_calls):
				if (len(call)==6 and call[1]==variable[0] and call[2]==variable[1]) or (len(call)==5 and call[0]==variable[0] and call[1]==variable[1]):
					if results_Ree[i]=="t":
						final_results[a]="t"

		for i, variable in enumerate(risky_functions):
			if final_results[i] == 't':
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "True Positive"))
			elif final_results[i] == 'f':
				print("{:<63} {}".format(f"{i+1}. {variable[0]}.{variable[1]}", "False Positive"))
			
			for j, call in enumerate(risky_calls):
				if len(call) == 6 and call[1] == variable[0] and call[2] == variable[1]:
					color_code = "\033[33m" if call[5] == 0 else "\033[31m"
					result_text = "True Positive" if results_Ree[j] == "t" else "False Positive"
					formatted_call = f"{color_code} ->{read(call[3])}, {call[0]}\033[0m"
					print("{:<72} {}".format(formatted_call, result_text))
				
				elif len(call) == 5 and call[0] == variable[0] and call[1] == variable[1]:
					result_text = "True Positive" if results_Ree[j] == "t" else "False Positive"
					formatted_call = f" ->calling function {call[2]}.{call[3]}"
					print("{:<63} {}".format(formatted_call, result_text))
					
					for y, ca in enumerate(risky_calls):
						if len(ca) == 6 and call[2] == ca[1] and call[3] == ca[2]:
							color_code = "\033[33m" if ca[5] == 0 else "\033[31m"
							result_text = "True Positive" if results_Ree[y] == "t" else "False Positive"
							formatted_call = f"{color_code}  ->{read(ca[3])}, {ca[0]}\033[0m"
							print("{:<72} {}".format(formatted_call, result_text))
			
			if cfg == True and Ree_calling_func_1hop[i] != []:
				for j, elem in enumerate(Ree_calling_func_1hop[i]):
					indent_level_1 = f"    {i+1}.{j+1}. {elem}"
					result_text = "True Positive" if results_Ree_calling_1hop[i][j] == 't' else "False Positive"
					print("{:<63} {}".format(indent_level_1, result_text))
					
					if Ree_calling_func_2hops[i][j] != []:
						for y, el in enumerate(Ree_calling_func_2hops[i][j]):
							indent_level_2 = f"        {i+1}.{j+1}.{y+1}. {el}"
							result_text = "True Positive" if results_Ree_calling_2hops[i][j][y] == 't' else "False Positive"
							print("{:<63} {}".format(indent_level_2, result_text))
			print()

		
