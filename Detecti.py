#!/usr/bin/env python3

import subprocess
import sys
import json
import argparse
from array import array

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

#print(json_string)

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
print("1. SINGLE CHECKS: For each part of the code analyzed, it is reported whether the result of the check assumes it is a true positive (T) or a false positive (F)")
print("2. DETAILED OUTPUT: It is possible to find more detailed notes of what was found in the analysis")
print("3. FINAL RESULTS: For each part of the code analyzed, the final verdict (derived from the overall consideration of all checks) is clearly indicated")
print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
        
    
#selection of vulnerabilities to be verified
def select_vulnerabilities(selection_string):
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
	else:
        # if selection not given as command parameter ask the user
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

#print("Vulnerabilities selected:", vulnerabilities_selection)

print()
print("NOTE: if the function name is blank \"\", it means it is the fallback function (obsolete defined with an unnamed function). On the other hand, if the name is \"None\", it means it is either the constructor (defined with constructor()) or the fallback function (defined with fallback() or receive())\n\n")

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
			if name!="":
				return name
			else:
				if verbose_modality:
					return "Variable Name not recognized" + str(dictionary)
				else:
					return "Variable Name not recognized"
		return dictionary

#part of code dealing with UNCHECKED RETURN VALUE vulnerability 
if vulnerabilities_selection[0]==1:
	print("/////////////////////////")
	print("UNCHECKED RETURN VALUE")
	print("/////////////////////////")
	print()

	#array to store the information of unchecked return value functions [f_name, visibility, variable, modifiers, dictionary instruction]
	URV_instructions=[]

	def search_urv_instructions(dictionary, function_name=None, visibility=None, modifiers=None):
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
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						continue
					search_urv_instructions(element, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				#send
				if key=="condition" or key=="initialValue" or key=="right":
					continue
				if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("send",function_name, visibility, value['expression']['expression'], modifiers, value))
				#call standard version with {}
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("call",function_name, visibility, value['expression']['expression'], modifiers, value))
				#call deprecated version without {}
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='call' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("call",function_name, visibility, value['expression']['expression'], modifiers, value))
				#call.value
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and (value['expression']['expression']['type']=="MemberAccess" and value['expression']['expression']['memberName']=="call") and (value['expression']['expression']['expression']['type']=="Identifier" or value['expression']['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("call.value",function_name, visibility, value['expression']['expression']['expression'], modifiers, value))
				#delegatecall
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='delegatecall' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("delegatecall",function_name, visibility, value['expression']['expression'], modifiers, value))
				#callcode
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName']=='callcode' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					URV_instructions.append(("callcode",function_name, visibility, value['expression']['expression'], modifiers, value))
				search_urv_instructions(value, function_name, visibility, modifiers)
	
	search_urv_instructions(contract_json)

	#checks whether there are actually instructions in the code that might seem vulnerable
	if URV_instructions==[]:
		print("No parts of code were found that might appear vulnerable to Unchecked Return Value\n")
	else:
		#function to allow the user to choose which send and call calls they want to verify
		def tuple_selection(array):
			tuple_to_keep=[]
			if alert_selection:
				choice=alert_selection
			else:
				print("format: Variable on which function is called, Instruction Type, Function\n")
				for i, tupla in enumerate(array):
					print(f"{i + 1}. {read(tupla[3])},{tupla[0]},{str(tupla[1])}")
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


		URV_instructions=tuple_selection(URV_instructions)
		#for instr in URV_instructions:
		#	print(instr)

		#arrays used in the "Final Results" output - store overall verdict for each send/call instruction
		results_URV=array('u',['t']*len(URV_instructions))

		print("\n--------------------------------------------------\n")
		print("{:<40} {}".format("CHECK", "RESULTS"))
		print()
		alert_string=""

		#FPs VERIFICATION BASED ON FUNCTIONS VISIBILITY 
		print("-Function is public/external-")
		alert_string+="\nCHECK REFERENCE:-Function is public/external-"
		i=0
		for variable in URV_instructions:
			if variable[2]=="private" or variable[2]=="internal":
				print("{:<43} {}".format(read(variable[3]), "F"))
				alert_string+="\n!!!ATTENTION!!!! The "+ variable[0] +" call on the \"" + read(variable[3]) + "\" variable could be a FALSE POSITIVE because of the visibility of the function \"" + str(variable[1]) + "\" which is " + str(variable[2])
				results_URV[i]='f'
			else:
				print("{:<43} {}".format(read(variable[3]), "T"))
			i+=1

		print()
		alert_string+="\n"

		#FPs VERIFICATION BASED ON FUNCTIONS MODIFIERS 
		print("-Absence of Modifiers-")
		alert_string+="\nCHECK REFERENCE:-Absence of Modifiers-"
		i=0
		for variable in URV_instructions:
			if variable[4]!=[]:
				print("{:<43} {}".format(read(variable[3]), "F"))
				results_URV[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The "+ variable[0] +" call on the \"" + read(variable[3]) + "\" variable could be a FALSE POSITIVE because of the modifiers of the function \"" + str(variable[1]) + "\", please check their restrictions"
			else:
				print("{:<43} {}".format(read(variable[3]), "T"))
			i+=1

		alert_string+="\n"

		#extract contract name
		contract_name = contract_json.get("children", [{}])[0].get("name", None)
		if contract_name=="solidity":
			contract_name = contract_json.get("children", [{}])[1].get("name", None)

		#variable to use as a comparison to check which variables on which send/call is called are set to msg.sender
		msg_sender={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'sender'}

		definition="Not Found"
		final_definition="Not Found"
				
		#function to identify how the variable on which send/call is called is defined
		def search_definition(dictionary,variable_name,function, ident):
			if not isinstance(dictionary, dict):
				#print(dictionary)\
				return 0
			global definition
			global final_definition
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_definition(element, variable_name, function, ident)
								continue
							else:
								continue
						if key=="statements":
							if "type" in element and element["type"]=="VariableDeclarationStatement" and "name" in element["variables"][0] and variable_name['type']=="Identifier" and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						search_definition(element, variable_name, function, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					#condition to check when to stop looking for assignments to the variable, we do not want to consider those after the call to send
					if key=='expression' and value==ident:
						final_definition=definition
					search_definition(value, variable_name, function, ident)

		print()

		#checks whether the variables on which send/call is called are equal to msg.sender
		print("-Variable defined differently")
		print(" from address of msg.sender-")
		alert_string+="\nCHECK REFERENCE:-Variable defined differently from address of msg.sender-"
		i=0
		for variable in URV_instructions:
			search_definition(contract_json,variable[3],variable[1],variable[5])
			if final_definition==msg_sender or variable[3]==msg_sender:
				print("{:<43} {}".format(read(variable[3]), "F"))
				results_URV[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The "+ variable[0] +" call on the \"" + read(variable[3]) + "\" variable could be a FALSE POSITIVE because the variable is assigned to the address of message sender (possible attacker)"
			else:
				print("{:<43} {}".format(read(variable[3]), "T"))
			i+=1
			definition="Not Found"
			final_definition="Not Found"

		alert_string+="\n"
		print()

		#function to determine whether the send/call statement is within the body of an if condition
		check=0
		def search_conditions(dictionary,ident,function=None, plus=None):
			if not isinstance(dictionary, dict):
				return 0
			global check
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_conditions(element, ident,function, plus)
								continue
							else:
								continue
						search_conditions(element, ident,function, plus)
					
				elif isinstance(value, dict):
					if plus==1 and value==ident:
						check=1
					if key=='trueBody' or key=='falseBody':
						search_conditions(value, ident,function, 1)
					search_conditions(value, ident,function,plus)

		#function to determine whether the send/call instruction is subject to some require condition 
		found_require=0
		def search_require(dictionary,ident,function):
			global found_require
			if not isinstance(dictionary, dict):
				return 0
			global check
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_require(element, ident,function)
								continue
							else:
								continue
						search_require(element, ident,function)
					
				elif isinstance(value, dict):
					#condition to check whether the send/call occurs subsequent to a require
					if found_require==1  and value==ident:
						check=1
					if key=='expression' and 'type' in value and value['type']=="Identifier" and value['name']=="require":
						found_require=1
					search_require(value, ident,function)

		#checks whether the send/call instruction is subject to some kind of condition
		print("-Instruction not subject to conditions")
		print(" (if or require)-")
		alert_string+="\nCHECK REFERENCE:-Instruction not subject to conditions (if or require)-"
		i=0
		for variable in URV_instructions:
			search_conditions(contract_json,variable[5],variable[1])
			search_require(contract_json,variable[5],variable[1])
			if check==1:
				print("{:<43} {}".format(read(variable[3]), "F"))
				results_URV[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The "+ variable[0] +" call on the \"" + read(variable[3]) + "\" variable could be a FALSE POSITIVE because the call is subject to some conditions (if or require), please check their implementations"
			else:
				print("{:<43} {}".format(read(variable[3]), "T"))
			i+=1
			check=0
			found_require=0	

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

		#checks whether the send/call instruction is the last instruction in the function
		print("\n-Instruction not last operation-")
		alert_string+="\n\nCHECK REFERENCE:-Instruction not last operation-"
		i=0
		for variable in URV_instructions:
			final=""
			last_statement(contract_json,variable[1])
			if 'expression' in final and final['expression']==variable[5]:
				print("{:<43} {}".format(read(variable[3]), "F"))
				results_URV[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The "+ variable[0] +" call on the \"" + read(variable[3]) + "\" variable could be a FALSE POSITIVE because the call is the last operation in \""+ str(variable[1]) +"\" function"
			else:
				print("{:<43} {}".format(read(variable[3]), "T"))
			i+=1
			
		print("\n--------------------------------------------------\n")
		print("                DETAILED OUTPUT")
		print(alert_string)

		print("\n--------------------------------------------------\n")	
		print("                FINAL RESULTS\n")
		i=0
		for variable in URV_instructions:
			if results_URV[i]=='t':
				print("{:<35} {}".format(read(variable[3]), "True Positive"))
			elif results_URV[i]=='f':
				print("{:<35} {}".format(read(variable[3]), "False Positive"))
			i+=1

#part of code dealing with TIMESTAMP DEPENDENCE vulnerability 
if vulnerabilities_selection[1]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("/////////////////////")
	print("TIMESTAMP DEPENDENCE")
	print("/////////////////////")
	print()

	timestamp={'type': 'MemberAccess','expression': {'type': 'Identifier','name': 'block'},'memberName': 'timestamp'}
	now={'type': 'Identifier','name': 'now'}
	alert_string=""

	presence=0

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

	#for var in state_variables:
	#	print(var)

	#function to check whether there is an occurrence of the timestamp within a dictionary
	def timestamp_presence(dictionary):
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
					timestamp_presence(element)
			elif isinstance(value, dict):
				if (key=="left" or key=="right") and (value==timestamp or value==now):
					presence=1
				timestamp_presence(value)

	#array to save information about the instructions in which the timestamp is used
	timestamp_usage=[]
	#counters in case the timestamp is used in different conditions (of the same type) within the same function
	c1=1 #if conditions
	c2=1 #require conditions
	c3=1 #while conditions

	#variable to account for the "line" of code
	l=0

	#function to look up where timestamp is used and for what
	def search_timestamp(dictionary, function_name=None, tipo=None, visibility=None, modifiers=None):
		global l
		global presence
		global c1
		global c2
		global c3
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				l+=1
				for element in value:
					if not isinstance(element, dict):
						return 0
					if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						visibility=element['visibility']
						modifiers=element['modifiers']
						c1=1
						c2=1
						c3=1
						search_timestamp(element, function_name, "function", visibility, modifiers)
						continue
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						function_name=element['name']
						c1=1
						c2=1
						c3=1
						search_timestamp(element, function_name, "modifier")
						continue
					#verification definition state variables
					if key=='subNodes' and element['type']=='StateVariableDeclaration':
						presence=0
						timestamp_presence(element["initialValue"])
						if presence==1:
							timestamp_usage.append(("assignment",element['variables'][0]['identifier'],"s",function_name, tipo, l))
					#verification variable definition in functions
					if key=='statements' and element['type']=='VariableDeclarationStatement':
						presence=0
						timestamp_presence(element["initialValue"])
						if presence==1:
							timestamp_usage.append(("assignment",element['variables'][0]['identifier'],"l", function_name, tipo, l))
					#check assignments
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
						presence=0
						timestamp_presence(element['expression']['right'])
						if presence==1:
							if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
								timestamp_usage.append(("assignment",element['expression']['left'],"s",function_name, tipo, l))
							else:
								timestamp_usage.append(("assignment",element['expression']['left'],"l",function_name, tipo, l))
							
					#check if conditions
					if key=='statements' and element['type']=='IfStatement':
						presence=0
						timestamp_presence(element["condition"])
						if presence==1:
							timestamp_usage.append(("if condition", c1, function_name, tipo, element["condition"]))
							c1+=1
					#check require conditions
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require':
						presence=0
						timestamp_presence(element['expression']['arguments'][0])
						if presence==1:
							timestamp_usage.append(("require condition", c2, function_name, tipo, element['expression']['arguments'][0]))
							c2+=1
					#check while conditions
					if key=='statements' and element['type']=='WhileStatement':
						presence=0
						timestamp_presence(element["condition"])
						if presence==1:
							timestamp_usage.append(("while condition", c3, function_name, tipo, element["condition"]))
							c3+=1
					
					search_timestamp(element, function_name, tipo, visibility, modifiers)
			elif isinstance(value, dict):
				l+=1
				if 'type' in value and value['type']=='IfStatement':
						presence=0
						timestamp_presence(value["condition"])
						if presence==1:
							timestamp_usage.append(("if condition", c1, function_name, tipo, l, visibility, modifiers, value['trueBody'], value['falseBody']))
							c1+=1
				search_timestamp(value, function_name, tipo, visibility, modifiers)
			else:
				l+=1

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
				print("format assignment: \"assignment\", Variable, Function/Modifier Name")
				print("format condition: Condition Type, Occurrence #n, Function/Modifier Name\n")
				for i, tupla in enumerate(array):
					if tupla[0]=="assignment":
						print(f"{i + 1}. {tupla[0]},{read(tupla[1])},{tupla[4]} {tupla[3]}")
					else:
						print(f"{i + 1}. {tupla[0]},{tupla[1]},{tupla[3]} {tupla[2]}")
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
		#for tupla in timestamp_usage:
		#	print(tupla)

		#function to check whether a variable appears within an expression (dictionary)
		def variable_presence(dictionary,variable):
			global presence
			if not isinstance(dictionary, dict):
				return 0
			if not isinstance(variable, dict):
				variable={'type': 'Identifier','name': variable}
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
		def scroll_definitions_local(dictionary,variable_name, function, tipo, line, functionC=None, tipoC=None):
			global l
			global presence
			global sub_var
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							return 0
						#verifies that it is in the considered function
						if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
							scroll_definitions_local(element,variable_name, function, tipo, line, element['name'], "function")
							continue
						if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
							scroll_definitions_local(element,variable_name, function, tipo, line, element['name'], "modifier")
							continue
						
						if key=='subNodes' and element['type']=='StateVariableDeclaration' and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], l, "s", functionC, tipoC))
						#verification variable definition in functions
						if key=='statements' and element['type']=='VariableDeclarationStatement' and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], l, "l", functionC, tipoC))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element['expression']['right'],variable_name)
							if presence==1:
								if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
									sub_var.append((element['expression']['left'], l, "s", functionC, tipoC))
								else:
									sub_var.append((element['expression']['left'], l, "l", functionC, tipoC))				

						scroll_definitions_local(element,variable_name, function, tipo, line, functionC, tipoC)
				elif isinstance(value, dict):
					l+=1
					scroll_definitions_local(value,variable_name, function, tipo, line, functionC, tipoC)
				else:
					l+=1


		def scroll_definitions_state(dictionary,variable_name, functionC=None, tipoC=None):
			global l
			global presence
			global sub_var
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							return 0
						#verifies that it is in the considered function
						if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
							scroll_definitions_state(element,variable_name, element['name'], "function")
							continue
						if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
							scroll_definitions_state(element,variable_name, element['name'], "modifier")
							continue
						
						if key=='subNodes' and element['type']=='StateVariableDeclaration':
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], l, "s", functionC, tipoC))
						#verification variable definition in functions
						if key=='statements' and element['type']=='VariableDeclarationStatement':
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['identifier'], l, "l", functionC, tipoC))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
							presence=0
							variable_presence(element['expression']['right'],variable_name)
							if presence==1:
								if (element['expression']['left']['type']=='Identifier' and element['expression']['left'] in state_variables) or (element['expression']['left']['type']=='IndexAccess' and element['expression']['left']['base'] in state_variables):
									sub_var.append((element['expression']['left'], l, "s", functionC, tipoC))
								else:
									sub_var.append((element['expression']['left'], l, "l", functionC, tipoC))				

						scroll_definitions_state(element,variable_name, functionC, tipoC)
				elif isinstance(value, dict):
					l+=1
					scroll_definitions_state(value,variable_name, functionC, tipoC)
				else:
					l+=1



		#assignment tuple count 
		c=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				c+=1

		#calculation of variable sets that are initialized using the variables defined with the timestamp
		print()
		related_variables = [[] for _ in range(c)]
		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				sub_var=[]
				l=0
				if var[2]=="l":
					scroll_definitions_local(contract_json,var[1],var[3],var[4],var[5])
				elif var[2]=="s":
					scroll_definitions_state(contract_json,var[1])
				else:
					print("Errore")
					sys.exit()
				for agg in sub_var:
					if agg not in related_variables[i]:
						related_variables[i].append(agg)
				while sub_var!=[]:
					cycle=sub_var
					sub_var=[]
					for vari in cycle:
						l=0
						if vari[2]=="l":
							scroll_definitions_local(contract_json,vari[0],vari[3],vari[4],vari[1])
						elif vari[2]=="s":
							scroll_definitions_state(contract_json,vari[0])
						else:
							print("Errore")
							sys.exit()

					for agg in sub_var:
						if agg in related_variables[i] or agg==var[1]:
							sub_var.remove(agg)
						else:
							related_variables[i].append(agg)
				i+=1
		
		#for elem in related_variables:
		#	print("-----------------------------------------")
		#	for el in elem:
		#		print(el)
		#		print()

		
		print("\n--------------------------------------------------\n")
		l=0
		#search_conditions(contract_json)

		def variable_presence_arguments(dictionary,variable):
			if not isinstance(dictionary, list):
				print("ERRORE")
				return 0
			for elem in  dictionary:
				variable_presence(elem,variable)

		def control_functions(dictionary, var, scope, fun, tipo, line, functionC=None, tipoC=None):
			global l
			global check
			global presence
			global check_spec
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							return 0
						if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
							control_functions(element,var, scope, fun, tipo, line, element['name'], "function")
							continue
						if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
							control_functions(element, var, scope, fun, tipo, line, element['name'], "modifier")
							continue			

						control_functions(element, var, scope, fun, tipo, line, functionC, tipoC)
				elif isinstance(value, dict):
					if key=="expression" and "type" in value and value["type"]=="FunctionCall" and ((scope=="l" and l>=line and tipo==tipoC and fun==functionC) or scope=="s"):
						presence=0
						variable_presence_arguments(value["arguments"], var)
						if "name" in value["expression"] and value["expression"]["name"]=="require":
							presence=0
						if presence==1:
							check=1
							check_spec=1
					l+=1
					control_functions(value, var, scope, fun, tipo, line, functionC, tipoC)
				else:
					l+=1

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
		
		def var_dang_cond(cond,var):
			global check
			global presence
			global check_spec
			if not isinstance(cond, dict):
				return 0
			if "type" in cond and cond["type"]=="BinaryOperation" and cond["operator"]=="==":
				presence=0
				variable_presence(cond["left"],var)
				variable_presence(cond["right"],var)
				if presence==1:
					check=1
					check_spec=1

			for key, value in cond.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						control_condition(element)
				elif isinstance(value, dict):
					control_condition(value)
		
		def check_condition_presence(dictionary, var, scope, fun, tipo, line, functionC=None, tipoC=None):
			global l
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							return 0
						#verifies that it is in the considered function
						if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
							check_condition_presence(element,var, scope, fun, tipo, line, element['name'], "function")
							continue
						if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
							check_condition_presence(element, var, scope, fun, tipo, line, element['name'], "modifier")
							continue	

						if key=='statements' and element['type']=='IfStatement' and ((scope=="l" and l>=line and tipo==tipoC and fun==functionC) or scope=="s"):
							var_dang_cond(element["condition"], var)
						#check require conditions
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require' and ((scope=="l" and l>=line and tipo==tipoC and fun==functionC) or scope=="s"):
							var_dang_cond(element['expression']['arguments'][0], var)
						#check while conditions
						if key=='statements' and element['type']=='WhileStatement' and ((scope=="l" and l>=line and tipo==tipoC and fun==functionC) or scope=="s"):
							var_dang_cond(element["condition"], var)
		

						check_condition_presence(element, var, scope, fun, tipo, line, functionC, tipoC)
				elif isinstance(value, dict):
					l+=1
					check_condition_presence(value, var, scope, fun, tipo, line, functionC, tipoC)
				else:
					l+=1


		alert_td = ['s'] * len(timestamp_usage)
		i=0
		a_count=0
		check_spec=0
		for var in timestamp_usage:
			check=0
			if var[0]=="assignment":
				l=0
				check_spec=0
				control_functions(contract_json,var[1],var[2],var[3],var[4],var[5])
				if check_spec==1:
					alert_string+="\n!!!ATTENTION!!! The variable "+read(var[1])+", defined using block timestamp, is used as a parameter in a function call. Check the function implementation"
				l=0
				check_spec=0
				check_condition_presence(contract_json,var[1],var[2],var[3],var[4],var[5])
				if check_spec==1:
					alert_string+="\n!!!ATTENTION!!! The variable "+read(var[1])+", defined using block timestamp, is used in a condition, checking it to be equal to another value"
				for vari in related_variables[a_count]:
					l=0
					check_spec=0
					control_functions(contract_json,vari[0],vari[2],vari[3],vari[4],vari[1])
					if check_spec==1:
						alert_string+="\n!!!ATTENTION!!! The variable "+read(vari[0])+", defined directly or indirectly with "+read(var[1])+"(in turn defined using block timestamp), is used as a parameter in a function call. Check the function implementation"
					l=0
					check_spec=0
					check_condition_presence(contract_json,vari[0],vari[2],vari[3],vari[4],vari[1])
					if check_spec==1:
						alert_string+="\n!!!ATTENTION!!! The variable "+read(vari[0])+", defined directly or indirectly with "+read(var[1])+"(in turn defined using block timestamp), is used in a condition, checking it to be equal to another value"
				if check==1:
					alert_td[i]='v'
				a_count+=1
			else:
				control_condition(var[4])
				if check==1:
					alert_string+="\n!!!ATTENTION!!! The #"+str(var[1])+" "+var[0]+" in the "+var[2]+" "+var[3]+" is checking the timestamp to be equal to some other values/variables"
					alert_td[i]='v'

			i+=1
		#print(alert_td)

		
		print("{:<50} {}".format("CHECK", "RESULTS"))

		print()

		print("-Timestamp NOT used EXCLUSIVELY for majority")
		print("or minority comparisons-")
		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if alert_td[i]=="v":
					print("{:<53} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[4]) + " " + str(var[3]) + ")", "T"))
				elif alert_td[i]=="s":
					print("{:<53} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[4]) + " " + str(var[3]) + ")", "F"))
			else:
				if alert_td[i]=="v":
					print("{:<53} {}".format("(" + var[0] + "," + str(var[1]) + "," + var[3] + " " + str(var[2]) + ")", "T"))
				elif alert_td[i]=="s":
					print("{:<53} {}".format("(" + var[0] + "," + str(var[1]) + "," + var[3] + " " + str(var[2]) + ")", "F"))
			i+=1

		
		print("\n--------------------------------------------------\n")
		print("                    DETAILED OUTPUT\n")
		print(alert_string)

		print("\n--------------------------------------------------\n")
		print("                    FINAL RESULTS\n")
		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if alert_td[i]=="v":
					print("{:<53} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[4]) + " " + str(var[3]) + ")", "True Positive"))
				elif alert_td[i]=="s":
					print("{:<53} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[4]) + " " + str(var[3]) + ")", "False Positive"))
			else:
				if alert_td[i]=="v":
					print("{:<53} {}".format("(" + var[0] + "," + str(var[1]) + "," + var[3] + " " + str(var[2]) + ")", "True Positive"))
				elif alert_td[i]=="s":
					print("{:<53} {}".format("(" + var[0] + "," + str(var[1]) + "," + var[3] + " " + str(var[2]) + ")", "False Positive"))
			i+=1


if vulnerabilities_selection[2]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("///////////")
	print("REENTRANCY")
	print("//////////")
	print()

	alert_string=""

	#array to store information about functions possibly vulnerable to Reentrancy
	risky_calls=[]
	
	#list of membername functions which may look external but are not
	exception=["pop","push","add","sub","mul","div","mod","send","value"]

	l=0
	cont=0
	#function to derive all function names that contain an external call through call
	def search_functions(dictionary, function_name=None, visibility=None, modifiers=None):
		global l
		global cont
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				l+=1
				for element in value:
					if not isinstance(element, dict):
						continue
					if key=='subNodes' and 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						visibility=element['visibility']
						modifiers=element['modifiers']
						cont=0
					if 'type' in element and element['type']=="NameValueExpression" and 'memberName' in element['expression'] and element['expression']['memberName']=='call':
						#print("trovato 1")
						cont+=1
						risky_calls.append((function_name,visibility,modifiers,element,element['expression']['expression'],l,cont))
					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='MemberAccess' and element['expression']['expression']['type']=='MemberAccess' and element['expression']['memberName']=='value' and element['expression']['expression']['memberName']=='call':
						#print("trovato 2")
						cont+=1
						risky_calls.append((function_name,visibility,modifiers,element,element['expression']['expression']['expression'],l,cont))
					if 'type' in element and element['type']=="FunctionCall" and element['expression']['type']=='MemberAccess' and element['expression']['memberName'] not in exception:
						if element['expression']['memberName']!="transfer" or len(element["arguments"])!=1:
							if element['expression']['expression']['type']!="Identifier" or element['expression']['expression']['name']!="abi":
								#print(element['expression']['memberName'])
								#print("trovato 3")
								cont+=1
								risky_calls.append((function_name,visibility,modifiers,element,element['expression']['expression'],l,cont))
							
										
					search_functions(element, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				l+=1
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call':
					#print("trovato 4")
					cont+=1
					risky_calls.append((function_name,visibility,modifiers,value,value['expression']['expression'],l,cont))
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['memberName']=='call':
					#print("trovato 5")
					cont+=1
					risky_calls.append((function_name,visibility,modifiers,value,value['expression']['expression']['expression'],l,cont))
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['memberName'] not in exception:
					if value['expression']['memberName']!="transfer" or len(value["arguments"])!=1:
						if value['expression']['expression']['type']!="Identifier" or value['expression']['expression']['name']!="abi":
							#print(value['expression']['memberName'])
							#print("trovato 6")
							cont+=1
							risky_calls.append((function_name,visibility,modifiers,value,value['expression']['expression'],l,cont))
				search_functions(value, function_name, visibility, modifiers)
			else:
				l+=1

	l=0
	search_functions(contract_json)
	print()

	#checks whether there are actually functions in the code that might seem vulnerable
	if risky_calls==[]:
		print("No functions in code were found that might appear vulnerable to Reentrancy\n")
	else:

		#User's choice of which functions to go to check for Reentrancy risk
		def tuple_selection(array):
			tuple_to_keep=[]
			lista=[]
			for tupla in array:
				lista.append(tupla[0])
			lista=list(set(lista))
			if alert_selection:
				choice=alert_selection
			else:
				for i,func in enumerate(lista):
					print(str(i+1) +". " + str(func))
				choice=input("\nInsert the number of the functions that need to be verified (separated by comma) - put n for none / put a for all:")
			if choice == "a" or choice == "n" or all(number.strip().isdigit() for number in choice.split(',')):
				if choice=="n":
					return tuple_to_keep
				if choice=="a":
					return array
				selected_indexes=[int(index.strip()) - 1 for index in choice.split(',')]
				#print(selected_indexes)
				for indice in selected_indexes:
					if 0<= indice < len(lista):
						for tupla in array:
							if tupla[0]==lista[indice]:
								tuple_to_keep.append(tupla)
				return tuple_to_keep
			else:
				if alert_selection:
					print("!INVALID ARGUMENT FOR TUPLE SELECTION!")
				else:
					print("!INVALID INPUT!")
				print()
				return tuple_selection(array)

		risky_calls=tuple_selection(risky_calls)
		results=array('u',['t']*len(risky_calls))

		print("\n--------------------------------------------------\n")
		print("{:<40} {}".format("CHECK", "RESULTS"))
		alert_string=""

		#VERIFY FPs BASED ON FUNCTIONS VISIBILITY 
		print("-Function is public/external-")
		alert_string+="\nCHECK REFERENCE:-Function is public/external-"
		i=0
		for variable in risky_calls:
			if variable[1]=="private" or variable[1]=="internal":
				print("{:<43} {}".format(str(variable[0]) + " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because of the visibility"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1

		print()
		alert_string+="\n"

		#VERIFY FPs BASED ON FUNCTIONS MODIFIERS 
		print("-Absence of Modifiers-")
		alert_string+="\n\nCHECK REFERENCE:-Absence of Modifiers-"
		i=0
		for variable in risky_calls:
			if variable[2]!=[]:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because of the modifiers, please check their restrictions"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1

		alert_string+="\n"

		#function to check whether the external call is subject to some if condition
		check=0
		def search_conditions(dictionary,ident,function=None, plus=None):
			if not isinstance(dictionary, dict):
				return 0
			global check
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_conditions(element, ident,function, plus)
								continue
							else:
								continue
						search_conditions(element, ident,function, plus)
					
				elif isinstance(value, dict):
					if plus==1 and value==ident:
						check=1
					if key=='trueBody' or key=='falseBody':
						search_conditions(value, ident,function, 1)
					search_conditions(value, ident,function,plus)

		#function to check whether the external call is subject to some require condition
		found_require=0
		def search_require(dictionary,ident,function):
			global found_require
			global check
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_require(element, ident,function)
								continue
							else:
								continue
						search_require(element, ident,function)
					
				elif isinstance(value, dict):
					if found_require==1 and value==ident:
						check=1
					if key=='expression' and 'type' in value and value['type']=="Identifier" and value['name']=="require":
						found_require=1
					search_require(value, ident,function)

		print("\n-Externall function call not subject to conditions")
		print(" (if or require)-")
		alert_string+="\n\nCHECK REFERENCE:-Externall function call not subject to conditions (if or require)-"
		i=0
		for variable in risky_calls:
			search_conditions(contract_json,variable[3],variable[0])
			search_require(contract_json,variable[3],variable[0])
			if check==1:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because the call is subject to some conditions (if or require). Check their restrictions"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1
			check=0
			found_require=0	

		#function to look up the definition of the variable on which the call function is called (address to which the external call is made)
		definition=""
		final_definition=""
		def search_definition(dictionary,variable_name,function, ident):
			if not isinstance(dictionary, dict):
				return 0
			global definition
			global final_definition
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if "type" in element and element["type"]=="StateVariableDeclaration" and element["variables"][0]["identifier"]==variable_name:
								definition=element["initialValue"]
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								search_definition(element, variable_name, function, ident)
								continue
							else:
								continue
						if key=="statements":
							if "type" in element and element["type"]=="VariableDeclarationStatement" and variable_name['type']=="Identifier" and "name" in element["variables"][0] and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						search_definition(element, variable_name, function, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					if value==ident:
						final_definition=definition
					search_definition(value, variable_name, function, ident)

		def extract_parameters(dictionary,function):
			if not isinstance(dictionary, dict):
				return 0
			global parameters
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition' and element['name']==function:
								for par in element["parameters"]:
									parameters.append(par["identifier"])
								extract_parameters(element, function)
								continue
							else:
								continue
						extract_parameters(element, function)
					
				elif isinstance(value, dict):
					extract_parameters(value, function)


		print("\n-External call Adr. controllable by user-")
		alert_string+="\n\nCHECK REFERENCE:-External call Adr. controllable by user-"
		i=0
		msg_sender={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'sender'}
		parameters=[]
		for funz in risky_calls:
			definition=""
			final_definition=""
			parameters.clear()
			search_definition(contract_json, funz[4], funz[0], funz[3])
			extract_parameters(contract_json,funz[0])
			#print(funz[4])
			#print(final_definition)
			#print(parameters)
			if final_definition!=msg_sender and final_definition not in parameters and ((funz[4]["type"]=="Identifier" and funz[4] not in parameters) or (funz[4]["type"]=="FunctionCall" and funz[4]["arguments"][0] not in parameters)):
				print("{:<43} {}".format(str(funz[0])+ " #" + str(funz[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(funz[6]) + " external call in \"" + str(funz[0]) + "\" function could be a FALSE POSITIVE because the call is made on an address not controllable by user (not equal to msg.sender and not passed as a parameter)"
			else:
				print("{:<43} {}".format(str(funz[0])+ " #" + str(funz[6]), "T"))
			i+=1

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

		#function to check whether any state variable is changed after the external call
		def state_verification(dictionary, function, line, functionC=None):
			global l
			global check
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							continue
						if key=='subNodes':
							if 'type' in element and element['type']=='FunctionDefinition':
								state_verification(element, function, line, element['name'])
								continue
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and function==functionC:
							for var in state_variables:
								if (element['expression']['left']==var or ('base' in element['expression']['left'] and element['expression']['left']['base']==var)) and l>line:
									check=1
						state_verification(element, function, line, functionC)
					
				elif isinstance(value, dict):
					l+=1
					state_verification(value, function, line, functionC)
				else:
					l+=1

		extract_variables(contract_json)

		print("\n-State Variable changed after external call-")
		alert_string+="\n\nCHECK REFERENCE:-State Variable changed after external call-"
		i=0
		for variable in risky_calls:
			l=0
			check=0
			state_verification(contract_json,variable[0],variable[5])
			if check==0:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because there are no changes to the status variables after the external call"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1

		#function to check whether the amount to be transferred includes msg.value
		msg_value={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'value'}
		def verify_amount(list_arg):
			global check
			if not isinstance(list_arg, list):
				return 0
			for arg in list_arg:
				if arg==msg_value:
					check=1
				elif 'type' in arg and arg['type']=="BinaryOperation":
					if (arg['operator']=="*" and (arg['left']==msg_value or arg['right']==msg_value)) or (arg['operator']=="/" and arg['left']==msg_value):
						check=1

		print("\n-Amount NOT directly proportional to msg.value-")
		alert_string+="\n\nCHECK REFERENCE:-Amount NOT directly proportional to msg.value-"
		i=0	
		for variable in risky_calls:
			check=0
			
			if 'arguments' in variable[3]['arguments']:
				#print(variable[3]['arguments']['arguments'])
				verify_amount(variable[3]['arguments']['arguments'])
			else:
				#print(variable[3]['arguments'])
				verify_amount(variable[3]['arguments'])
			if check==1:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because an argument (supposed to be amount to transfer) is directly proportional to msg.value. Check if actually the argument identified is actually the amount to transfer"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1

		print("\n--------------------------------------------------\n")
		print("               DETAILED OUTPUT\n")
		print(alert_string)

		print("\n--------------------------------------------------\n")
		print("                FINAL RESULTS\n")
		lista=[]
		for i,tupla in enumerate(risky_calls):
			if i==0:
				lista.append(tupla[0])
			elif tupla[0]!=risky_calls[i-1][0]:
				lista.append(tupla[0])
		
		for funz in lista:
			tot=0
			i=0
			for var in risky_calls:
				if var[0]==funz and results[i]=='t':
					tot=1
				i+=1
			if tot==1:
				print("{:<35} {}".format(str(funz), "True Positive"))
			elif tot==0:
				print("{:<35} {}".format(str(funz), "False Positive"))
			i+=1
		
