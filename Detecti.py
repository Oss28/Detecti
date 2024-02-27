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
D D D     E E E E   T T T T   E E E E   C C C C  T T T T  III
D     D   E            T      E        C            T      I
D     D   E E E E      T      E E E E  C            T      I
D     D   E            T      E        C            T      I
D D D     E E E E      T      E E E E   C C C C     T     III
"""

print(pixel_art_detecti)

print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
print("DESCRIPTION OF OUTPUT (divided into 3 sections)")
print("1. SINGLE CHECKS: For each part of the code analyzed, it is reported whether the result of the check assumes it is a true positive (T) or a false positive (F)")
print("2. FINAL RESULTS: For each part of the code analyzed, the final verdict (derived from the overall consideration of all checks) is clearly indicated")
print("3. DETAILED OUTPUT: It is possible to find more detailed notes of what was found in the analysis")
print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
        
    
#selection of vulnerabilities to be verified
def select_vulnerabilities(selection_string):
	if selection_string:
		vulnerabilities_selection = [0, 0, 0]  # Inizializza tutte le vulnerabilità a non selezionate
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
        # Se nessuna selezione è stata fornita come argomento, richiedi input manuale
		print("Select which vulnerabilities to check:")
		print("(enter the corresponding numbers, divided by comma)")
		vulnerabilities_selection = [0, 0, 0]
		print("1. Unchecked Call Return Value")
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

# Run vulnerability screening
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

#part of code dealing with UNCHECKED CALL RETURN VALUE vulnerability 
if vulnerabilities_selection[0]==1:
	print("/////////////////////////")
	print("UNCHECKED CALL RETURN VALUE")
	print("/////////////////////////")
	print()

	#array to store the information about variables on which send is called, extracted with the subsequent function
	send_variables=[]

	#extract information about variables on which send is called
	def search_send_variables(dictionary, function_name=None, visibility=None, modifiers=None):
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
					search_send_variables(element, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				if 'type' in value and value['type']=="FunctionCall" and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					send_variables.append((function_name, visibility, value['expression']['expression'], modifiers, value))
				search_send_variables(value, function_name, visibility, modifiers)


	search_send_variables(contract_json)

	#array to store the information about variables on which call is called, extracted with the subsequent function
	call_variables=[]

	#extract information about variables on which call is called
	def search_call_variables(dictionary, function_name=None, visibility=None, modifiers=None):
		if not isinstance(dictionary, dict):
			return 0
		for key, value in dictionary.items():
			if isinstance(value, list):
				for element in value:
					if not isinstance(element, dict):
						return 0
					if 'type' in element and element['type']=='FunctionDefinition':
						function_name=element['name']
						visibility=element['visibility']
						modifiers=element['modifiers']
					if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
						continue
					search_call_variables(element, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call' and (value['expression']['expression']['type']=="Identifier" or value['expression']['expression']['type']=="IndexAccess" or value['expression']['expression']['type']=="MemberAccess"):
					call_variables.append((function_name, visibility, value['expression']['expression'], modifiers, value))
				search_call_variables(value, function_name, visibility, modifiers)

	search_call_variables(contract_json)

	#checks whether there are actually instructions in the code that might seem vulnerable
	if send_variables==[] and call_variables==[]:
		print("No parts of code were found that might appear vulnerable to Unchecked Externall Call\n")
	else:
		#function to allow the user to choose which send and call calls they want to verify
		def tuple_selection(array,tipo):
			tuple_to_keep=[]
			if alert_selection:
				choice=alert_selection
			else:
				if tipo=="send":
					print("format: Function, Variable on which send is called")
				elif tipo=="call":
					print("format: Function, Variable on which call is called")
				else:
					print("ERROR")
					return 0
				for i, tupla in enumerate(array):
					print(f"{i + 1}. {tupla[0]},{read(tupla[2])}")
				choice=input("Insert the number of the tuples that need to be verified (separated by comma) - put n for none / put a for all:")
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
				return tuple_selection(array,tipo)


		if send_variables!=[]:
			send_variables=tuple_selection(send_variables,"send")
		if call_variables!=[]:
			print("----------------------------------")
			call_variables=tuple_selection(call_variables,"call")

		#arrays used in the "Final Results" output - store overall verdict for each send/call instruction
		results_send=array('u',['t']*len(send_variables))
		results_call=array('u',['t']*len(call_variables))

		print("\n--------------------------------------------------\n")
		print("{:<40} {}".format("CHECK", "RESULTS"))
		print()
		alert_string=""

		#FPs VERIFICATION BASED ON FUNCTIONS VISIBILITY 
		print("-Function is public/external-")
		alert_string+="\nCHECK REFERENCE:-Function is public/external-"
		i=0
		for variable in send_variables:
			if variable[1]=="private" or variable[1]=="internal":
				print("{:<43} {}".format(read(variable[2]), "F"))
				alert_string+="\n!!!ATTENTION!!!! The send call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because of the visibility of the function \"" + variable[0] + "\" which is " + variable[1]
				results_send[i]='f'
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1

		i=0
		for variable in call_variables:
			if variable[1]=="private" or variable[1]=="internal":
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_call[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The call call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because of the visibility of the function \"" + variable[0] + "\" which is " + variable[1]
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1

		print()
		alert_string+="\n"

		#FPs VERIFICATION BASED ON FUNCTIONS MODIFIERS 
		print("-Absence of Modifiers-")
		alert_string+="\nCHECK REFERENCE:-Absence of Modifiers-"
		i=0
		for variable in send_variables:
			if variable[3]!=[]:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_send[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The send call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because of the modifiers of the function \"" + variable[0] + "\", please check their restrictions"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1

		i=0
		for variable in call_variables:
			if variable[3]!=[]:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_call[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The call call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because of the modifiers of the function \"" + variable[0] + "\", please check their restrictions"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
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
		def search_definition(dictionary,variable_name,function, tipo, ident):
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
								search_definition(element, variable_name, function, tipo, ident)
								continue
							else:
								continue
						if key=="statements":
							if "type" in element and element["type"]=="VariableDeclarationStatement" and "name" in element["variables"][0] and variable_name['type']=="Identifier" and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						search_definition(element, variable_name, function, tipo, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					#condition to check when to stop looking for assignments to the variable, we do not want to consider those after the call to send
					if key=='expression' and value==ident:
						final_definition=definition
					search_definition(value, variable_name, function, tipo, ident)

		print()

		#checks whether the variables on which send/call is called are equal to msg.sender
		print("-Variable defined differently")
		print(" from address of msg.sender-")
		alert_string+="\nCHECK REFERENCE:-Variable defined differently from address of msg.sender-"
		i=0
		for variable in send_variables:
			search_definition(contract_json,variable[2],variable[0],"send",variable[4])
			if final_definition==msg_sender or variable[2]==msg_sender:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_send[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The send call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the variable is assigned to the address of message sender (possible attacker)"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1
			definition="Not Found"
			final_definition="Not Found"

		i=0
		for variable in call_variables:
			search_definition(contract_json,variable[2],variable[0],"call",variable[4])
			if final_definition==msg_sender or variable[2]==msg_sender:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_call[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The call call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the variable is assigned to the address of message sender (possible attacker)"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
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
		print("-Send/Call not subject to conditions")
		print(" (if or require)-")
		alert_string+="\nCHECK REFERENCE:-Send/Call not subject to conditions (if or require)-"
		i=0
		for variable in send_variables:
			search_conditions(contract_json,variable[4],variable[0])
			search_require(contract_json,variable[4],variable[0])
			if check==1:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_send[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The send call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the call is subject to some conditions (if or require), please check their implementations"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1
			check=0
			found_require=0	

		i=0
		for variable in call_variables:
			search_conditions(contract_json,variable[4],variable[0])
			search_require(contract_json,variable[4],variable[0])
			if check==1:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_call[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The call call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the call is subject to some conditions (if or require), please check their implementations"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
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
						last_statement(element, function)
					
				elif isinstance(value, dict):
					last_statement(value, function)

		#checks whether the send/call instruction is the last instruction in the function
		print("\n-Send/Call not last operation-")
		alert_string+="\n\nCHECK REFERENCE:-Send/Call not last operation-"
		i=0
		for variable in send_variables:
			final=""
			last_statement(contract_json,variable[0])
			if 'expression' in final and final['expression']==variable[4]:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_send[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The send call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the call is the last operation in \""+ variable[0] +"\" function"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1
			
		i=0
		for variable in call_variables:
			final=""
			last_statement(contract_json,variable[0])
			if 'expression' in final and final['expression']==variable[4]:
				print("{:<43} {}".format(read(variable[2]), "F"))
				results_call[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The call call on the \"" + read(variable[2]) + "\" variable could be a FALSE POSITIVE because the call is the last operation in \""+ variable[0] +"\" function"
			else:
				print("{:<43} {}".format(read(variable[2]), "T"))
			i+=1

		print("\n--------------------------------------------------\n")	
		print("                FINAL RESULTS\n")
		i=0
		for variable in send_variables:
			if results_send[i]=='t':
				print("{:<35} {}".format(read(variable[2]), "True Positive"))
			elif results_send[i]=='f':
				print("{:<35} {}".format(read(variable[2]), "False Positive"))
			i+=1
		i=0
		for variable in call_variables:
			if results_call[i]=='t':
				print("{:<35} {}".format(read(variable[2]), "True Positive"))
			elif results_call[i]=='f':
				print("{:<35} {}".format(read(variable[2]), "False Positive"))
			i+=1
		print("\n--------------------------------------------------\n")
		print("                DETAILED OUTPUT")
		print(alert_string)

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
	c1=1
	c2=1
	c3=1

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
							timestamp_usage.append(("assignment",element['variables'][0]['name'],function_name, tipo, l, visibility, modifiers))
					#verification variable definition in functions
					if key=='statements' and element['type']=='VariableDeclarationStatement':
						presence=0
						timestamp_presence(element["initialValue"])
						if presence==1:
							timestamp_usage.append(("assignment",element['variables'][0]['name'],function_name, tipo, l, visibility, modifiers))
					#check assignments
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
						presence=0
						timestamp_presence(element['expression']['right'])
						if presence==1:
							timestamp_usage.append(("assignment",element['expression']['left'],function_name, tipo, l, visibility, modifiers))
					#check if conditions
					if key=='statements' and element['type']=='IfStatement':
						presence=0
						timestamp_presence(element["condition"])
						if presence==1:
							timestamp_usage.append(("if condition", c1, function_name, tipo, l, visibility, modifiers, element['trueBody'], element['falseBody']))
							c1+=1
					#check require conditions
					if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require':
						presence=0
						timestamp_presence(element['expression']['arguments'][0])
						if presence==1:
							timestamp_usage.append(("require condition", c2, function_name, tipo, l, visibility, modifiers))
							c2+=1
					#check while conditions
					if key=='statements' and element['type']=='WhileStatement':
						presence=0
						timestamp_presence(element["condition"])
						if presence==1:
							timestamp_usage.append(("while condition", c3, function_name, tipo, l, visibility, modifiers, element['body']))
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
				print("format condition: Condition Type, Occurrence #n, Function/Modifier Name")
				for i, tupla in enumerate(array):
					print(f"{i + 1}. {tupla[0]},{read(tupla[1])},{tupla[3]} {tupla[2]}")
				choice=input("Insert the number of the tuples that need to be verified (separated by comma) - put n for none / put a for all:")
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
		def scroll_definitions(dictionary,variable_name, variabile_orig, function, tipo, line, functionC=None, tipoC=None):
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
							scroll_definitions(element,variable_name, variabile_orig, function, tipo, line, element['name'], "function")
							continue
						if key=='subNodes' and 'type' in element and element['type']=='ModifierDefinition':
							scroll_definitions(element,variable_name, variabile_orig, function, tipo, line, element['name'], "modifier")
							continue
						
						if key=='subNodes' and element['type']=='StateVariableDeclaration' and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['name'], l))
						#verification variable definition in functions
						if key=='statements' and element['type']=='VariableDeclarationStatement' and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element["initialValue"],variable_name)
							if presence==1:
								sub_var.append((element['variables'][0]['name'], l))
						#check assignments
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='BinaryOperation' and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and l>=line and (tipo==None or (tipo==tipoC and function==functionC)):
							presence=0
							variable_presence(element['expression']['right'],variable_name)
							if presence==1:
								sub_var.append((element['expression']['left'], l))				

						scroll_definitions(element,variable_name, variabile_orig, function, tipo, line, functionC, tipoC)
				elif isinstance(value, dict):
					l+=1
					scroll_definitions(value,variable_name, variabile_orig, function, tipo, line, functionC, tipoC)
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
		new=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				sub_var=[]
				l=0
				scroll_definitions(contract_json,var[1],var[1],var[2],var[3],var[4])
				for agg in sub_var:
					new=0
					for old in related_variables[i]:
						if agg==old:
							new=1
					if new==0:
						related_variables[i].append(agg)
				while sub_var!=[]:
					cycle=sub_var
					sub_var=[]
					for vari in cycle:
						l=0
						scroll_definitions(contract_json,vari[0],var[1],var[2],var[3],vari[1])
					
					for agg in sub_var:
						new=0
						for old in related_variables[i]:
							if agg==old or agg==var[1]:
								new=1
								sub_var.remove(agg)
						if new==0:
							related_variables[i].append(agg)
				i+=1

		#Extract variables that are used as the amount of cryptocurrency to be transferred
		variables_money=[]
		def search_variables(dictionary, function_name=None, tipo2=None, defin=None, tipo=None):
			global l
			if not isinstance(dictionary, dict):
				#print(dictionary)\
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l+=1
					for element in value:
						if not isinstance(element, dict):
							continue
						if 'type' in element and element['type']=='FunctionDefinition':
							function_name=element['name']
							tipo2="function"
						if 'type' in element and element['type']=='ModifierDefinition':
							function_name=element['name']
							tipo2="modifier"
						if key=='arguments' and defin==1:
							search_variables(element, function_name, tipo2, 1, tipo)
						else:
							search_variables(element, function_name, tipo2)
				elif isinstance(value, dict):
					l+=1
					if (key=='right' or key=='left') and 'type' in value and (value['type']=='Identifier' or value['type']=='IndexAccess') and defin==1:
						variables_money.append((function_name, tipo, value, tipo2, l))

					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='send':
						if value['arguments'][0]['type']=='Identifier' or value['arguments'][0]['type']=='IndexAccess':
							variables_money.append((function_name, "send", value['arguments'][0], tipo2, l))
							search_variables(value, function_name, tipo2)
						else:
							search_variables(value, function_name, tipo2, 1, "send")
					elif (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='transfer':
						if value['arguments'][0]['type']=='Identifier' or value['arguments'][0]['type']=='IndexAccess':
							variables_money.append((function_name, "transfer",value['arguments'][0], tipo2, l))
							search_variables(value, function_name, tipo2)
						else:
							search_variables(value, function_name, tipo2, 1, "transfer")
					elif (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'type' in value['expression'] and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['memberName']=='call':
						if value['expression']['arguments']['arguments'][0]['type']=='Identifier' or value['expression']['arguments']['arguments'][0]['type']=='IndexAccess':
							variables_money.append((function_name, "call",value['expression']['arguments']['arguments'][0], tipo2, l))
							search_variables(value, function_name, tipo2)
						else:
							search_variables(value, function_name, tipo2, 1, "call")
					elif key=='expression' and defin==1 and 'type' in value and value['type']=='NameValueExpression':
						search_variables(value, function_name, tipo2, 1, tipo)
					elif key=='arguments' and defin==1 and 'type' in value and value['type']=='NameValueList':
						search_variables(value, function_name, tipo2, 1, tipo)
					elif (key=='right' or key=='left') and defin==1:
						search_variables(value, function_name, tipo2, 1, tipo)
					else:
						search_variables(value, function_name, tipo2)
				else:
					l+=1


		search_variables(contract_json)

		#compare variables_money with variables defined using timestamps
		alert_money=array('u',['s']*c)
		i=0
		alt=None
		for var in timestamp_usage:
			if var[0]=="assignment":
				alt=None
				if not isinstance(var[1], dict):
					alt={'type': 'Identifier','name': var[1]}
				for money in variables_money:
					if (var[1]==money[2] or alt==money[2]) and (var[2]==None or var[2]==money[0]) and (var[3]==None or var[3]==money[3]) and var[4]<money[4]:
						alert_money[i]="a"
				for vari in related_variables[i]:
					alt=None
					if not isinstance(vari[0], dict):
						alt={'type': 'Identifier','name': vari[0]}
					for money in variables_money:
						if (vari[0]==money[2] or alt==money[2]) and (var[2]==None or var[2]==money[0]) and (var[3]==None or var[3]==money[3]) and vari[1]<money[4]:
							alert_money[i]="a"
				i+=1

		#function to extract all variables within the condition (dictionary)
		condition_variables=[]
		def extract_variables(dictionary,function):
			global condition_variables
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						extract_variables(element,function)
				elif isinstance(value, dict):
					if (key=="left" or key=="right") and (value['type']=="Identifier" or value['type']=="IndexAccess"):
						condition_variables.append((value, function))
					extract_variables(value,function)

		#function to check whether any of the variables defined using timestamp is present in the condition
		conditions_alert=array('u',['s']*c)
		def variable_verification(line):
			i=0
			alt=None
			global conditions_alert
			for var in timestamp_usage:
				if var[0]=="assignment":
					alt=None
					if not isinstance(var[1], dict):
						alt={'type': 'Identifier','name': var[1]}
					for cond in condition_variables:
						if (var[1]==cond[0] or alt==cond[0]) and (var[2]==None or var[2]==cond[1]) and var[4]<line:
							conditions_alert[i]="a"
					for vari in related_variables[i]:
						alt=None
						if not isinstance(vari[0], dict):
							alt={'type': 'Identifier','name': vari[0]}
						for cond in condition_variables:
							if vari[0]==cond[0] and (var[2]==None or var[2]==cond[1]) and vari[1]<line:
								conditions_alert[i]="a"
					i+=1
		#function to check whether "dangerous" operations are performed within the body of the if/while condition
		dangeorus=0
		def verification_body(dictionary, function):
			global dangeorus
			l2=l
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					l2+=1
					for element in value:
						if not isinstance(element, dict):
							return 0
						if key=='statements' and element['type']=="VariableDeclarationStatement" and element['initialValue']!=None:
							for var in variables_money:
								if function==var[0] and var[2]==element['variables'][0]['identifier'] and var[4]>l2:
									dangeorus=1
						if key=='statements' and element['type']=="ExpressionStatement" and element['expression']['type']=="BinaryOperation" and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-='):
							for var in variables_money:
								if function==var[0] and var[2]==element['expression']['left'] and var[4]>l2:
									dangeorus=1
						verification_body(element, function)
				elif isinstance(value, dict):
					l2+=1
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='send':
						dangeorus=1
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='transfer':
						dangeorus=1
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'type' in value['expression'] and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['memberName']=='call':
						dangeorus=1
					

					verification_body(value, function)
				else:
					l2+=1

		#function to check whether "dangerous" operations are performed after the require condition
		check=0
		def verification_body_require(dictionary, function, req):
			global check
			global dangeorus
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						if ('type' in element and element['type']=='FunctionDefinition' and element['name']!=function) or ('type' in element and element['type']=='ModifierDefinition'):
							continue
						if key=='statements' and element['type']=="VariableDeclarationStatement" and element['initialValue']!=None and check==1:
							for var in variables_money:
								if function==var[0] and var[2]==element['variables'][0]['identifier']:
									dangeorus=1
						if key=='statements' and element['type']=="ExpressionStatement" and element['expression']['type']=="BinaryOperation" and (element['expression']['operator']=='=' or element['expression']['operator']=='+=' or element['expression']['operator']=='-=') and check==1:
							for var in variables_money:
								if function==var[0] and var[2]==element['expression']['left']:
									dangeorus=1
						if key=='statements' and element==req:
							check=1
						verification_body_require(element, function, req)
				elif isinstance(value, dict):
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='send' and check==1:
						dangeorus=1
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'memberName' in value['expression'] and value['expression']['memberName']=='transfer' and check==1:
						dangeorus=1
					if (key=='expression' or key=='initialValue' or key=='right' or key=='left') and value['type']=='FunctionCall' and 'type' in value['expression'] and value['expression']['type']=='NameValueExpression' and value['expression']['expression']['memberName']=='call' and check==1:
						dangeorus=1
					verification_body_require(value, function, req)

		#function to identify all conditions within the code
		def search_conditions(dictionary, function_name=None):
			global condition_variables
			global dangeorus
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
						if 'type' in element and element['type']=='FunctionDefinition':
							function_name=element['name']
						#check if conditions
						if key=='statements' and element['type']=='IfStatement':
							dangeorus=0
							verification_body(element['trueBody'], function_name)
							verification_body(element['falseBody'], function_name)
							if dangeorus==1:
								condition_variables=[]
								extract_variables(element['condition'], function_name)
								variable_verification(l)
						#check require conditions
						if key=='statements' and element['type']=='ExpressionStatement' and element['expression']['type']=='FunctionCall' and 'name' in element['expression']['expression'] and element['expression']['expression']['name']=='require':
							check=0
							dangeorus=0
							verification_body_require(contract_json,function_name,element)
							if dangeorus==1:
								condition_variables=[]
								extract_variables(element['expression']['arguments'][0], function_name)
								variable_verification(l)
						#check while conditions
						if key=='statements' and element['type']=='WhileStatement':
							dangeorus=0
							verification_body(element['body'], function_name)
							if dangeorus==1:
								condition_variables=[]
								extract_variables(element['condition'], function_name)
								variable_verification(l)
						search_conditions(element, function_name)
				elif isinstance(value, dict):
					l+=1
					search_conditions(value, function_name)
				else:
					l+=1

		print("\n--------------------------------------------------\n")
		l=0
		search_conditions(contract_json)
		
		print("{:<40} {}".format("CHECK", "RESULTS"))

		print()

		print("-Timestamp used inside the cryptocurrency")
		print("amount to be transferred-")

		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if alert_money[i]=="a":
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "T"))
				elif alert_money[i]=="s":
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "F"))
				i+=1
			else:
				print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "F"))

		print("\nIf the condition is verified (T), remember to apply the 15-second rule to see if it is a dangerous case")
		print()

		print("-Timestamp used inside a condition")
		print(" regulating a dangerous body")
		print(" (while, if, or require)-")

		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if conditions_alert[i]=="a":
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "T"))
				elif conditions_alert[i]=="s":
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "F"))
				i+=1
			elif var[0]=="if condition":
				dangeorus=0
				verification_body(var[7],var[2])
				verification_body(var[8],var[2])
				if dangeorus==1:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "T"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "F"))
			elif var[0]=="while condition":
				dangeorus=0
				verification_body(var[7],var[2])
				if dangeorus==1:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "T"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "F"))
			elif var[0]=="require condition":
				dangeorus=0
				verification_body_require(contract_json,var[2],var[4])
				if dangeorus==1:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "T"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "F"))


		print("\n--------------------------------------------------\n")
		print("                    FINAL RESULTS\n")
		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if alert_money[i]=="s" and conditions_alert[i]=="s":
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "False Positive"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + read(var[1]) + "," + str(var[2]) + ")", "True Positive"))
				i+=1	
			elif var[0]=="if condition":
				dangeorus=0
				verification_body(var[7],var[2])
				verification_body(var[8],var[2])
				if dangeorus==0:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "False Positive"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "True Positive"))
			elif var[0]=="while condition":
				dangeorus=0
				verification_body(var[7],var[2])
				if dangeorus==0:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "False Positive"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "True Positive"))
			elif var[0]=="require condition":
				dangeorus=0
				verification_body_require(contract_json,var[2],var[4])
				if dangeorus==0:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "False Positive"))
				else:
					print("{:<43} {}".format("(" + var[0] + "," + str(var[1]) + "," + str(var[2]) + ")", "True Positive"))
		print("\n--------------------------------------------------\n")
		print("                    DETAILED OUTPUT\n")

		i=0
		for var in timestamp_usage:
			if var[0]=="assignment":
				if alert_money[i]=="s" and conditions_alert[i]=="s":
					print("!!!ATTENTION!!!! The timestamp used to define \"" + read(var[1]) + "\" variable in \"" + str(var[2]) + "\" function could be a FALSE POSITIVE because it is not used, even indirectly, either to indicate the amount of cryptocurrency to be transferred or in a condition regulating a dangerous body.")
				i+=1	
			elif var[0]=="if condition":
				dangeorus=0
				verification_body(var[7],var[2])
				verification_body(var[8],var[2])
				if dangeorus==0:
					print("!!!ATTENTION!!!! The timestamp used in \"" + var[0] + "\" in \"" + str(var[2]) + "\" function (n"+ str(var[1]) +" occurrence) could be a FALSE POSITIVE because it is not a condition regulating a dangerous body.")
			elif var[0]=="while condition":
				dangeorus=0
				verification_body(var[7],var[2])
				if dangeorus==0:
					print("!!!ATTENTION!!!! The timestamp used in \"" + var[0] + "\" in \"" + str(var[2]) + "\" function (n"+ str(var[1]) +" occurrence) could be a FALSE POSITIVE because it is not a condition regulating a dangerous body.")
			elif var[0]=="require condition":
				dangeorus=0
				verification_body_require(contract_json,var[2],var[4])
				if dangeorus==0:
					print("!!!ATTENTION!!!! The timestamp used in \"" + var[0] + "\" in \"" + str(var[2]) + "\" function (n"+ str(var[1]) +" occurrence) could be a FALSE POSITIVE because it is not a condition regulating a dangerous body.")


if vulnerabilities_selection[2]==1:
	print("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n")
	print("///////////")
	print("REENTRANCY")
	print("//////////")
	print()

	alert_string=""

	#array to store information about functions possibly vulnerable to Reentrancy
	risky_calls=[]

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
										
					search_functions(element, function_name, visibility, modifiers)
			elif isinstance(value, dict):
				l+=1
				if 'type' in value and value['type']=="NameValueExpression" and 'memberName' in value['expression'] and value['expression']['memberName']=='call':
					cont+=1
					risky_calls.append((function_name,visibility,modifiers,value,value['expression']['expression'],l,cont))
				if 'type' in value and value['type']=="FunctionCall" and value['expression']['type']=='MemberAccess' and value['expression']['expression']['type']=='MemberAccess' and value['expression']['memberName']=='value' and value['expression']['expression']['memberName']=='call':
					cont+=1
					risky_calls.append((function_name,visibility,modifiers,value,value['expression']['expression']['expression'],l,cont))
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
			for i,tupla in enumerate(array):
				if i==0:
					lista.append(tupla[0])
				elif tupla[0]!=array[i-1][0]:
					lista.append(tupla[0])
			if alert_selection:
				choice=alert_selection
			else:
				for i,func in enumerate(lista):
					print(str(i+1) +". " + func)
				choice=input("Insert the number of the functions that need to be verified (separated by comma) - put n for none / put a for all:")
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
				print("{:<43} {}".format(str(variable[0]) + " #" + str(variable[6]) , "F"))
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

		print("\n-Externall Call not subject to conditions")
		print(" (if or require)-")
		alert_string+="\n\nCHECK REFERENCE:-Externall Call not subject to conditions (if or require)-"
		i=0
		for variable in risky_calls:
			search_conditions(contract_json,variable[3],variable[0])
			search_require(contract_json,variable[3],variable[0])
			if check==1:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because the call is subject to some conditions (if or require)"
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
							if "type" in element and element["type"]=="VariableDeclarationStatement" and "name" in element["variables"][0] and variable_name['type']=="Identifier" and element["variables"][0]["name"]==variable_name['name']:
									definition=element["initialValue"]
						search_definition(element, variable_name, function, ident)
					
				elif isinstance(value, dict):
					if key=="expression" and value["type"]=="BinaryOperation" and value["operator"]=="=" and value['left']==variable_name:
							definition=value["right"]
					if value==ident:
						final_definition=definition
					search_definition(value, variable_name, function, ident)


		print("\n-Call Adr. NOT HardCoded-")
		alert_string+="\n\nCHECK REFERENCE:-Call Adr. NOT HardCoded-"
		i=0
		for funz in risky_calls:
			definition=""
			final_definition=""
			search_definition(contract_json, funz[4], funz[0], funz[3])
			if final_definition!="":
				print("{:<43} {}".format(str(funz[0])+ " #" + str(funz[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(funz[6]) + " external call in \"" + str(funz[0]) + "\" function could be a FALSE POSITIVE because the call is made on an hard-coded address"
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

		print("\n-State Variable changed after call-")
		alert_string+="\n\nCHECK REFERENCE:-State Variable changed after call-"
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

		#function to check whether the amount to be transferred includes msg.value (function not actually used)
		presence=0
		msg_value={'type': 'MemberAccess', 'expression': {'type': 'Identifier', 'name': 'msg'}, 'memberName': 'value'}
		def presenza_msg_value(dictionary):
			global presence
			if dictionary==msg_value:
				presence=1
			if not isinstance(dictionary, dict):
				return 0
			for key, value in dictionary.items():
				if isinstance(value, list):
					for element in value:
						if not isinstance(element, dict):
							return 0
						presenza_msg_value(element)
				elif isinstance(value, dict):
					if (key=="left" or key=="right") and value==msg_value:
						presence=1
					presenza_msg_value(value)

		print("\n-Amount NOT defined as msg.value-")
		alert_string+="\n\nCHECK REFERENCE:-Amount NOT defined as msg.value-"
		i=0
		for variable in risky_calls:
			if 'arguments' in variable[3]['arguments'] and variable[3]['arguments']['arguments'][0]==msg_value:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because the amount is defined as msg.value"
			elif 'arguments' not in variable[3]['arguments'] and variable[3]['arguments'][0]==msg_value:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "F"))
				results[i]='f'
				alert_string+="\n!!!ATTENTION!!!! The #" + str(variable[6]) + " external call in \"" + str(variable[0]) + "\" function could be a FALSE POSITIVE because the amount is defined as msg.value"
			else:
				print("{:<43} {}".format(str(variable[0])+ " #" + str(variable[6]), "T"))
			i+=1

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
		print("\n--------------------------------------------------\n")
		print("               DETAILED OUTPUT\n")
		print(alert_string)
