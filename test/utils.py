import re

def javahex_to_pythonhex(javaArrayBytes):
	#frame.append(0xA2)
	comp = re.compile("\(byte\)(0x[0-9A-Fa-f]+)")
	text = ""
	for byt in comp.findall(javaArrayBytes):
		#text += byt
		text += str(byt).replace("0x", r"\x")
	#return bytearray(text)
	return "b'%s'" % text


def hexstr_to_pythonhexstr(hexArrayBytes):
	ret = ""
	for i in range(0, len(hexArrayBytes), 2):
		ret += r"\x%s%s" % (hexArrayBytes[i], hexArrayBytes[i+1])
	return ret


if __name__ == "__main__":
	javaArrayBytes = """
				(byte)0x36,(byte)0x50,(byte)0x47,(byte)0x10,(byte)0x10,(byte)0x61,(byte)0xfd,(byte)0x65,(byte)0x0d,(byte)0xb1,
				(byte)0xc8,(byte)0x35,(byte)0x6d,(byte)0xa8,(byte)0xa3,(byte)0xcc,(byte)0x14,(byte)0x94,(byte)0xc0,(byte)0xec,
				(byte)0x7f,(byte)0x9e,(byte)0xda,(byte)0x72,(byte)0x64,(byte)0x15,(byte)0x03,(byte)0x91,(byte)0xed,(byte)0x07,
				(byte)0xbc,(byte)0xb1,(byte)0x5d,(byte)0x86,(byte)0xfb,(byte)0xa7,(byte)0x39,(byte)0x98,(byte)0x61,(byte)0x06,
				(byte)0x1d,(byte)0xd3,(byte)0x7c,(byte)0xdd,(byte)0xbb,(byte)0xda,(byte)0xd3,(byte)0x8d,(byte)0x1d,(byte)0x49,
				(byte)0x02,(byte)0xd3,(byte)0x9c,(byte)0xe1,(byte)0xf0,(byte)0xcd,(byte)0x62,(byte)0x79,(byte)0x65,(byte)0xfe
								
	"""
	bArray = javahex_to_pythonhex(javaArrayBytes)
	#print bArray.decode()
	
	print "b'%s'" % hexstr_to_pythonhexstr("c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3")
	