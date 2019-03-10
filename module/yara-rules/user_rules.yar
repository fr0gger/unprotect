/*#########################################################################################################
/* THIS FILE IS PART OF THE UNPROTECT PROJECT AND CAN BE CUSTOMIZED BY THE USER TO ADD HIS OWN RULES */
/* THE BELOW RULES ARE SOME EXAMPLES, FEEL FREE TO ADD YOUR OWN RULES */
/*#########################################################################################################

/* Match any file with "PE" within 0x200 bytes (decimal) of the first occurrence of "MZ" */
rule RelativeOffsetExample {
	strings:
		$mz = "MZ"
		$pe = "PE"

	condition:
		$mz at 0 and $pe in (@mz[0]..0x200)
}

/* Match any PE file as defined by MZ and PE signatures at required locations. */

rule IsPeFile {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0 and uint32(uint32(0x3C)) == 0x4550
}

