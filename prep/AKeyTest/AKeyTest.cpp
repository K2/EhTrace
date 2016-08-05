// AKeyTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define MD5LEN  16
#define BUFSIZE 32
extern "C" FARPROC AMain;

int main()
{


	//-------------------------------------------------------------------
	// Declare and initialize variables.

	HCRYPTPROV   hCryptProv;
	HCRYPTKEY    hOriginalKey;
	HCRYPTKEY    hDuplicateKey;
	HCRYPTHASH	 hHash;
	DWORD        dwMode;
	BYTE         pbData[BUFSIZE];
	BYTE	     rgbHash[MD5LEN];
	DWORD		 cbHash = MD5LEN;
	CHAR		 rgbDigits[] = "0123456789abcdef";
	//-------------------------------------------------------------------
	// Begin processing.

	printf("This program creates a session key and duplicates \n");
	printf("that key. Next, parameters are added to the original \n");
	printf("key. Finally, both keys are destroyed. \n\n");


	/// init EhTrace
	AMain();

	ULONG64 StartCycle = __rdtsc();

	//-------------------------------------------------------------------
	// Acquire a cryptographic provider context handle.

	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		0))
	{
		printf("CryptAcquireContext succeeded. \n");
	}
	else
	{
		MyHandleError("Error during CryptAcquireContext!\n");
	}

	// Generate a random initialization vector.
	if (CryptGenRandom(
		hCryptProv,
		BUFSIZE,
		pbData))
	{
		printf("Random sequence generated. \n");
		printf("sequence is: ");
		for (DWORD i = 0; i < BUFSIZE; i++)
		{
			printf("%c%c", rgbDigits[pbData[i] >> 4],
				rgbDigits[pbData[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		MyHandleError("Error during CryptGenRandom.");
	}


	//-------------------------------------------------------------------
	// Generate a key.
	if (CryptGenKey(
		hCryptProv,
		CALG_RC4,
		0,
		&hOriginalKey))
	{
		printf("Original session key is created. \n");
	}
	else
	{
		MyHandleError("ERROR - CryptGenKey.");
	}
	//-------------------------------------------------------------------
	// Duplicate the key.

	if (CryptDuplicateKey(
		hOriginalKey,
		NULL,
		0,
		&hDuplicateKey))
	{
		printf("The session key has been duplicated. \n");
	}
	else
	{
		MyHandleError("ERROR - CryptDuplicateKey");
	}
	//-------------------------------------------------------------------
	// Set additional parameters on the original key.
	// First, set the cipher mode.

	dwMode = CRYPT_MODE_ECB;
	if (CryptSetKeyParam(
		hOriginalKey,
		KP_MODE,
		(BYTE*)&dwMode,
		0))
	{
		printf("Key Parameters set. \n");
	}
	else
	{
		MyHandleError("Error during CryptSetKeyParam.");
	}
	// Generate a random initialization vector.
	if (CryptGenRandom(
		hCryptProv,
		BUFSIZE,
		pbData))
	{
		printf("Random sequence generated. \n");
		printf("sequence is: ");
		for (DWORD i = 0; i < BUFSIZE; i++)
		{
			printf("%c%c", rgbDigits[pbData[i] >> 4],
				rgbDigits[pbData[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		MyHandleError("Error during CryptGenRandom.");
	}
	//----------------------------------------------------------------
	// Create an empty hash object.

	if (CryptCreateHash(
		hCryptProv,
		CALG_MD5,
		0,
		0,
		&hHash))
	{
		printf("An empty hash object has been created. \n");
	}
	else
	{
		MyHandleError("Error during CryptCreateHash!");
	}
	//----------------------------------------------------------------
	// Hash the password string.
	if (CryptHashData(
		hHash,
		(BYTE *)pbData,
		sizeof(pbData),
		0))
	{
		printf("The password has been hashed. \n");
		cbHash = MD5LEN;
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			printf("MD5 hash is: ");
			for (DWORD i = 0; i < cbHash; i++)
			{
				printf("%c%c", rgbDigits[rgbHash[i] >> 4],
					rgbDigits[rgbHash[i] & 0xf]);
			}
			printf("\n");
		}

	}
	else
	{
		MyHandleError("Error during CryptHashData!");
	}
	//----------------------------------------------------------------
	// Create a session key based on the hash of the password.

	if (CryptDeriveKey(
		hCryptProv,
		CALG_RC2,
		hHash,
		CRYPT_EXPORTABLE,
		&hDuplicateKey))
	{
		printf("The key has been derived. \n");
	}
	else
	{
		MyHandleError("Error during CryptDeriveKey!");
	}
	//-------------------------------------------------------------------
	// Set the initialization vector.
	if (CryptSetKeyParam(
		hOriginalKey,
		KP_IV,
		pbData,
		0))
	{
		printf("Parameter set with random sequence as "
			"initialization vector. \n");
	}
	else
	{
		MyHandleError("Error during CryptSetKeyParam.");
	}

	//-------------------------------------------------------------------
	// Clean up.
	if (hHash)
		if (!(CryptDestroyHash(hHash)))
			MyHandleError("Error during CryptDestroyHash");

	if (hOriginalKey)
		if (!CryptDestroyKey(hOriginalKey))
			MyHandleError("Failed CryptDestroyKey\n");

	if (hDuplicateKey)
		if (!CryptDestroyKey(hDuplicateKey))
			MyHandleError("Failed CryptDestroyKey\n");

	if (hCryptProv)
		if (!CryptReleaseContext(hCryptProv, 0))
			MyHandleError("Failed CryptReleaseContext\n");

	printf("\nThe program ran to completion without error. \n");

	ULONG64 EndCycle = __rdtsc();
	printf("\n CPU CYCLES SPENT = 0x%llx\n", EndCycle - StartCycle);
} // End of main.

  //-------------------------------------------------------------------
  //  This example uses the function MyHandleError, a simple error
  //  handling function, to print an error message and exit 
  //  the program. 
  //  For most applications, replace this function with one 
  //  that does more extensive error reporting.

void MyHandleError(char *s)
{
	printf("An error occurred in running the program.\n");
	printf("%s\n", s);
	printf("Error number %x\n.", GetLastError());
	printf("Program terminating.\n");
	exit(1);
}
