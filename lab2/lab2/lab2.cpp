#include "pch.h"
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>

//-------------------------------------------------------------------
// This example uses the function MyHandleError, a simple error
// handling function to print an error message and exit 
// the program. 
// For most applications, replace this function with one 
// that does more extensive error reporting.

void MyHandleError(LPCSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} // End of MyHandleError.

void main(void)
{
	//---------------------------------------------------------------
	// Declare and initialize variables.
	HCRYPTPROV hCryptProv;


	//---------------------------------------------------------------
	// Get a handle to the default PROV_RSA_FULL provider.
	if (CryptAcquireContext(
		&hCryptProv, // A pointer to a handle of a CSP.
		NULL, // The key container name.
		NULL, // A null-terminated string that contains the name of the CSP to be used.
		PROV_RSA_FULL, // Specifies the type of provider to acquire. PROV_RSA_FULL - Microsoft Base Cryptographic Provider
		0)) // Flag values.
	{
		_tprintf(TEXT("CryptAcquireContext succeeded.\n"));
	}
	else
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			// No default container was found. Attempt to create it.
			if (CryptAcquireContext(
				&hCryptProv,
				NULL,
				NULL,
				PROV_RSA_FULL,
				CRYPT_NEWKEYSET)) // Creates a new key container with the name specified by pszContainer.
			{
				_tprintf(TEXT("CryptAcquireContext succeeded.\n"));
			}
			else
			{
				MyHandleError(TEXT("Could not create the default ")
					TEXT("key container.\n"));
			}
		}
		else
		{
			MyHandleError(TEXT("A general error running ")
				TEXT("CryptAcquireContext."));
		}
	}

	CHAR pszName[1000];
	DWORD cbName;

	//---------------------------------------------------------------
	// Read the name of the CSP.
	cbName = 1000;
	if (CryptGetProvParam(
		hCryptProv, // A handle of the CSP target of the query.
		PP_NAME, // The nature of the query.
		(BYTE*)pszName, // A pointer to a buffer to receive the data. 
		&cbName, // A pointer to a DWORD value that specifies the size, in bytes, of the buffer pointed to by the pbData parameter.
		0)) // Flag values.
	{
		_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
		printf("Provider name: %s\n", pszName);
	}
	else
	{
		MyHandleError(TEXT("Error reading CSP name.\n"));
	}

	//---------------------------------------------------------------
	// Read the name of the key container.
	cbName = 1000;
	if (CryptGetProvParam(
		hCryptProv,
		PP_CONTAINER,
		(BYTE*)pszName,
		&cbName,
		0))
	{
		_tprintf(TEXT("CryptGetProvParam succeeded.\n"));
		printf("Key Container name: %s\n", pszName);
	}
	else
	{
		MyHandleError(TEXT("Error reading key container name.\n"));
	}

	//---------------------------------------------------------------
	// Release the provider handle.
	if (CryptReleaseContext(hCryptProv, 0))
	{
		_tprintf(TEXT("The second call to CryptReleaseContext ")
			TEXT("succeeded.\n"));
	}
	else
	{
		MyHandleError(TEXT("Error during ")
			TEXT("CryptReleaseContext #2!\n"));
	}

	//---------------------------------------------------------------
	// Get a handle to a PROV_RSA_FULL provider and
	// create a key container named "My Sample Key Container".
	LPCTSTR pszContainerName = TEXT("My Sample Key Container");

	hCryptProv = NULL;
	if (CryptAcquireContext(
		&hCryptProv,
		pszContainerName,
		NULL,
		PROV_RSA_FULL,
		CRYPT_NEWKEYSET))
	{
		_tprintf(TEXT("CryptAcquireContext succeeded. \n"));
		_tprintf(TEXT("New key set created. \n"));

		//-----------------------------------------------------------
		// Release the provider handle and the key container.
		if (hCryptProv)
		{
			if (CryptReleaseContext(hCryptProv, 0))
			{
				hCryptProv = NULL;
				_tprintf(TEXT("CryptReleaseContext succeeded. \n"));
			}
			else
			{
				MyHandleError(TEXT("Error during ")
					TEXT("CryptReleaseContext!\n"));
			}
		}
	}
	else
	{
		if (GetLastError() == NTE_EXISTS)
		{
			_tprintf(TEXT("The named key container could not be ")
				TEXT("created because it already exists.\n"));

			// Just continue the program. The named container 
			// will be reopened below.
		}
		else
		{
			MyHandleError(TEXT("Error during CryptAcquireContext ")
				TEXT("for a new key container."));
		}
	}

	//---------------------------------------------------------------
	// Get a handle to the provider by using the new key container. 
	// Note: This key container will be empty until keys
	// are explicitly created by using the CryptGenKey function.
	if (CryptAcquireContext(
		&hCryptProv,
		pszContainerName,
		NULL,
		PROV_RSA_FULL,
		0))
	{
		_tprintf(TEXT("Acquired the key set just created. \n"));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptAcquireContext!\n"));
	}


	//---------------------------------------------------------------
	// Release the provider handle.
	if (CryptReleaseContext(
		hCryptProv,
		0))
	{
		_tprintf(TEXT("CryptReleaseContext succeeded. \n"));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptReleaseContext!\n"));
	}

	//---------------------------------------------------------------
	// Delete the new key container.
	if (CryptAcquireContext(
		&hCryptProv,
		pszContainerName,
		NULL,
		PROV_RSA_FULL,
		CRYPT_DELETEKEYSET))
	{
		_tprintf(TEXT("Deleted the key container just created. \n"));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptAcquireContext!\n"));
	}
}