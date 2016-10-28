//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
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

void MyHandleError(LPTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} // End of MyHandleError.


void main(void)
{
	// Handle for the cryptographic provider context.
	HCRYPTPROV	hCryptProv = 0;
	// Public/private key handle.
	HCRYPTKEY	hKeyGenK = 0;
	HCRYPTKEY	hKeyGet = 0;
	HCRYPTHASH	hHash;
	BYTE		*pbSignature = NULL;
	DWORD		dwSigLen = 0;

	// The name of the container.
	LPCTSTR pszSCReader = TEXT("\\\\.\\Yubico Yubikey 4 CCID 0\\YKPIV_KEY_RETIRED1");
	DWORD	_KEY_LEN = 0x08000000; //0x04000000


	if (CryptAcquireContext(
		&hCryptProv,
		pszSCReader,
		MS_SCARD_PROV,
		PROV_RSA_FULL,
		CRYPT_DELETEKEYSET))
	{
		_tprintf(TEXT("A key container has been deleted.\n"));
	}
	else {
		_tprintf(TEXT("Could not delete a key container.\n"));
	}

	if (CryptAcquireContext(
		&hCryptProv,
		pszSCReader,
		MS_SCARD_PROV,
		PROV_RSA_FULL,
		CRYPT_NEWKEYSET))
	{
		_tprintf(TEXT("A new key container has been created.\n"));
	}
	else {
		MyHandleError(TEXT("Could not create a new key container.\n"));
	}

	if (CryptGetUserKey(
			hCryptProv,
			AT_SIGNATURE,
			&hKeyGet))
	{
		_tprintf(TEXT("CryptGetUserKey: Got user key.\n"));
	}
	if (GetLastError() == NTE_NO_KEY) {
		// Create a key exchange key pair.
		_tprintf(TEXT("The exchange key does not exist.\n"));
		_tprintf(TEXT("Attempting to create an exchange key pair.\n"));
		if (CryptGenKey(
			hCryptProv,
			AT_SIGNATURE,
			_KEY_LEN,
			&hKeyGenK))
		{
			_tprintf(TEXT("Exchange key pair created.\n"));
		} else {
			MyHandleError(TEXT("Error occurred attempting to ")
				TEXT("create an exchange key.\n"));
		}
	} else {
		MyHandleError(TEXT("Error occurred attempting to CryptGetUserKey."));
	}

	if (CryptGetUserKey(
		hCryptProv,
		AT_SIGNATURE,
		&hKeyGet))
	{
		_tprintf(TEXT("CryptGetUserKey: Got user key again.\n"));
	} else {
		MyHandleError(TEXT("Error occurred attempting to CryptGetUserKey."));
	}

	if (CryptCreateHash(
		hCryptProv,
		CALG_SHA1,
		0,
		0,
		&hHash))
	{
		_tprintf(TEXT("An empty hash object has been created.\n"));
	} else {
		MyHandleError(TEXT("Error during CryptCreateHash!\n"));
	}

	BYTE *pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
	DWORD dwBufferLen = strlen((char *)pbBuffer) + 1;
	if (CryptHashData(
		hHash,
		pbBuffer,
		dwBufferLen,
		0))
	{
		_tprintf(TEXT("The data buffer has been hashed.\n"));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptHashData!\n"));
	}

	//-------------------------------------------------------------------
	// Determine the size of the signature and allocate memory.
	if (CryptSignHash(
		hHash,
		AT_SIGNATURE,
		NULL,
		0,
		NULL,
		&dwSigLen))
	{
		_tprintf(TEXT("Signature length %d found.\n", dwSigLen));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptSignHash."));
	}

	//-------------------------------------------------------------------
	// Allocate memory for the signature buffer.
	if (pbSignature = (BYTE *)malloc(dwSigLen))
	{
		_tprintf(TEXT("Memory allocated for the signature.\n"));
	}
	else
	{
		MyHandleError(TEXT("Out of memory."));
	}

	//-------------------------------------------------------------------
	// Sign the hash object.
	if (CryptSignHash(
		hHash,
		AT_SIGNATURE,
		NULL,
		0,
		pbSignature,
		&dwSigLen))
	{
		_tprintf(TEXT("pbSignature is the hash signature.\n"));
	}
	else
	{
		MyHandleError(TEXT("Error during CryptSignHash."));
	}

	if (hKeyGenK)
		CryptDestroyKey(hKeyGenK);
	if (hKeyGet)
		CryptDestroyKey(hKeyGet);
	if (pbSignature)
		free(pbSignature);
	if (hHash)
		CryptDestroyHash(hHash);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);

	_tprintf(TEXT("Everything is okay. A signature key "));
	_tprintf(TEXT("pair and an exchange key exist in "));
	_tprintf(TEXT("the %s key container.\n"), pszSCReader);
} // End main.