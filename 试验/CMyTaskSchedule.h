#pragma once

#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

class CMyTaskSchedule
{
public:
    CMyTaskSchedule();
    ~CMyTaskSchedule();

    //************************************
    // ������:  CMyTaskSchedule::NewTask
    // ��������:   BOOL
    // ����: �����ƻ�����
    // ����1: char * lpszTaskName    �ƻ�������
    // ����2: char * lpszProgramPath    �ƻ�����·��
    // ����3: char * lpszParameters        �ƻ��������
    // ����4: char * lpszAuthor            �ƻ���������
    //************************************
    static BOOL NewTask(char* lpszTaskName, char* lpszProgramPath, char* lpszParameters, char* lpszAuthor);

    //************************************
    // ������:  CMyTaskSchedule::Delete
    // ��������:   BOOL
    // ����: ɾ���ƻ�����
    // ����1: char * lpszTaskName    �ƻ�������
    //************************************
    static BOOL Delete(char* lpszTaskName);


    static ITaskService* m_lpITS;
    static ITaskFolder* m_lpRootFolder;
};