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
    BOOL NewTask(char* lpszTaskName, char* lpszProgramPath, char* lpszParameters, char* lpszAuthor);

    //************************************
    // ������:  CMyTaskSchedule::Delete
    // ��������:   BOOL
    // ����: ɾ���ƻ�����
    // ����1: char * lpszTaskName    �ƻ�������
    //************************************
    BOOL Delete(char* lpszTaskName);


    ITaskService* m_lpITS;
    ITaskFolder* m_lpRootFolder;
};