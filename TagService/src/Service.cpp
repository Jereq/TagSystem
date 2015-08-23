#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <AclAPI.h>
#include <strsafe.h>

#include <cstdio>

#include <string>

#define SVCNAME TEXT("Tag System Service")

SERVICE_STATUS gSvcStatus = { 0 };
SERVICE_STATUS_HANDLE gSvcStatusHandle;
HANDLE ghSvcStopEvent = nullptr;

void WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv);
void WINAPI SvcCtrlHandler(DWORD dwCtrl);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

int SvcInstall();
void SvcDelete();
void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
void SvcInit(DWORD dwArgc, LPTSTR* lpszArgv);
void SvcReportWinFuncError(LPTSTR szFunction);
void SvcReportInfo(LPTSTR msg);

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		SERVICE_TABLE_ENTRY DispatchTable[] =
		{
			{ SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
			{ nullptr, nullptr }
		};

		if (!StartServiceCtrlDispatcher(DispatchTable))
		{
			if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			{
				fprintf(stderr, "This application should be run as a service\n");
			}
			else
			{
				SvcReportWinFuncError(TEXT("StartServiceCtrlDispatcher"));
			}
		}

		return EXIT_SUCCESS;
	}
	else if (argc == 2)
	{
		std::string arg(argv[1]);

		if (arg == "--install")
		{
			return SvcInstall();
		}
		else if (arg == "--delete")
		{
			SvcDelete();
			return EXIT_SUCCESS;
		}
		else
		{
			fprintf(stderr, "Unrecognized argument\n");
		}
	}
	else
	{
		fprintf(stderr, "Wrong number of arguments\n");
		return EXIT_FAILURE;
	}
}

int SvcInstall()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	TCHAR szPath[MAX_PATH];

	if (!GetModuleFileName(nullptr, szPath, MAX_PATH))
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return EXIT_FAILURE;
	}

	schSCManager = OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);

	if (!schSCManager)
	{
		printf("OpendSCManager failed (%d)\n", GetLastError());
		return EXIT_FAILURE;
	}

	schService = CreateService(
		schSCManager,
		SVCNAME,
		SVCNAME,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szPath,
		nullptr,
		nullptr,
		nullptr,
		nullptr,//TEXT("NT AUTHORITY\\LocalService"),
		TEXT(""));

	if (!schService)
	{
		printf("CreateService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return EXIT_FAILURE;
	}
	else
	{
		printf("Servcie installed successfully\n");
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return EXIT_SUCCESS;
}

void SvcDelete()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

	if (!schSCManager)
	{
		printf("OpendSCManager failed (%d)\n", GetLastError());
		return;
	}

	schService = OpenService(
		schSCManager,
		SVCNAME,
		DELETE);

	if (!schService)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	if (!DeleteService(schService))
	{
		printf("DeleteService failed (%d)\n", GetLastError());
	}
	else
	{
		printf("Servcie deleted successfully\n");
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

void WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);

	if (!gSvcStatusHandle)
	{
		SvcReportWinFuncError(TEXT("RegisterServiceCtrlHandler"));
		return;
	}

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	SvcInit(dwArgc, lpszArgv);
}

bool GetSecurityAttributes(SECURITY_ATTRIBUTES& outAttributes)
{
	PSECURITY_DESCRIPTOR pSD = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!pSD)
	{
		SvcReportWinFuncError(TEXT("LocalAlloc"));
		return false;
	}

	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		SvcReportWinFuncError(TEXT("InitializeSecurityDescriptor"));

		LocalFree(pSD);
		return false;
	}

	if (!SetSecurityDescriptorDacl(pSD, TRUE, nullptr, FALSE))
	{
		SvcReportWinFuncError(TEXT("SetSecurityDescriptorDacl"));

		LocalFree(pSD);
		return false;
	}

	outAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	outAttributes.lpSecurityDescriptor = pSD;
	outAttributes.bInheritHandle = FALSE;

	return true;
}

void FreeSecurityAttributes(const SECURITY_ATTRIBUTES& attributes)
{
	LocalFree(attributes.lpSecurityDescriptor);
}

void SvcInit(DWORD dwArgc, LPTSTR* lpszArgv)
{
	SECURITY_ATTRIBUTES securityAttributes;
	if (!GetSecurityAttributes(securityAttributes))
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	HANDLE pipe = CreateNamedPipeA(
		"\\\\.\\pipe\\TagServicePipe",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		50,
		&securityAttributes);

	if (pipe == INVALID_HANDLE_VALUE)
	{
		SvcReportWinFuncError(TEXT("CreateNamedPipeA"));

		FreeSecurityAttributes(securityAttributes);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	ghSvcStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

	if (ghSvcStopEvent == nullptr)
	{
		SvcReportWinFuncError(TEXT("CreateEvent"));

		FreeSecurityAttributes(securityAttributes);
		CloseHandle(pipe);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	SvcReportInfo(TEXT("Service running"));
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	while (WaitForSingleObject(ghSvcStopEvent, 0) == WAIT_TIMEOUT)
	{
		if (ConnectNamedPipe(pipe, nullptr))
		{
			//SvcReportInfo(TEXT("Connected pipe"));
			char buffer[4096];
			DWORD bytesRead;
			if (ReadFile(pipe, buffer, 4096, &bytesRead, nullptr))
			{
				for (unsigned int i = 0; i < bytesRead / 2; ++i)
				{
					char temp = buffer[i];
					buffer[i] = buffer[bytesRead - i - 1];
					buffer[bytesRead - i - 1] = temp;
				}

				DWORD bytesWritten;
				WriteFile(pipe, buffer, bytesRead, &bytesWritten, nullptr);
			}

			FlushFileBuffers(pipe);
			DisconnectNamedPipe(pipe);
		}
	}

	FreeSecurityAttributes(securityAttributes);
	CloseHandle(pipe);
	ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else
		gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_START_PENDING) || (dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else
		gSvcStatus.dwCheckPoint = dwCheckPoint++;

	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

void WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		DeleteFileA("\\\\.\\pipe\\TagServicePipe");
		SetEvent(ghSvcStopEvent);
		return;

	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}
}

void SvcReportEvent(WORD wType, DWORD dwEventID, LPTSTR msg)
{
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];

	hEventSource = RegisterEventSource(nullptr, SVCNAME);

	if (hEventSource)
	{
		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = msg;

		ReportEvent(hEventSource,
			wType,
			0,
			dwEventID,
			nullptr,
			2,
			0,
			lpszStrings,
			nullptr);

		DeregisterEventSource(hEventSource);
	}
}

const DWORD FACILITY_RUNTIME = 0x2L << 16;
const DWORD CUSTOMER_FLAG = 0x1L << 29;

const DWORD STATUS_SEVERITY_INFORMATIONAL = 0x1L << 30;
const DWORD STATUS_SEVERITY_ERROR = 0x3L << 30;

void SvcReportWinFuncError(LPTSTR szFunction)
{
	static const DWORD SVC_ERROR = STATUS_SEVERITY_ERROR | CUSTOMER_FLAG | FACILITY_RUNTIME | 1;

	TCHAR buffer[80];
	StringCchPrintf(buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

	SvcReportEvent(EVENTLOG_ERROR_TYPE, SVC_ERROR, buffer);
}

void SvcReportInfo(LPTSTR msg)
{
	static const DWORD SVC_INFO = STATUS_SEVERITY_INFORMATIONAL | CUSTOMER_FLAG | FACILITY_RUNTIME | 2;

	SvcReportEvent(EVENTLOG_INFORMATION_TYPE, SVC_INFO, msg);
}
