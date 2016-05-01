#include "ProcInfo.h"

ProcessInfo::ProcessInfo(_In_ int pid, _In_ wchar_t* path)
{
	this->pid = pid;
	this->imagePath = std::wstring(path);
}

bool ProcessInfo::operator<(_In_ const ProcessInfo& other) const
{
	return pid < other.getPid();
}

bool ProcessInfo::operator==(_In_ const ProcessInfo& other) const
{
	return pid == other.getPid();
}

int ProcessInfo::getPid() const
{
	return pid;
}

std::wstring ProcessInfo::getPath() const
{
	return imagePath;
}