#include <string>

class ProcessInfo
{
private:
	int pid;
	std::wstring imagePath;

public:
	ProcessInfo(_In_ int pid, _In_ wchar_t* path);
	bool operator<(_In_ const ProcessInfo& other) const;
	bool operator==(_In_ const ProcessInfo& other) const;
	int getPid() const;
	std::wstring getPath() const;
};